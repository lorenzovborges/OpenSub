//! Local bridge for Cursor's Connect/protobuf Agent stream.
//!
//! The bridge only handles OpenAI-family model requests. Other models are
//! streamed unchanged to Cursor's backend so Composer, Grok, and future native
//! models continue to use the user's Cursor subscription.

use std::collections::HashMap;
use std::convert::Infallible;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bytes::Bytes;
use flate2::read::GzDecoder;
use futures::{StreamExt, TryStreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_util::io::StreamReader;

use crate::{auth, codex, config};

pub const BRIDGE_SECRET_HEADER: &str = "x-opensub-bridge-secret";
pub const ORIGINAL_HOST_HEADER: &str = "x-opensub-original-host";

const MAX_INITIAL_FRAME: usize = 16 * 1024 * 1024;

pub struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    pub fn new(listener: TcpListener, acceptor: TlsAcceptor) -> Self {
        Self { listener, acceptor }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.listener.accept().await {
                Ok((stream, address)) => match self.acceptor.accept(stream).await {
                    Ok(stream) => return (stream, address),
                    Err(error) => {
                        tracing::warn!(error = %error, "local bridge TLS handshake failed");
                    }
                },
                Err(error) => {
                    tracing::warn!(error = %error, "local bridge TCP accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

#[derive(Clone)]
pub struct BridgeState {
    secret: Arc<str>,
    client: reqwest::Client,
    events: Arc<EventLog>,
    capture_protocol: bool,
}

impl BridgeState {
    pub fn new(secret: String, capture_protocol: bool) -> Result<Self> {
        Ok(Self {
            secret: secret.into(),
            client: reqwest::Client::builder()
                .user_agent("OpenSub Cursor Bridge")
                .build()?,
            events: Arc::new(EventLog::new()?),
            capture_protocol,
        })
    }
}

struct EventLog {
    file: Mutex<std::fs::File>,
}

impl EventLog {
    fn new() -> Result<Self> {
        let path = event_log_path();
        let parent = path.parent().context("bridge event log has no parent")?;
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    fn record(&self, event: &str, model: Option<&str>) {
        let Ok(mut file) = self.file.lock() else {
            return;
        };
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default();
        let model = model.map(|value| value.chars().take(128).collect::<String>());
        let line = json!({
            "timestamp_ms": timestamp_ms,
            "event": event,
            "model": model,
        });
        let _ = writeln!(file, "{line}");
    }
}

pub fn event_log_path() -> PathBuf {
    config::data_dir().join("cursor-proxy").join("events.jsonl")
}

pub fn router(state: BridgeState) -> axum::Router {
    axum::Router::new()
        .route("/agent.v1.AgentService/Run", post(run))
        .with_state(state)
}

async fn run(State(state): State<BridgeState>, request: Request) -> Response {
    let transport_event = match request.version() {
        axum::http::Version::HTTP_2 => "bridge_http2",
        axum::http::Version::HTTP_11 => "bridge_http1",
        _ => "bridge_http_other",
    };
    state.events.record(transport_event, None);
    match route_request(state.clone(), request).await {
        Ok(response) => response,
        Err(error) => {
            state.events.record(bridge_error_event(&error), None);
            tracing::warn!(error = %format!("{error:#}"), "Cursor Agent bridge request failed");
            connect_error_response("OpenSub could not process the Cursor Agent request")
        }
    }
}

async fn route_request(state: BridgeState, request: Request) -> Result<Response> {
    authorize_bridge(request.headers(), &state.secret)?;
    let original_host = original_host(request.headers())?;
    let (parts, body) = request.into_parts();
    let mut incoming = body.into_data_stream();
    let mut buffered = Vec::new();
    let mut initial = Vec::new();

    while first_connect_frame(&initial)?.is_none() {
        let chunk = incoming
            .next()
            .await
            .ok_or_else(|| anyhow!("Agent request ended before its first Connect frame"))??;
        initial.extend_from_slice(&chunk);
        buffered.push(chunk);
        if initial.len() > MAX_INITIAL_FRAME + 5 {
            bail!("initial Agent frame exceeds the safety limit");
        }
    }

    let frame = first_connect_frame(&initial)?.expect("checked above");
    let message = decode_connect_message(frame.flags, frame.payload)?;
    let run = parse_agent_run(&message)?;
    let (requested_model, reasoning_effort) = parse_requested_model(&run)?;

    if state.capture_protocol {
        write_protocol_capture(&message)?;
        state
            .events
            .record("protocol_captured", Some(&requested_model));
        println!("→ Agent protocol captured locally; upstream request blocked.");
        bail!("Agent protocol capture completed");
    }

    if !is_openai_model(&requested_model) {
        state.events.record("route_cursor", Some(&requested_model));
        tracing::debug!(
            model = %requested_model,
            host = %original_host,
            "Cursor Agent request routed to Cursor"
        );
        return passthrough(state, parts.headers, original_host, buffered, incoming).await;
    }

    let agent = AgentRequest::parse(&run, requested_model, reasoning_effort)?;

    tracing::info!(
        model = %agent.requested_model,
        reasoning = %agent.reasoning_effort.as_deref().unwrap_or("default"),
        mcp_tools = agent.mcp_tools.len(),
        "OpenAI request intercepted by OpenSub"
    );
    state
        .events
        .record("route_opensub", Some(&agent.requested_model));

    let first_frame_len = frame.payload.len() + 5;
    let initial_remainder = initial[first_frame_len..].to_vec();
    let (client_tx, client_rx) = mpsc::channel(32);
    tokio::spawn(read_client_stream(initial_remainder, incoming, client_tx));

    Ok(openai_response(agent, client_rx, Arc::clone(&state.events)).await)
}

fn write_protocol_capture(message: &[u8]) -> Result<()> {
    let path = config::data_dir()
        .join("cursor-proxy")
        .join("last-agent-request.bin");
    let parent = path.parent().context("protocol capture has no parent")?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(message)?;
    file.sync_all()?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn bridge_error_event(error: &anyhow::Error) -> &'static str {
    let message = format!("{error:#}");
    if message.contains("before its first Connect frame") {
        "error_missing_initial_connect_frame"
    } else if message.contains("initial Agent frame exceeds") {
        "error_initial_frame_too_large"
    } else if message.contains("bridge secret") {
        "error_bridge_auth"
    } else {
        "error_bridge_request"
    }
}

async fn passthrough<S>(
    state: BridgeState,
    headers: HeaderMap,
    original_host: String,
    buffered: Vec<Bytes>,
    incoming: S,
) -> Result<Response>
where
    S: futures::Stream<Item = Result<Bytes, axum::Error>> + Send + 'static,
{
    let prefix = futures::stream::iter(buffered.into_iter().map(Ok::<Bytes, std::io::Error>));
    let remainder = incoming.map_err(std::io::Error::other);
    let body = reqwest::Body::wrap_stream(prefix.chain(remainder));
    let url = format!("https://{original_host}/agent.v1.AgentService/Run");
    let mut upstream = state.client.post(url).body(body);

    for (name, value) in &headers {
        if should_forward_request_header(name) {
            upstream = upstream.header(name, value);
        }
    }

    let upstream = upstream.send().await.context("Cursor passthrough failed")?;
    let status = upstream.status();
    let response_headers = upstream.headers().clone();
    let stream = upstream.bytes_stream().map_err(std::io::Error::other);
    let mut response = Response::builder().status(status);
    for (name, value) in &response_headers {
        if should_forward_response_header(name) {
            response = response.header(name, value);
        }
    }
    Ok(response.body(Body::from_stream(stream))?)
}

async fn openai_response(
    agent: AgentRequest,
    client_rx: mpsc::Receiver<ClientMessage>,
    events: Arc<EventLog>,
) -> Response {
    let (tx, rx) = mpsc::channel::<Result<Bytes, Infallible>>(32);
    tokio::spawn(async move {
        if let Err(error) =
            stream_openai_agent(agent, client_rx, tx.clone(), Arc::clone(&events)).await
        {
            events.record("error_generation", None);
            tracing::warn!(error = %error, "OpenSub Agent generation failed");
            let message = text_delta_frame(
                "OpenSub could not complete this request. Check the proxy terminal for details.",
            );
            let _ = tx.send(Ok(message)).await;
            let _ = tx.send(Ok(turn_ended_frame(None))).await;
            let _ = tx.send(Ok(end_stream_frame())).await;
        } else {
            events.record("generation_completed", None);
        }
    });

    (
        StatusCode::OK,
        [
            ("content-type", "application/connect+proto"),
            ("cache-control", "no-store"),
        ],
        Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx)),
    )
        .into_response()
}

async fn stream_openai_agent(
    agent: AgentRequest,
    mut client_rx: mpsc::Receiver<ClientMessage>,
    tx: mpsc::Sender<Result<Bytes, Infallible>>,
    events: Arc<EventLog>,
) -> Result<()> {
    let tokens = auth::require_token().await?;
    let upstream_model = map_cursor_model(&agent.requested_model);
    let conversation = load_conversation_material(&agent);
    let mut input = conversation.input;
    input.push(json!({
        "type": "message",
        "role": "user",
        "content": [{"type": "input_text", "text": agent.prompt}]
    }));
    let mut instructions = vec![
        "You are an AI coding agent running inside Cursor. Use the provided tools to inspect or change the workspace when needed. Do not claim a tool action occurred unless its result is present.".to_string(),
    ];
    if let Some(custom) = &agent.custom_system_prompt
        && !custom.trim().is_empty()
    {
        instructions.push(custom.clone());
    }
    if !conversation.instructions.trim().is_empty() {
        instructions.push(conversation.instructions);
    }
    let mut tools = core_tools();
    tools.extend(agent.mcp_tools.iter().map(McpTool::responses_value));
    let mcp_tools = agent
        .mcp_tools
        .iter()
        .map(|tool| (tool.name.clone(), tool))
        .collect::<HashMap<_, _>>();
    let mut exec_sequence = 1u32;
    let mut total_usage = Usage::default();

    for _round in 0..24 {
        let mut body = json!({
            "model": upstream_model,
            "instructions": instructions.join("\n\n"),
            "input": input,
            "tools": tools,
            "tool_choice": "auto",
            "parallel_tool_calls": false,
            "store": false,
            "stream": true,
            "include": ["reasoning.encrypted_content"],
            "service_tier": "priority",
            "prompt_cache_key": config::session_id(),
        });
        if let Some(effort) = agent
            .reasoning_effort
            .as_deref()
            .and_then(|effort| map_reasoning_effort(effort, &upstream_model))
        {
            body["reasoning"] = json!({"effort": effort});
        }

        let round = stream_responses_round(&tokens, &body, &tx).await?;
        if let Some(usage) = round.usage {
            total_usage.add(usage);
        }
        input.extend(round.output_items);
        if round.tool_calls.is_empty() {
            tx.send(Ok(turn_ended_frame(Some(total_usage)))).await?;
            tx.send(Ok(end_stream_frame())).await?;
            return Ok(());
        }

        for call in round.tool_calls {
            tracing::debug!(tool = %call.name, "Cursor tool execution requested");
            events.record("tool_requested", Some(&call.name));
            let execution = ToolExecution::from_call(&call, &mcp_tools, exec_sequence)?;
            exec_sequence = exec_sequence.saturating_add(1);
            tx.send(Ok(tool_started_frame(&execution))).await?;
            tx.send(Ok(exec_server_frame(&execution))).await?;
            let result = wait_for_exec_result(&execution, &mut client_rx).await?;
            events.record("tool_completed", Some(&call.name));
            tx.send(Ok(tool_completed_frame(&execution))).await?;
            input.push(json!({
                "type": "function_call_output",
                "call_id": call.call_id,
                "output": result,
            }));
        }
    }

    bail!("Agent exceeded the maximum number of tool rounds")
}

async fn stream_responses_round(
    tokens: &crate::auth::store::TokenData,
    body: &Value,
    tx: &mpsc::Sender<Result<Bytes, Infallible>>,
) -> Result<ResponsesRound> {
    let upstream = codex::client::post_responses_stream(tokens, body).await?;
    let mapped = upstream.map_err(std::io::Error::other);
    let reader = StreamReader::new(mapped);
    let mut lines = BufReader::new(reader).lines();
    let mut round = ResponsesRound::default();
    let mut pending = HashMap::<String, ToolCall>::new();

    while let Some(line) = lines.next_line().await? {
        let Some(data) = line.strip_prefix("data:").map(str::trim) else {
            continue;
        };
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let event: Value = match serde_json::from_str(data) {
            Ok(event) => event,
            Err(error) => {
                tracing::debug!(error = %error, bytes = data.len(), "ignored malformed Responses event");
                continue;
            }
        };
        match event.get("type").and_then(Value::as_str) {
            Some("response.output_text.delta") => {
                if let Some(delta) = event.get("delta").and_then(Value::as_str)
                    && !delta.is_empty()
                {
                    tx.send(Ok(text_delta_frame(delta))).await?;
                }
            }
            Some("response.output_item.added") => {
                if let Some(call) = event.get("item").and_then(ToolCall::from_item) {
                    pending.insert(call.item_id.clone(), call);
                }
            }
            Some("response.function_call_arguments.delta")
            | Some("response.custom_tool_call_input.delta") => {
                if let Some(delta) = event.get("delta").and_then(Value::as_str) {
                    let id = event
                        .get("item_id")
                        .or_else(|| event.get("id"))
                        .and_then(Value::as_str);
                    if let Some(call) = id.and_then(|id| pending.get_mut(id)) {
                        call.arguments.push_str(delta);
                    }
                }
            }
            Some("response.output_item.done") => {
                if let Some(item) = event.get("item") {
                    if let Some(call) = ToolCall::from_item(item) {
                        pending.insert(call.item_id.clone(), call);
                    }
                    if let Some(item) = response_input_item(item) {
                        round.output_items.push(item);
                    }
                }
            }
            Some("response.completed") => round.usage = response_usage(&event),
            Some("response.failed") | Some("error") => {
                bail!("Responses upstream reported a generation failure");
            }
            _ => {}
        }
    }
    round.tool_calls = pending.into_values().collect();
    round
        .tool_calls
        .sort_by(|left, right| left.item_id.cmp(&right.item_id));
    Ok(round)
}

fn response_input_item(item: &Value) -> Option<Value> {
    match item.get("type").and_then(Value::as_str)? {
        "function_call" => Some(json!({
            "type": "function_call",
            "call_id": item.get("call_id")?,
            "name": item.get("name")?,
            "arguments": item.get("arguments").cloned().unwrap_or_else(|| json!("{}")),
        })),
        "custom_tool_call" => Some(json!({
            "type": "custom_tool_call",
            "call_id": item.get("call_id")?,
            "name": item.get("name")?,
            "input": item.get("input").cloned().unwrap_or_else(|| json!("{}")),
        })),
        "reasoning" | "message" => Some(item.clone()),
        _ => None,
    }
}

#[derive(Default)]
struct ResponsesRound {
    output_items: Vec<Value>,
    tool_calls: Vec<ToolCall>,
    usage: Option<Usage>,
}

#[derive(Debug)]
struct ToolCall {
    item_id: String,
    call_id: String,
    name: String,
    arguments: String,
}

impl ToolCall {
    fn from_item(item: &Value) -> Option<Self> {
        match item.get("type")?.as_str()? {
            "function_call" | "custom_tool_call" => {}
            _ => return None,
        }
        Some(Self {
            item_id: item.get("id")?.as_str()?.to_string(),
            call_id: item
                .get("call_id")
                .and_then(Value::as_str)
                .unwrap_or_else(|| item.get("id").and_then(Value::as_str).unwrap_or("call"))
                .to_string(),
            name: item.get("name")?.as_str()?.to_string(),
            arguments: item
                .get("arguments")
                .or_else(|| item.get("input"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
    }
}

fn core_tools() -> Vec<Value> {
    vec![
        function_tool(
            "shell",
            "Run a shell command in the workspace.",
            json!({
                "type":"object", "properties": {
                    "command":{"type":"string"},
                    "working_directory":{"type":"string"},
                    "timeout":{"type":"integer"}
                }, "required":["command"]
            }),
        ),
        function_tool(
            "read_file",
            "Read a file from the workspace.",
            json!({
                "type":"object", "properties": {
                    "path":{"type":"string"}, "offset":{"type":"integer"}, "limit":{"type":"integer"}
                }, "required":["path"]
            }),
        ),
        function_tool(
            "write_file",
            "Write the complete contents of a file.",
            json!({
                "type":"object", "properties": {
                    "path":{"type":"string"}, "content":{"type":"string"}
                }, "required":["path","content"]
            }),
        ),
        function_tool(
            "grep",
            "Search workspace files with a regular expression.",
            json!({
                "type":"object", "properties": {
                    "pattern":{"type":"string"}, "path":{"type":"string"}, "glob":{"type":"string"},
                    "case_insensitive":{"type":"boolean"}, "head_limit":{"type":"integer"}
                }, "required":["pattern"]
            }),
        ),
        function_tool(
            "list_dir",
            "List a directory tree in the workspace.",
            json!({
                "type":"object", "properties": {"path":{"type":"string"}}, "required":["path"]
            }),
        ),
    ]
}

fn function_tool(name: &str, description: &str, parameters: Value) -> Value {
    json!({"type":"function", "name":name, "description":description, "parameters":parameters})
}

#[derive(Default)]
struct ConversationMaterial {
    instructions: String,
    input: Vec<Value>,
}

fn load_conversation_material(agent: &AgentRequest) -> ConversationMaterial {
    let ids = agent
        .root_prompt_blobs
        .iter()
        .chain(&agent.turn_blobs)
        .cloned()
        .collect::<Vec<_>>();
    let mut values = vec![None; ids.len()];

    for (index, id) in ids.iter().enumerate() {
        if let Some(value) = agent.prefetched_blobs.get(id) {
            values[index] = Some(value.clone());
        }
    }

    let available = values.iter().flatten().count();
    tracing::debug!(
        available_context_blobs = available,
        omitted_context_blobs = ids.len().saturating_sub(available),
        "Cursor context prepared from prefetched blobs"
    );

    let root_count = agent.root_prompt_blobs.len();
    let mut material = ConversationMaterial::default();
    let mut instruction_parts = Vec::new();
    for value in values.iter().take(root_count).flatten() {
        if let Some(json) = parse_blob_json(value) {
            collect_context_text(&json, &mut instruction_parts);
        }
    }
    instruction_parts.retain(|part| !part.trim().is_empty());
    material.instructions = instruction_parts.join("\n\n");

    for value in values.iter().skip(root_count).flatten() {
        if let Some(json) = parse_blob_json(value) {
            collect_history_messages(&json, &mut material.input);
        }
    }
    material
}

fn parse_blob_json(raw: &[u8]) -> Option<Value> {
    if raw.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = GzDecoder::new(raw);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).ok()?;
        serde_json::from_slice(&decoded).ok()
    } else {
        serde_json::from_slice(raw).ok()
    }
}

fn collect_context_text(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for key in ["content", "text", "message", "instructions", "prompt"] {
                if let Some(text) = object.get(key).and_then(Value::as_str) {
                    output.push(text.to_string());
                }
            }
            for (key, value) in object {
                if !matches!(
                    key.as_str(),
                    "content" | "text" | "message" | "instructions" | "prompt"
                ) {
                    collect_context_text(value, output);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_context_text(value, output);
            }
        }
        _ => {}
    }
}

fn collect_history_messages(value: &Value, output: &mut Vec<Value>) {
    match value {
        Value::Object(object) => {
            if let Some(role) = object.get("role").and_then(Value::as_str)
                && matches!(role, "user" | "assistant" | "system" | "developer")
                && let Some(text) = object_text(object)
            {
                output.push(json!({
                    "type":"message",
                    "role":role,
                    "content":[{
                        "type": if role == "assistant" {"output_text"} else {"input_text"},
                        "text":text
                    }]
                }));
                return;
            }
            for (key, role) in [("user_message", "user"), ("assistant_message", "assistant")] {
                if let Some(child) = object.get(key) {
                    let mut text = Vec::new();
                    collect_context_text(child, &mut text);
                    if !text.is_empty() {
                        output.push(json!({
                            "type":"message",
                            "role":role,
                            "content":[{
                                "type": if role == "assistant" {"output_text"} else {"input_text"},
                                "text":text.join("\n")
                            }]
                        }));
                    }
                }
            }
            for (key, child) in object {
                if !matches!(key.as_str(), "user_message" | "assistant_message") {
                    collect_history_messages(child, output);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_history_messages(value, output);
            }
        }
        _ => {}
    }
}

fn object_text(object: &serde_json::Map<String, Value>) -> Option<String> {
    for key in ["content", "text", "message"] {
        match object.get(key) {
            Some(Value::String(text)) => return Some(text.clone()),
            Some(Value::Array(parts)) => {
                let text = parts
                    .iter()
                    .filter_map(|part| part.get("text").and_then(Value::as_str))
                    .collect::<String>();
                if !text.is_empty() {
                    return Some(text);
                }
            }
            _ => {}
        }
    }
    None
}

#[derive(Debug)]
enum ClientMessage {
    Exec {
        id: u32,
        exec_id: String,
        result_field: u32,
        result: Vec<u8>,
    },
}

async fn read_client_stream<S>(mut buffer: Vec<u8>, incoming: S, tx: mpsc::Sender<ClientMessage>)
where
    S: futures::Stream<Item = Result<Bytes, axum::Error>> + Send + 'static,
{
    futures::pin_mut!(incoming);
    loop {
        while let Ok(Some(frame)) = first_connect_frame(&buffer) {
            let frame_len = frame.payload.len() + 5;
            if frame.flags & 0x02 == 0
                && let Ok(message) = decode_connect_message(frame.flags, frame.payload)
                && let Ok(client) = WireMessage::parse(&message)
                && let Some(exec) = client.bytes(2).and_then(|raw| WireMessage::parse(raw).ok())
            {
                let result = exec.fields.iter().find_map(|field| {
                    if matches!(field.number, 2..=14 | 16..=53)
                        && let WireValue::Bytes(value) = &field.value
                    {
                        Some((field.number, value.to_vec()))
                    } else {
                        None
                    }
                });
                if let Some((result_field, result)) = result {
                    let message = ClientMessage::Exec {
                        id: exec.varint(1).unwrap_or_default() as u32,
                        exec_id: exec
                            .string(15)
                            .ok()
                            .flatten()
                            .unwrap_or_default()
                            .to_string(),
                        result_field,
                        result,
                    };
                    if tx.send(message).await.is_err() {
                        return;
                    }
                }
            }
            buffer.drain(..frame_len);
        }

        match incoming.next().await {
            Some(Ok(chunk)) => buffer.extend_from_slice(&chunk),
            Some(Err(_)) | None => return,
        }
    }
}

#[derive(Debug)]
struct ToolExecution {
    id: u32,
    exec_id: String,
    model_call_id: String,
    exec_field: u32,
    args: Vec<u8>,
    display_tool_call: Vec<u8>,
}

impl ToolExecution {
    fn from_call(call: &ToolCall, mcp_tools: &HashMap<String, &McpTool>, id: u32) -> Result<Self> {
        let arguments: Value = serde_json::from_str(&call.arguments)
            .with_context(|| format!("tool {} returned invalid JSON arguments", call.name))?;
        let (exec_field, args) = match call.name.as_str() {
            "shell" => (2, shell_args(&arguments, &call.call_id)?),
            "write_file" => (3, write_args(&arguments, &call.call_id)?),
            "grep" => (5, grep_args(&arguments, &call.call_id)?),
            "read_file" => (7, read_args(&arguments, &call.call_id)?),
            "list_dir" => (8, list_args(&arguments, &call.call_id)?),
            name => {
                let tool = mcp_tools
                    .get(name)
                    .ok_or_else(|| anyhow!("model requested unknown tool {name}"))?;
                (11, mcp_args(tool, &arguments, &call.call_id)?)
            }
        };
        let native_display_args = if exec_field == 7 {
            Some(read_display_args(&arguments)?)
        } else {
            None
        };
        let display_args = native_display_args.as_deref().unwrap_or(&args);
        let display_tool_call =
            if let Some(tool_call) = native_display_tool_call(exec_field, display_args) {
                tool_call
            } else {
                let display_args = if let Some(tool) = mcp_tools.get(&call.name) {
                    mcp_args(tool, &arguments, &call.call_id)?
                } else {
                    generic_display_args(&call.name, &arguments, &call.call_id)?
                };
                let mcp_tool_call = message(&[(1, &display_args)]);
                message(&[(15, &mcp_tool_call)])
            };
        Ok(Self {
            id,
            exec_id: call.call_id.clone(),
            model_call_id: call.item_id.clone(),
            exec_field,
            args,
            display_tool_call,
        })
    }
}

fn native_display_tool_call(exec_field: u32, args: &[u8]) -> Option<Vec<u8>> {
    let tool_field = match exec_field {
        2 => 1,  // shell_tool_call
        5 => 5,  // grep_tool_call
        7 => 8,  // read_tool_call
        8 => 13, // ls_tool_call
        _ => return None,
    };
    let native_tool_call = message(&[(1, args)]);
    Some(message(&[(tool_field, &native_tool_call)]))
}

fn exec_server_frame(execution: &ToolExecution) -> Bytes {
    let mut exec = Vec::new();
    push_varint_field(&mut exec, 1, u64::from(execution.id));
    push_bytes_field(&mut exec, execution.exec_field, &execution.args);
    let server = message(&[(2, &exec)]);
    connect_envelope(0, &server)
}

fn tool_started_frame(execution: &ToolExecution) -> Bytes {
    let update = message(&[
        (1, execution.exec_id.as_bytes()),
        (2, &execution.display_tool_call),
        (3, execution.model_call_id.as_bytes()),
    ]);
    let interaction = message(&[(2, &update)]);
    connect_envelope(0, &message(&[(1, &interaction)]))
}

fn tool_completed_frame(execution: &ToolExecution) -> Bytes {
    let update = message(&[
        (1, execution.exec_id.as_bytes()),
        (2, &execution.display_tool_call),
        (3, execution.model_call_id.as_bytes()),
    ]);
    let interaction = message(&[(3, &update)]);
    connect_envelope(0, &message(&[(1, &interaction)]))
}

async fn wait_for_exec_result(
    execution: &ToolExecution,
    client_rx: &mut mpsc::Receiver<ClientMessage>,
) -> Result<String> {
    let result = tokio::time::timeout(std::time::Duration::from_secs(600), async {
        while let Some(message) = client_rx.recv().await {
            if let ClientMessage::Exec { id, exec_id, .. } = &message
                && (*id == execution.id || exec_id == &execution.exec_id)
            {
                return Ok(message);
            }
        }
        bail!("Cursor closed the Agent execution stream")
    })
    .await
    .context("Cursor tool execution timed out")??;
    Ok(exec_result_text(&result))
}

fn shell_args(arguments: &Value, call_id: &str) -> Result<Vec<u8>> {
    let command = required_string(arguments, "command")?;
    let mut args = Vec::new();
    push_bytes_field(&mut args, 1, command.as_bytes());
    if let Some(cwd) = optional_string(arguments, "working_directory") {
        push_bytes_field(&mut args, 2, cwd.as_bytes());
    }
    if let Some(timeout) = arguments.get("timeout").and_then(Value::as_u64) {
        push_varint_field(&mut args, 3, timeout.min(u64::from(u32::MAX)));
    }
    push_bytes_field(&mut args, 4, call_id.as_bytes());
    Ok(args)
}

fn read_args(arguments: &Value, call_id: &str) -> Result<Vec<u8>> {
    let mut args = Vec::new();
    push_bytes_field(&mut args, 1, required_string(arguments, "path")?.as_bytes());
    push_bytes_field(&mut args, 2, call_id.as_bytes());
    if let Some(offset) = arguments.get("offset").and_then(Value::as_u64) {
        push_varint_field(&mut args, 4, offset);
    }
    if let Some(limit) = arguments.get("limit").and_then(Value::as_u64) {
        push_varint_field(&mut args, 5, limit);
    }
    Ok(args)
}

fn read_display_args(arguments: &Value) -> Result<Vec<u8>> {
    let mut args = Vec::new();
    push_bytes_field(&mut args, 1, required_string(arguments, "path")?.as_bytes());
    if let Some(offset) = arguments.get("offset").and_then(Value::as_u64) {
        push_varint_field(&mut args, 2, offset);
    }
    if let Some(limit) = arguments.get("limit").and_then(Value::as_u64) {
        push_varint_field(&mut args, 3, limit);
    }
    Ok(args)
}

fn write_args(arguments: &Value, call_id: &str) -> Result<Vec<u8>> {
    let mut args = Vec::new();
    push_bytes_field(&mut args, 1, required_string(arguments, "path")?.as_bytes());
    push_bytes_field(
        &mut args,
        2,
        required_string(arguments, "content")?.as_bytes(),
    );
    push_bytes_field(&mut args, 3, call_id.as_bytes());
    push_varint_field(&mut args, 4, 1);
    Ok(args)
}

fn grep_args(arguments: &Value, call_id: &str) -> Result<Vec<u8>> {
    let mut args = Vec::new();
    push_bytes_field(
        &mut args,
        1,
        required_string(arguments, "pattern")?.as_bytes(),
    );
    for (field, key) in [(2, "path"), (3, "glob")] {
        if let Some(value) = optional_string(arguments, key) {
            push_bytes_field(&mut args, field, value.as_bytes());
        }
    }
    if arguments
        .get("case_insensitive")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        push_varint_field(&mut args, 8, 1);
    }
    if let Some(limit) = arguments.get("head_limit").and_then(Value::as_u64) {
        push_varint_field(&mut args, 10, limit);
    }
    push_bytes_field(&mut args, 14, call_id.as_bytes());
    Ok(args)
}

fn list_args(arguments: &Value, call_id: &str) -> Result<Vec<u8>> {
    let mut args = Vec::new();
    push_bytes_field(&mut args, 1, required_string(arguments, "path")?.as_bytes());
    push_bytes_field(&mut args, 3, call_id.as_bytes());
    Ok(args)
}

fn mcp_args(tool: &McpTool, arguments: &Value, call_id: &str) -> Result<Vec<u8>> {
    let object = arguments
        .as_object()
        .ok_or_else(|| anyhow!("MCP tool arguments must be an object"))?;
    let mut args = Vec::new();
    push_bytes_field(&mut args, 1, tool.name.as_bytes());
    for (key, value) in object {
        let entry = message(&[(1, key.as_bytes()), (2, &protobuf_value(value))]);
        push_bytes_field(&mut args, 2, &entry);
    }
    push_bytes_field(&mut args, 3, call_id.as_bytes());
    push_bytes_field(&mut args, 4, tool.provider.as_bytes());
    push_bytes_field(&mut args, 5, tool.tool_name.as_bytes());
    push_bytes_field(&mut args, 9, tool.provider.as_bytes());
    Ok(args)
}

fn generic_display_args(name: &str, arguments: &Value, call_id: &str) -> Result<Vec<u8>> {
    let tool = McpTool {
        name: name.to_string(),
        provider: "opensub".to_string(),
        tool_name: name.to_string(),
        description: None,
        parameters: Value::Null,
    };
    mcp_args(&tool, arguments, call_id)
}

fn protobuf_value(value: &Value) -> Vec<u8> {
    let mut output = Vec::new();
    match value {
        Value::Null => push_varint_field(&mut output, 1, 0),
        Value::Bool(value) => push_varint_field(&mut output, 4, u64::from(*value)),
        Value::Number(value) => {
            let number = value.as_f64().unwrap_or_default();
            push_varint(&mut output, 2 << 3 | 1);
            output.extend_from_slice(&number.to_le_bytes());
        }
        Value::String(value) => push_bytes_field(&mut output, 3, value.as_bytes()),
        Value::Object(value) => {
            let mut structure = Vec::new();
            for (key, value) in value {
                let entry = message(&[(1, key.as_bytes()), (2, &protobuf_value(value))]);
                push_bytes_field(&mut structure, 1, &entry);
            }
            push_bytes_field(&mut output, 5, &structure);
        }
        Value::Array(values) => {
            let mut list = Vec::new();
            for value in values {
                push_bytes_field(&mut list, 1, &protobuf_value(value));
            }
            push_bytes_field(&mut output, 6, &list);
        }
    }
    output
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("tool argument {key} must be a string"))
}

fn optional_string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn exec_result_text(result: &ClientMessage) -> String {
    let ClientMessage::Exec {
        result_field,
        result,
        ..
    } = result;
    match result_field {
        2 => shell_result_text(result),
        7 | 29 => read_result_text(result),
        11 => mcp_result_text(result),
        _ => generic_result_text(result),
    }
    .unwrap_or_else(|_| "Cursor returned an unreadable tool result".to_string())
}

fn shell_result_text(raw: &[u8]) -> Result<String> {
    let result = WireMessage::parse(raw)?;
    for (field, status) in [
        (1, "success"),
        (2, "failure"),
        (3, "timeout"),
        (4, "rejected"),
        (5, "spawn_error"),
        (7, "permission_denied"),
    ] {
        if let Some(raw) = result.bytes(field) {
            let detail = WireMessage::parse(raw)?;
            return Ok(json!({
                "status": status,
                "exit_code": detail.varint(3),
                "stdout": detail.string(5).ok().flatten(),
                "stderr": detail.string(6).ok().flatten(),
                "message": detail.string(3).ok().flatten(),
            })
            .to_string());
        }
    }
    generic_result_text(raw)
}

fn read_result_text(raw: &[u8]) -> Result<String> {
    let result = WireMessage::parse(raw)?;
    if let Some(success) = result.bytes(1) {
        let success = WireMessage::parse(success)?;
        return Ok(json!({
            "path": success.string(1)?.unwrap_or_default(),
            "content": success.string(2)?.unwrap_or_default(),
            "total_lines": success.varint(3),
            "file_size": success.varint(4),
            "truncated": success.varint(6).unwrap_or_default() != 0,
        })
        .to_string());
    }
    generic_result_text(raw)
}

fn mcp_result_text(raw: &[u8]) -> Result<String> {
    let result = WireMessage::parse(raw)?;
    if let Some(success) = result.bytes(1) {
        let success = WireMessage::parse(success)?;
        let text = success
            .all_bytes(1)
            .filter_map(|item| WireMessage::parse(item).ok())
            .filter_map(|item| item.bytes(1))
            .filter_map(|text| WireMessage::parse(text).ok())
            .filter_map(|text| text.string(1).ok().flatten().map(str::to_string))
            .collect::<Vec<_>>();
        return Ok(if text.is_empty() {
            "MCP tool completed successfully".to_string()
        } else {
            text.join("\n")
        });
    }
    generic_result_text(raw)
}

fn generic_result_text(raw: &[u8]) -> Result<String> {
    let message = WireMessage::parse(raw)?;
    let mut strings = Vec::new();
    collect_wire_strings(&message, &mut strings, 0);
    strings.dedup();
    Ok(if strings.is_empty() {
        "Cursor tool completed without textual output".to_string()
    } else {
        strings.join("\n")
    })
}

fn collect_wire_strings(message: &WireMessage<'_>, output: &mut Vec<String>, depth: usize) {
    if depth > 8 || output.len() >= 256 {
        return;
    }
    for bytes in message
        .fields
        .iter()
        .filter_map(|field| match &field.value {
            WireValue::Bytes(bytes) => Some(*bytes),
            _ => None,
        })
    {
        if let Ok(text) = std::str::from_utf8(bytes)
            && text
                .chars()
                .all(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        {
            if !text.is_empty() {
                output.push(text.to_string());
            }
        } else if let Ok(nested) = WireMessage::parse(bytes) {
            collect_wire_strings(&nested, output, depth + 1);
        }
    }
}

fn authorize_bridge(headers: &HeaderMap, expected: &str) -> Result<()> {
    let supplied = headers
        .get(BRIDGE_SECRET_HEADER)
        .and_then(|value| value.to_str().ok());
    if supplied != Some(expected) {
        bail!("unauthorized local bridge request");
    }
    Ok(())
}

fn original_host(headers: &HeaderMap) -> Result<String> {
    let host = headers
        .get(ORIGINAL_HOST_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host == "cursor.sh" || host.ends_with(".cursor.sh") {
        Ok(host)
    } else {
        bail!("refusing non-Cursor passthrough host")
    }
}

fn should_forward_request_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "host"
            | "content-length"
            | "connection"
            | "transfer-encoding"
            | BRIDGE_SECRET_HEADER
            | ORIGINAL_HOST_HEADER
    )
}

fn should_forward_response_header(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "content-length" | "connection" | "transfer-encoding"
    )
}

fn connect_error_response(message: &str) -> Response {
    let body = connect_envelope(
        0x02,
        json!({
            "error": {"code": "internal", "message": message}
        })
        .to_string()
        .as_bytes(),
    );
    (
        StatusCode::OK,
        [("content-type", "application/connect+proto")],
        body,
    )
        .into_response()
}

#[derive(Debug)]
struct ConnectFrame<'a> {
    flags: u8,
    payload: &'a [u8],
}

fn first_connect_frame(input: &[u8]) -> Result<Option<ConnectFrame<'_>>> {
    if input.len() < 5 {
        return Ok(None);
    }
    let len = u32::from_be_bytes(input[1..5].try_into().expect("four-byte slice")) as usize;
    if len > MAX_INITIAL_FRAME {
        bail!("initial Agent frame exceeds the safety limit");
    }
    if input.len() < len + 5 {
        return Ok(None);
    }
    Ok(Some(ConnectFrame {
        flags: input[0],
        payload: &input[5..5 + len],
    }))
}

fn decode_connect_message(flags: u8, payload: &[u8]) -> Result<Vec<u8>> {
    if flags & 0x02 != 0 {
        bail!("received a Connect end-stream frame instead of an Agent request");
    }
    if flags & 0x01 == 0 {
        return Ok(payload.to_vec());
    }
    let mut decoder = GzDecoder::new(payload);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .context("invalid gzip-compressed Agent request")?;
    Ok(decoded)
}

#[derive(Debug)]
struct AgentRequest {
    requested_model: String,
    reasoning_effort: Option<String>,
    prompt: String,
    mcp_tools: Vec<McpTool>,
    root_prompt_blobs: Vec<Vec<u8>>,
    turn_blobs: Vec<Vec<u8>>,
    prefetched_blobs: HashMap<Vec<u8>, Vec<u8>>,
    custom_system_prompt: Option<String>,
}

impl AgentRequest {
    fn parse(
        run: &WireMessage<'_>,
        requested_model: String,
        reasoning_effort: Option<String>,
    ) -> Result<Self> {
        let conversation_state = run
            .bytes(1)
            .map(WireMessage::parse)
            .transpose()?
            .unwrap_or(WireMessage { fields: Vec::new() });
        let root_prompt_blobs = conversation_state
            .all_bytes(1)
            .map(ToOwned::to_owned)
            .collect();
        let turn_blobs = conversation_state
            .all_bytes(8)
            .map(ToOwned::to_owned)
            .collect();
        let prefetched_blobs = run
            .all_bytes(17)
            .filter_map(|raw| WireMessage::parse(raw).ok())
            .filter_map(|blob| Some((blob.bytes(1)?.to_vec(), blob.bytes(2)?.to_vec())))
            .collect();
        let action = WireMessage::parse(
            run.bytes(2)
                .ok_or_else(|| anyhow!("Agent run request has no action"))?,
        )?;
        let user_action = WireMessage::parse(
            action
                .bytes(1)
                .ok_or_else(|| anyhow!("Agent action is not a user message"))?,
        )?;
        let user_message = WireMessage::parse(
            user_action
                .bytes(1)
                .ok_or_else(|| anyhow!("Agent user action has no message"))?,
        )?;
        let prompt = user_message
            .string(1)
            .context("Agent user message is not UTF-8")?
            .unwrap_or_default()
            .to_string();
        let mcp_tools = user_action
            .bytes(2)
            .map(WireMessage::parse)
            .transpose()?
            .map(|context| {
                context
                    .all_bytes(7)
                    .filter_map(|raw| McpTool::parse(raw).transpose())
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            requested_model,
            reasoning_effort,
            prompt,
            mcp_tools,
            root_prompt_blobs,
            turn_blobs,
            prefetched_blobs,
            custom_system_prompt: run.string(8)?.map(str::to_string),
        })
    }
}

fn parse_agent_run(message: &[u8]) -> Result<WireMessage<'_>> {
    let client = WireMessage::parse(message)?;
    WireMessage::parse(
        client
            .bytes(1)
            .ok_or_else(|| anyhow!("first Agent message is not a run request"))?,
    )
}

fn parse_requested_model(run: &WireMessage<'_>) -> Result<(String, Option<String>)> {
    if let Some(raw) = run.bytes(9) {
        let requested = WireMessage::parse(raw)?;
        let model = requested
            .string(1)?
            .ok_or_else(|| anyhow!("requested model has no ID"))?
            .to_string();
        let reasoning = requested.all_bytes(3).find_map(|raw| {
            let parameter = WireMessage::parse(raw).ok()?;
            (parameter.string(1).ok().flatten() == Some("reasoning"))
                .then(|| parameter.string(2).ok().flatten().map(str::to_string))
                .flatten()
        });
        return Ok((model, reasoning));
    }
    if let Some(raw) = run.bytes(3) {
        let details = WireMessage::parse(raw)?;
        if let Some(model) = details.string(1)? {
            return Ok((model.to_string(), None));
        }
    }
    bail!("Agent run request has no model ID")
}

#[derive(Debug)]
struct McpTool {
    name: String,
    provider: String,
    tool_name: String,
    description: Option<String>,
    parameters: Value,
}

impl McpTool {
    fn parse(raw: &[u8]) -> Result<Option<Self>> {
        let tool = WireMessage::parse(raw)?;
        let Some(name) = tool.string(1)? else {
            return Ok(None);
        };
        let parameters = tool
            .string(6)?
            .and_then(|schema| serde_json::from_str(schema).ok())
            .unwrap_or_else(|| json!({"type": "object", "properties": {}}));
        Ok(Some(Self {
            name: name.to_string(),
            provider: tool.string(4)?.unwrap_or_default().to_string(),
            tool_name: tool.string(5)?.unwrap_or_default().to_string(),
            description: tool.string(2)?.map(str::to_string),
            parameters,
        }))
    }

    fn responses_value(&self) -> Value {
        let mut value = json!({
            "type": "function",
            "name": self.name,
            "parameters": self.parameters,
        });
        if let Some(description) = &self.description {
            value["description"] = Value::String(description.clone());
        }
        value
    }
}

#[derive(Debug)]
enum WireValue<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed,
}

#[derive(Debug)]
struct WireField<'a> {
    number: u32,
    value: WireValue<'a>,
}

#[derive(Debug)]
struct WireMessage<'a> {
    fields: Vec<WireField<'a>>,
}

impl<'a> WireMessage<'a> {
    fn parse(input: &'a [u8]) -> Result<Self> {
        let mut fields = Vec::new();
        let mut offset = 0;
        while offset < input.len() {
            let key = read_varint(input, &mut offset)?;
            let number = (key >> 3) as u32;
            if number == 0 {
                bail!("protobuf field number cannot be zero");
            }
            let value = match key & 0x07 {
                0 => WireValue::Varint(read_varint(input, &mut offset)?),
                1 => {
                    take(input, &mut offset, 8)?;
                    WireValue::Fixed
                }
                2 => {
                    let len = read_varint(input, &mut offset)? as usize;
                    WireValue::Bytes(take(input, &mut offset, len)?)
                }
                5 => {
                    take(input, &mut offset, 4)?;
                    WireValue::Fixed
                }
                wire => bail!("unsupported protobuf wire type {wire}"),
            };
            fields.push(WireField { number, value });
        }
        Ok(Self { fields })
    }

    fn bytes(&self, number: u32) -> Option<&'a [u8]> {
        self.all_bytes(number).next()
    }

    fn all_bytes(&self, number: u32) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.fields.iter().filter_map(move |field| {
            (field.number == number)
                .then_some(&field.value)
                .and_then(|value| match value {
                    WireValue::Bytes(bytes) => Some(*bytes),
                    _ => None,
                })
        })
    }

    fn string(&self, number: u32) -> Result<Option<&'a str>> {
        self.bytes(number)
            .map(std::str::from_utf8)
            .transpose()
            .map_err(Into::into)
    }

    fn varint(&self, number: u32) -> Option<u64> {
        self.fields.iter().find_map(|field| {
            (field.number == number)
                .then_some(&field.value)
                .and_then(|value| match value {
                    WireValue::Varint(value) => Some(*value),
                    _ => None,
                })
        })
    }
}

fn read_varint(input: &[u8], offset: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *input
            .get(*offset)
            .ok_or_else(|| anyhow!("truncated protobuf varint"))?;
        *offset += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("protobuf varint is too long")
}

fn take<'a>(input: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| anyhow!("protobuf field length overflow"))?;
    let value = input
        .get(*offset..end)
        .ok_or_else(|| anyhow!("truncated protobuf field"))?;
    *offset = end;
    Ok(value)
}

fn is_openai_model(model: &str) -> bool {
    let model = model.to_ascii_lowercase();
    model.starts_with("gpt-")
        || model.starts_with("chatgpt-")
        || model.contains("codex")
        || matches!(model.as_bytes(), [b'o', b'1'..=b'9', ..])
}

fn map_cursor_model(model: &str) -> String {
    if let Ok(override_model) = std::env::var("OPENSUB_CURSOR_MODEL")
        && !override_model.trim().is_empty()
    {
        return override_model.trim().to_string();
    }
    config::DEFAULT_MODELS
        .iter()
        .find(|candidate| model == **candidate || model.starts_with(&format!("{candidate}-")))
        .copied()
        .unwrap_or("gpt-5.5")
        .to_string()
}

fn map_reasoning_effort(value: &str, upstream_model: &str) -> Option<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "none" => Some("none"),
        "minimal" if upstream_model == "gpt-5.5" => Some("low"),
        "minimal" => Some("minimal"),
        "low" => Some("low"),
        "medium" => Some("medium"),
        "high" => Some("high"),
        "xhigh" | "max" => Some("xhigh"),
        _ => None,
    }
}

#[derive(Clone, Copy, Default)]
struct Usage {
    input: u64,
    output: u64,
    cached: u64,
    reasoning: u64,
}

impl Usage {
    fn add(&mut self, other: Self) {
        self.input = self.input.saturating_add(other.input);
        self.output = self.output.saturating_add(other.output);
        self.cached = self.cached.saturating_add(other.cached);
        self.reasoning = self.reasoning.saturating_add(other.reasoning);
    }
}

fn response_usage(event: &Value) -> Option<Usage> {
    let usage = event.get("response")?.get("usage")?;
    Some(Usage {
        input: usage
            .get("input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        output: usage
            .get("output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cached: usage
            .get("input_tokens_details")
            .and_then(|details| details.get("cached_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        reasoning: usage
            .get("output_tokens_details")
            .and_then(|details| details.get("reasoning_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
    })
}

fn text_delta_frame(text: &str) -> Bytes {
    let text_update = message(&[(1, text.as_bytes())]);
    let interaction = message(&[(1, &text_update)]);
    let server = message(&[(1, &interaction)]);
    connect_envelope(0, &server)
}

fn turn_ended_frame(usage: Option<Usage>) -> Bytes {
    let mut ended = Vec::new();
    if let Some(usage) = usage {
        push_varint_field(&mut ended, 1, usage.input);
        push_varint_field(&mut ended, 2, usage.output);
        push_varint_field(&mut ended, 3, usage.cached);
        push_varint_field(&mut ended, 5, usage.reasoning);
    }
    let interaction = message(&[(14, &ended)]);
    let server = message(&[(1, &interaction)]);
    connect_envelope(0, &server)
}

fn end_stream_frame() -> Bytes {
    connect_envelope(0x02, b"{}")
}

fn connect_envelope(flags: u8, payload: &[u8]) -> Bytes {
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.push(flags);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame.into()
}

fn message(fields: &[(u32, &[u8])]) -> Vec<u8> {
    let mut output = Vec::new();
    for (number, value) in fields {
        push_varint(&mut output, u64::from(*number) << 3 | 2);
        push_varint(&mut output, value.len() as u64);
        output.extend_from_slice(value);
    }
    output
}

fn push_varint_field(output: &mut Vec<u8>, number: u32, value: u64) {
    push_varint(output, u64::from(number) << 3);
    push_varint(output, value);
}

fn push_bytes_field(output: &mut Vec<u8>, number: u32, value: &[u8]) {
    push_varint(output, u64::from(number) << 3 | 2);
    push_varint(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn push_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_openai_and_native_models() {
        assert!(is_openai_model("gpt-5.4-nano"));
        assert!(is_openai_model("o4-mini"));
        assert!(is_openai_model("gpt-5.3-codex"));
        assert!(!is_openai_model("composer-2.5"));
        assert!(!is_openai_model("grok-4"));
        assert!(!is_openai_model("claude-4.5-opus"));
    }

    #[test]
    fn native_model_routing_does_not_require_a_user_action() {
        let requested_model = message(&[(1, b"grok-4.5")]);
        let non_user_action = message(&[(2, b"internal-action")]);
        let run_request = message(&[(2, &non_user_action), (9, &requested_model)]);
        let client_message = message(&[(1, &run_request)]);

        let run = parse_agent_run(&client_message).unwrap();
        let (model, reasoning) = parse_requested_model(&run).unwrap();

        assert_eq!(model, "grok-4.5");
        assert_eq!(reasoning, None);
        assert!(!is_openai_model(&model));
        assert!(AgentRequest::parse(&run, model, reasoning).is_err());
    }

    #[test]
    fn preserves_supported_reasoning_effort_for_gpt_5_5() {
        assert_eq!(map_reasoning_effort("none", "gpt-5.5"), Some("none"));
        assert_eq!(map_reasoning_effort("minimal", "gpt-5.5"), Some("low"));
        assert_eq!(map_reasoning_effort("xhigh", "gpt-5.5"), Some("xhigh"));
    }

    #[test]
    fn parses_connect_frame_boundaries() {
        let frame = connect_envelope(0, b"payload");
        assert!(first_connect_frame(&frame[..4]).unwrap().is_none());
        let parsed = first_connect_frame(&frame).unwrap().unwrap();
        assert_eq!(parsed.flags, 0);
        assert_eq!(parsed.payload, b"payload");
    }

    #[test]
    fn text_delta_uses_agent_server_message_shape() {
        let frame = text_delta_frame("hello");
        let parsed = first_connect_frame(&frame).unwrap().unwrap();
        let server = WireMessage::parse(parsed.payload).unwrap();
        let interaction = WireMessage::parse(server.bytes(1).unwrap()).unwrap();
        let update = WireMessage::parse(interaction.bytes(1).unwrap()).unwrap();
        assert_eq!(update.string(1).unwrap(), Some("hello"));
    }

    #[test]
    fn list_execution_uses_native_ls_tool_call_shape() {
        let args = list_args(&json!({"path": "."}), "call-1").unwrap();
        let display = native_display_tool_call(8, &args).unwrap();
        let tool_call = WireMessage::parse(&display).unwrap();
        let ls_tool_call = WireMessage::parse(tool_call.bytes(13).unwrap()).unwrap();
        let ls_args = WireMessage::parse(ls_tool_call.bytes(1).unwrap()).unwrap();
        assert_eq!(ls_args.string(1).unwrap(), Some("."));
        assert_eq!(ls_args.string(3).unwrap(), Some("call-1"));
    }

    #[test]
    fn read_display_uses_read_tool_args_shape() {
        let args =
            read_display_args(&json!({"path": "README.md", "offset": 2, "limit": 5})).unwrap();
        let display = native_display_tool_call(7, &args).unwrap();
        let tool_call = WireMessage::parse(&display).unwrap();
        let read_tool_call = WireMessage::parse(tool_call.bytes(8).unwrap()).unwrap();
        let read_args = WireMessage::parse(read_tool_call.bytes(1).unwrap()).unwrap();
        assert_eq!(read_args.string(1).unwrap(), Some("README.md"));
        assert_eq!(read_args.varint(2), Some(2));
        assert_eq!(read_args.varint(3), Some(5));
    }

    #[test]
    fn exec_server_frame_uses_local_executor_shape() {
        let call = ToolCall {
            item_id: "item-1".to_string(),
            call_id: "call-1".to_string(),
            name: "read_file".to_string(),
            arguments: r#"{"path":"README.md"}"#.to_string(),
        };
        let execution = ToolExecution::from_call(&call, &HashMap::new(), 1).unwrap();
        let frame = exec_server_frame(&execution);
        let parsed = first_connect_frame(&frame).unwrap().unwrap();
        let server = WireMessage::parse(parsed.payload).unwrap();
        let exec = WireMessage::parse(server.bytes(2).unwrap()).unwrap();

        assert_eq!(exec.varint(1), Some(1));
        assert!(exec.bytes(15).is_none());
        assert!(exec.bytes(7).is_some());
    }
}
