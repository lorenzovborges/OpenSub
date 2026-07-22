//! Local bridge for Cursor's Connect/protobuf Agent stream.
//!
//! The bridge only handles OpenAI-family model requests. Other models are
//! streamed unchanged to Cursor's backend so Composer, Grok, and future native
//! models continue to use the user's Cursor subscription.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine;
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
const MAX_CACHED_CONVERSATIONS: usize = 32;
const MAX_CACHED_TURNS: usize = 64;
const MAX_CACHED_CONVERSATION_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROTOCOL_TRACE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CURSOR_INSTRUCTIONS_BYTES: usize = 256 * 1024;
const MAX_TRANSCRIPT_READ_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TRANSCRIPT_MESSAGES: usize = 128;
const MAX_TRANSCRIPT_CONTEXT_BYTES: usize = 2 * 1024 * 1024;

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
    conversations: Arc<ConversationCache>,
    capture_protocol: bool,
    trace: Option<Arc<ProtocolTrace>>,
    native_passthrough: bool,
    next_request_id: Arc<AtomicU64>,
}

impl BridgeState {
    pub fn new(secret: String, capture_protocol: bool) -> Result<Self> {
        let trace_enabled = trace_env_enabled("OPENSUB_CURSOR_TRACE");
        let native_passthrough = trace_env_enabled("OPENSUB_CURSOR_NATIVE_TRACE");
        if trace_enabled && native_passthrough {
            bail!("OpenSub and native Cursor trace modes cannot be enabled together");
        }
        let trace_path = if native_passthrough {
            Some(native_protocol_trace_path())
        } else if trace_enabled {
            Some(protocol_trace_path())
        } else {
            None
        };
        let trace = trace_path
            .map(|path| ProtocolTrace::new(path).map(Arc::new))
            .transpose()?;
        Ok(Self {
            secret: secret.into(),
            client: reqwest::Client::builder()
                .user_agent("OpenSub Cursor Bridge")
                .build()?,
            events: Arc::new(EventLog::new()?),
            conversations: Arc::new(ConversationCache::default()),
            capture_protocol,
            trace,
            native_passthrough,
            next_request_id: Arc::new(AtomicU64::new(1)),
        })
    }
}

fn trace_env_enabled(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| matches!(value.trim(), "1" | "true" | "yes"))
}

struct ProtocolTrace {
    path: PathBuf,
    state: Mutex<ProtocolTraceState>,
}

struct ProtocolTraceState {
    file: BufWriter<std::fs::File>,
    bytes: u64,
    sequence: u64,
    truncated: bool,
}

impl ProtocolTrace {
    fn new(path: PathBuf) -> Result<Self> {
        let parent = path.parent().context("protocol trace has no parent")?;
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
            path,
            state: Mutex::new(ProtocolTraceState {
                file: BufWriter::with_capacity(256 * 1024, file),
                bytes: 0,
                sequence: 0,
                truncated: false,
            }),
        })
    }

    fn record_json(&self, request_id: u64, direction: &str, kind: &str, data: Value) {
        self.record(request_id, direction, kind, "json", data);
    }

    fn record_bytes(&self, request_id: u64, direction: &str, kind: &str, data: &[u8]) {
        self.record(
            request_id,
            direction,
            kind,
            "base64",
            Value::String(base64::engine::general_purpose::STANDARD.encode(data)),
        );
    }

    fn record(&self, request_id: u64, direction: &str, kind: &str, encoding: &str, data: Value) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.truncated {
            return;
        }
        state.sequence = state.sequence.saturating_add(1);
        let line = json!({
            "timestamp_ms": now_ms(),
            "sequence": state.sequence,
            "request_id": request_id,
            "direction": direction,
            "kind": kind,
            "encoding": encoding,
            "data": data,
        })
        .to_string();
        let line_bytes = line.len().saturating_add(1) as u64;
        if state.bytes.saturating_add(line_bytes) > MAX_PROTOCOL_TRACE_BYTES {
            let marker = json!({
                "timestamp_ms": now_ms(),
                "sequence": state.sequence,
                "request_id": request_id,
                "direction": "opensub",
                "kind": "trace_truncated",
                "encoding": "json",
                "data": {"max_bytes": MAX_PROTOCOL_TRACE_BYTES},
            });
            let _ = writeln!(state.file, "{marker}");
            state.truncated = true;
            tracing::warn!(
                path = %self.path.display(),
                max_bytes = MAX_PROTOCOL_TRACE_BYTES,
                "protocol trace reached its size limit"
            );
            return;
        }
        if writeln!(state.file, "{line}").is_ok() {
            state.bytes = state.bytes.saturating_add(line_bytes);
        }
    }
}

pub fn protocol_trace_path() -> PathBuf {
    config::data_dir()
        .join("cursor-proxy")
        .join("protocol-trace.jsonl")
}

pub fn native_protocol_trace_path() -> PathBuf {
    config::data_dir()
        .join("cursor-proxy")
        .join("cursor-native-trace.jsonl")
}

#[derive(Default)]
struct ConversationCache {
    conversations: Mutex<HashMap<String, CachedConversation>>,
}

#[derive(Default)]
struct CachedConversation {
    turns: VecDeque<CachedTurn>,
    bytes: usize,
    updated_at_ms: u128,
}

struct CachedTurn {
    items: Vec<Value>,
    bytes: usize,
}

impl ConversationCache {
    fn snapshot(&self, conversation_id: &str) -> Vec<Value> {
        let Ok(conversations) = self.conversations.lock() else {
            return Vec::new();
        };
        conversations
            .get(conversation_id)
            .map(|conversation| {
                conversation
                    .turns
                    .iter()
                    .flat_map(|turn| turn.items.iter().cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn commit(&self, conversation_id: String, mut items: Vec<Value>) {
        if items.is_empty() {
            return;
        }
        let mut bytes = serialized_items_len(&items);
        if bytes > MAX_CACHED_CONVERSATION_BYTES {
            items.retain(|item| item.get("type").and_then(Value::as_str) == Some("message"));
            bytes = serialized_items_len(&items);
        }
        if items.is_empty() || bytes > MAX_CACHED_CONVERSATION_BYTES {
            return;
        }

        let Ok(mut conversations) = self.conversations.lock() else {
            return;
        };
        if !conversations.contains_key(&conversation_id)
            && conversations.len() >= MAX_CACHED_CONVERSATIONS
            && let Some(oldest) = conversations
                .iter()
                .min_by_key(|(_, conversation)| conversation.updated_at_ms)
                .map(|(id, _)| id.clone())
        {
            conversations.remove(&oldest);
        }
        let conversation = conversations.entry(conversation_id).or_default();
        conversation.turns.push_back(CachedTurn { items, bytes });
        conversation.bytes = conversation.bytes.saturating_add(bytes);
        conversation.updated_at_ms = now_ms();
        while conversation.turns.len() > MAX_CACHED_TURNS
            || conversation.bytes > MAX_CACHED_CONVERSATION_BYTES
        {
            let Some(removed) = conversation.turns.pop_front() else {
                break;
            };
            conversation.bytes = conversation.bytes.saturating_sub(removed.bytes);
        }
    }
}

fn serialized_items_len(items: &[Value]) -> usize {
    items
        .iter()
        .map(|item| {
            serde_json::to_vec(item)
                .map(|value| value.len())
                .unwrap_or_default()
        })
        .sum()
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
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

    if state.native_passthrough {
        let request_id = state.next_request_id.fetch_add(1, Ordering::Relaxed);
        if let Some(trace) = &state.trace {
            trace.record_json(
                request_id,
                "opensub",
                "native_cursor_route",
                json!({
                    "model": requested_model,
                    "reasoning_effort": reasoning_effort,
                    "original_host": original_host,
                    "transport": format!("{:?}", parts.version),
                }),
            );
        }
        state
            .events
            .record("route_cursor_trace", Some(&requested_model));
        return passthrough(
            state,
            parts.headers,
            original_host,
            buffered,
            incoming,
            Some(request_id),
        )
        .await;
    }

    if !is_openai_model(&requested_model) {
        state.events.record("route_cursor", Some(&requested_model));
        tracing::debug!(
            model = %requested_model,
            host = %original_host,
            "Cursor Agent request routed to Cursor"
        );
        return passthrough(
            state,
            parts.headers,
            original_host,
            buffered,
            incoming,
            None,
        )
        .await;
    }

    let request_id = state.next_request_id.fetch_add(1, Ordering::Relaxed);
    if let Some(trace) = &state.trace {
        trace.record_bytes(
            request_id,
            "cursor_to_opensub",
            "agent_run_protobuf",
            &message,
        );
        trace.record_json(
            request_id,
            "opensub",
            "route_metadata",
            json!({
                "model": requested_model,
                "reasoning_effort": reasoning_effort,
                "original_host": original_host,
            }),
        );
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
    tokio::spawn(read_client_stream(
        initial_remainder,
        incoming,
        client_tx,
        state.trace.clone(),
        request_id,
    ));

    Ok(openai_response(
        agent,
        client_rx,
        Arc::clone(&state.events),
        Arc::clone(&state.conversations),
        state.trace.clone(),
        request_id,
    )
    .await)
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
    trace_request_id: Option<u64>,
) -> Result<Response>
where
    S: futures::Stream<Item = Result<Bytes, axum::Error>> + Send + 'static,
{
    if let (Some(trace), Some(request_id)) = (&state.trace, trace_request_id) {
        for chunk in &buffered {
            trace.record_bytes(
                request_id,
                "cursor_to_cursor_cloud",
                "request_body_chunk",
                chunk,
            );
        }
    }
    let prefix = futures::stream::iter(buffered.into_iter().map(Ok::<Bytes, std::io::Error>));
    let request_trace = state.trace.clone();
    let remainder = incoming.map(move |result| match result {
        Ok(chunk) => {
            if let (Some(trace), Some(request_id)) = (&request_trace, trace_request_id) {
                trace.record_bytes(
                    request_id,
                    "cursor_to_cursor_cloud",
                    "request_body_chunk",
                    &chunk,
                );
            }
            Ok(chunk)
        }
        Err(error) => Err(std::io::Error::other(error)),
    });
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
    if let (Some(trace), Some(request_id)) = (&state.trace, trace_request_id) {
        trace.record_json(
            request_id,
            "cursor_cloud_to_cursor",
            "response_metadata",
            json!({"status": status.as_u16()}),
        );
    }
    let response_trace = state.trace.clone();
    let stream = upstream.bytes_stream().map(move |result| match result {
        Ok(chunk) => {
            if let (Some(trace), Some(request_id)) = (&response_trace, trace_request_id) {
                trace.record_bytes(
                    request_id,
                    "cursor_cloud_to_cursor",
                    "response_body_chunk",
                    &chunk,
                );
            }
            Ok(chunk)
        }
        Err(error) => Err(std::io::Error::other(error)),
    });
    let mut response = Response::builder().status(status);
    for (name, value) in &response_headers {
        if should_forward_response_header(name) {
            response = response.header(name, value);
        }
    }
    Ok(response.body(Body::from_stream(stream))?)
}

async fn send_cursor_frame(
    tx: &mpsc::Sender<Result<Bytes, Infallible>>,
    trace: Option<&Arc<ProtocolTrace>>,
    request_id: u64,
    kind: &str,
    frame: Bytes,
) -> Result<()> {
    if let Some(trace) = trace {
        trace.record_bytes(request_id, "opensub_to_cursor", kind, &frame);
    }
    tx.send(Ok(frame)).await?;
    Ok(())
}

async fn openai_response(
    agent: AgentRequest,
    client_rx: mpsc::Receiver<ClientMessage>,
    events: Arc<EventLog>,
    conversations: Arc<ConversationCache>,
    trace: Option<Arc<ProtocolTrace>>,
    request_id: u64,
) -> Response {
    let (tx, rx) = mpsc::channel::<Result<Bytes, Infallible>>(32);
    tokio::spawn(async move {
        if let Err(error) = stream_openai_agent(
            agent,
            client_rx,
            tx.clone(),
            Arc::clone(&events),
            conversations,
            trace.clone(),
            request_id,
        )
        .await
        {
            events.record("error_generation", None);
            tracing::warn!(error = %error, "OpenSub Agent generation failed");
            if let Some(trace) = &trace {
                trace.record_json(
                    request_id,
                    "opensub",
                    "generation_error",
                    json!({"message": format!("{error:#}")}),
                );
            }
            let message = text_delta_frame(
                "OpenSub could not complete this request. Check the proxy terminal for details.",
            );
            let _ = send_cursor_frame(&tx, trace.as_ref(), request_id, "error_text", message).await;
            let _ = send_cursor_frame(
                &tx,
                trace.as_ref(),
                request_id,
                "turn_ended",
                turn_ended_frame(None),
            )
            .await;
            let _ = send_cursor_frame(
                &tx,
                trace.as_ref(),
                request_id,
                "end_stream",
                end_stream_frame(),
            )
            .await;
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
    conversations: Arc<ConversationCache>,
    trace: Option<Arc<ProtocolTrace>>,
    request_id: u64,
) -> Result<()> {
    let tokens = auth::require_token().await?;
    let upstream_model = map_cursor_model(&agent.requested_model);
    let inherited_subagent_model =
        model_with_reasoning_variant(&agent.requested_model, agent.reasoning_effort.as_deref());
    let conversation = load_conversation_material(&agent);
    let mut input = conversation.input;
    if input.is_empty()
        && let Some(conversation_id) = &agent.conversation_id
    {
        input = conversations.snapshot(conversation_id);
    }
    let turn_start = input.len();
    let current_prompt = agent.prompt.clone();
    input.push(json!({
        "type": "message",
        "role": "user",
        "content": [{"type": "input_text", "text": current_prompt}]
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
    if !agent.mcp_tools.is_empty() {
        instructions.push(mcp_catalog_instruction(&agent.mcp_tools));
    }
    let mut tools = core_tools();
    if !agent.mcp_tools.is_empty() {
        tools.extend(mcp_meta_tools());
    }
    let mcp_tools = agent
        .mcp_tools
        .iter()
        .map(|tool| (tool.name.clone(), tool))
        .collect::<HashMap<_, _>>();
    let mut exec_sequence = 1u32;
    let mut total_usage = Usage::default();
    let mut round_number = 0u32;

    loop {
        round_number = round_number.saturating_add(1);
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
            "prompt_cache_key": agent.conversation_id.as_deref().unwrap_or(config::session_id()),
        });
        if let Some(effort) = agent
            .reasoning_effort
            .as_deref()
            .and_then(|effort| map_reasoning_effort(effort, &upstream_model))
        {
            body["reasoning"] = json!({"effort": effort});
        }

        let round = stream_responses_round(
            &tokens,
            &body,
            &tx,
            trace.as_ref(),
            request_id,
            round_number,
        )
        .await?;
        if let Some(usage) = round.usage {
            total_usage.add(usage);
        }
        input.extend(round.output_items);
        if round.tool_calls.is_empty() {
            if let Some(conversation_id) = &agent.conversation_id {
                conversations.commit(conversation_id.clone(), input[turn_start..].to_vec());
            }
            send_cursor_frame(
                &tx,
                trace.as_ref(),
                request_id,
                "turn_ended",
                turn_ended_frame(Some(total_usage)),
            )
            .await?;
            send_cursor_frame(
                &tx,
                trace.as_ref(),
                request_id,
                "end_stream",
                end_stream_frame(),
            )
            .await?;
            return Ok(());
        }

        for call in round.tool_calls {
            tracing::debug!(tool = %call.name, "Cursor tool execution requested");
            events.record("tool_requested", Some(&call.name));
            if call.name == "GetMcpTools" {
                let output = discover_mcp_tools(&call.arguments, &agent.mcp_tools)?;
                events.record("tool_completed", Some(&call.name));
                input.push(json!({
                    "type": "function_call_output",
                    "call_id": call.call_id,
                    "output": output,
                }));
                continue;
            }
            let execution = ToolExecution::from_call(
                &call,
                &mcp_tools,
                exec_sequence,
                agent.conversation_id.as_deref(),
                Some(&inherited_subagent_model),
            )?;
            exec_sequence = exec_sequence.saturating_add(1);
            send_cursor_frame(
                &tx,
                trace.as_ref(),
                request_id,
                "tool_started",
                tool_started_frame(&execution),
            )
            .await?;
            send_cursor_frame(
                &tx,
                trace.as_ref(),
                request_id,
                "tool_execute",
                exec_server_frame(&execution),
            )
            .await?;
            let result = wait_for_exec_result(&execution, &mut client_rx).await?;
            events.record("tool_completed", Some(&call.name));
            send_cursor_frame(
                &tx,
                trace.as_ref(),
                request_id,
                "tool_completed",
                tool_completed_frame(&execution, &result),
            )
            .await?;
            input.push(json!({
                "type": "function_call_output",
                "call_id": call.call_id,
                "output": result.output_text,
            }));
        }
    }
}

async fn stream_responses_round(
    tokens: &crate::auth::store::TokenData,
    body: &Value,
    tx: &mpsc::Sender<Result<Bytes, Infallible>>,
    trace: Option<&Arc<ProtocolTrace>>,
    request_id: u64,
    round_number: u32,
) -> Result<ResponsesRound> {
    if let Some(trace) = trace {
        trace.record_json(
            request_id,
            "opensub_to_codex",
            "responses_request",
            json!({"round": round_number, "body": body}),
        );
    }
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
                if let Some(trace) = trace {
                    trace.record_json(
                        request_id,
                        "codex_to_opensub",
                        "malformed_responses_sse_data",
                        json!({
                            "round": round_number,
                            "parse_error": error.to_string(),
                            "data": data,
                        }),
                    );
                }
                tracing::debug!(error = %error, bytes = data.len(), "ignored malformed Responses event");
                continue;
            }
        };
        if let Some(trace) = trace {
            trace.record_json(
                request_id,
                "codex_to_opensub",
                "responses_sse_event",
                json!({"round": round_number, "event": event.clone()}),
            );
        }
        match event.get("type").and_then(Value::as_str) {
            Some("response.output_text.delta") => {
                if let Some(delta) = event.get("delta").and_then(Value::as_str)
                    && !delta.is_empty()
                {
                    send_cursor_frame(tx, trace, request_id, "text_delta", text_delta_frame(delta))
                        .await?;
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
                bail!(
                    "Responses upstream generation failed: {}",
                    responses_error(&event)
                );
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

fn responses_error(event: &Value) -> String {
    let error = event
        .pointer("/response/error")
        .or_else(|| event.get("error"));
    let Some(error) = error else {
        return "no error details provided".to_string();
    };
    if let Some(message) = error.as_str() {
        return truncate_error(message);
    }

    let code = error.get("code").and_then(Value::as_str);
    let kind = error.get("type").and_then(Value::as_str);
    let message = error.get("message").and_then(Value::as_str);
    let details = [code, kind, message]
        .into_iter()
        .flatten()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>()
        .join(": ");
    if details.is_empty() {
        "no error details provided".to_string()
    } else {
        truncate_error(&details)
    }
}

fn truncate_error(message: &str) -> String {
    const MAX_CHARS: usize = 500;
    let mut chars = message.chars();
    let truncated = chars.by_ref().take(MAX_CHARS).collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
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
        function_tool(
            "task",
            "Delegate a task to a Cursor subagent. Cursor creates and runs the subagent in its own harness, inheriting the current model and reasoning mode.",
            json!({
                "type":"object", "properties": {
                    "description":{"type":"string"},
                    "prompt":{"type":"string"},
                    "subagent_type":{"type":"string"},
                    "resume":{"type":"string"},
                    "readonly":{"type":"boolean"},
                    "run_in_background":{"type":"boolean"}
                }, "required":["description","prompt","subagent_type"]
            }),
        ),
    ]
}

fn mcp_meta_tools() -> Vec<Value> {
    vec![
        function_tool(
            "GetMcpTools",
            "Discover MCP servers and tool schemas. Call this before CallMcpTool.",
            json!({
                "type":"object",
                "properties": {
                    "server":{"type":"string"},
                    "toolName":{"type":"string"},
                    "pattern":{"type":"string"}
                },
                "additionalProperties": false
            }),
        ),
        function_tool(
            "CallMcpTool",
            "Invoke an MCP tool through Cursor after discovering it with GetMcpTools.",
            json!({
                "type":"object",
                "properties": {
                    "server":{"type":"string"},
                    "toolName":{"type":"string"},
                    "arguments":{"type":"object"},
                    "description":{"type":"string"}
                },
                "required":["server","toolName","arguments"],
                "additionalProperties": false
            }),
        ),
    ]
}

fn mcp_catalog_instruction(tools: &[McpTool]) -> String {
    let mut servers = HashMap::<&str, Vec<&str>>::new();
    for tool in tools {
        servers
            .entry(tool.server_id.as_str())
            .or_default()
            .push(tool.tool_name.as_str());
    }
    let mut servers = servers.into_iter().collect::<Vec<_>>();
    servers.sort_by_key(|(server, _)| *server);
    let catalog = servers
        .into_iter()
        .map(|(server, mut names)| {
            names.sort_unstable();
            names.dedup();
            format!("- {server}: {}", names.join(", "))
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "MCP tools are executed by Cursor. Always call GetMcpTools to inspect a schema before CallMcpTool. Available servers:\n{catalog}"
    )
}

fn discover_mcp_tools(arguments: &str, tools: &[McpTool]) -> Result<String> {
    let arguments: Value =
        serde_json::from_str(arguments).context("GetMcpTools returned invalid JSON arguments")?;
    let server = optional_string(&arguments, "server");
    let tool_name = optional_string(&arguments, "toolName");
    let pattern = optional_string(&arguments, "pattern").map(str::to_ascii_lowercase);

    if server.is_none() && tool_name.is_none() && pattern.is_none() {
        let mut catalog = HashMap::<&str, Vec<&str>>::new();
        for tool in tools {
            catalog
                .entry(tool.server_id.as_str())
                .or_default()
                .push(tool.tool_name.as_str());
        }
        let mut catalog = catalog
            .into_iter()
            .map(|(server, mut names)| {
                names.sort_unstable();
                names.dedup();
                json!({"server": server, "tools": names})
            })
            .collect::<Vec<_>>();
        catalog.sort_by(|left, right| {
            left.get("server")
                .and_then(Value::as_str)
                .cmp(&right.get("server").and_then(Value::as_str))
        });
        return Ok(serde_json::to_string(&catalog)?);
    }

    let matched = tools
        .iter()
        .filter(|tool| {
            server.is_none_or(|server| tool.server_id == server || tool.provider == server)
        })
        .filter(|tool| tool_name.is_none_or(|name| tool.tool_name == name || tool.name == name))
        .filter(|tool| {
            pattern.as_ref().is_none_or(|pattern| {
                tool.name.to_ascii_lowercase().contains(pattern)
                    || tool.tool_name.to_ascii_lowercase().contains(pattern)
                    || tool.server_id.to_ascii_lowercase().contains(pattern)
                    || tool.provider.to_ascii_lowercase().contains(pattern)
                    || tool
                        .description
                        .as_deref()
                        .unwrap_or_default()
                        .to_ascii_lowercase()
                        .contains(pattern)
            })
        })
        .map(|tool| {
            json!({
                "server": tool.server_id,
                "toolName": tool.tool_name,
                "description": tool.description,
                "inputSchema": tool.parameters,
            })
        })
        .collect::<Vec<_>>();
    Ok(serde_json::to_string(&matched)?)
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
    tracing::debug!(
        root_prompts = agent.root_prompt_messages_json.len(),
        history_messages = agent.history.len(),
        has_summary = agent.conversation_summary.is_some(),
        "Cursor conversation context prepared"
    );

    let mut material = ConversationMaterial::default();
    let mut instruction_parts = Vec::new();
    for message in &agent.root_prompt_messages_json {
        match serde_json::from_str(message) {
            Ok(Value::String(text)) => instruction_parts.push(text),
            Ok(json) => collect_context_text(&json, &mut instruction_parts),
            Err(_) if !message.trim().is_empty() => instruction_parts.push(message.clone()),
            Err(_) => {}
        }
    }
    if let Some(summary) = &agent.conversation_summary
        && !summary.trim().is_empty()
    {
        instruction_parts.push(format!("Conversation summary:\n{summary}"));
    }
    instruction_parts.extend(agent.cursor_context_instructions.iter().cloned());
    instruction_parts.retain(|part| !part.trim().is_empty());
    material.instructions = instruction_parts.join("\n\n");
    material.input = if agent.history.is_empty() {
        agent
            .transcript_path
            .as_deref()
            .map(|path| load_transcript_history(path, &agent.prompt))
            .unwrap_or_default()
    } else {
        agent.history.clone()
    };
    material
}

fn load_transcript_history(path: &Path, current_prompt: &str) -> Vec<Value> {
    let Ok(metadata) = fs::metadata(path) else {
        return Vec::new();
    };
    if !metadata.is_file() {
        return Vec::new();
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let start = metadata.len().saturating_sub(MAX_TRANSCRIPT_READ_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut raw = Vec::with_capacity(
        metadata
            .len()
            .saturating_sub(start)
            .min(MAX_TRANSCRIPT_READ_BYTES) as usize,
    );
    if file
        .take(MAX_TRANSCRIPT_READ_BYTES)
        .read_to_end(&mut raw)
        .is_err()
    {
        return Vec::new();
    }
    if start > 0 {
        let Some(first_newline) = raw.iter().position(|byte| *byte == b'\n') else {
            return Vec::new();
        };
        raw.drain(..=first_newline);
    }
    let content = String::from_utf8_lossy(&raw);

    parse_transcript_history(&content, current_prompt)
}

fn parse_transcript_history(content: &str, current_prompt: &str) -> Vec<Value> {
    let mut messages = VecDeque::<(Value, usize)>::new();
    let mut total_bytes = 0usize;
    for line in content.lines() {
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(role) = record.get("role").and_then(Value::as_str) else {
            continue;
        };
        if !matches!(role, "user" | "assistant") {
            continue;
        }
        let text = record
            .pointer("/message/content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|item| item.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|item| item.get("text").and_then(Value::as_str))
            .filter(|text| !text.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        if text.is_empty() || (role == "user" && transcript_contains_prompt(&text, current_prompt))
        {
            continue;
        }
        let bytes = text.len();
        let message = history_message(role, text);
        messages.push_back((message, bytes));
        total_bytes = total_bytes.saturating_add(bytes);
        while messages.len() > MAX_TRANSCRIPT_MESSAGES || total_bytes > MAX_TRANSCRIPT_CONTEXT_BYTES
        {
            let Some((_, removed_bytes)) = messages.pop_front() else {
                break;
            };
            total_bytes = total_bytes.saturating_sub(removed_bytes);
        }
    }
    messages.into_iter().map(|(message, _)| message).collect()
}

fn transcript_contains_prompt(transcript_message: &str, current_prompt: &str) -> bool {
    let prompt = current_prompt.trim();
    if prompt.is_empty() {
        return false;
    }
    transcript_message.trim() == prompt
        || transcript_message.contains(&format!("<user_query>\n{prompt}\n</user_query>"))
}

fn decode_blob_text(raw: &[u8]) -> Option<String> {
    let decoded = decode_blob_bytes(raw)?;
    let text = std::str::from_utf8(&decoded).ok()?;
    if let Ok(Value::String(value)) = serde_json::from_str(text) {
        return Some(value);
    }
    if let Ok(json) = serde_json::from_str(text) {
        let mut parts = Vec::new();
        collect_context_text(&json, &mut parts);
        if !parts.is_empty() {
            return Some(parts.join("\n"));
        }
    }
    Some(text.to_string())
}

fn decode_blob_bytes(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = GzDecoder::new(raw);
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).ok()?;
        Some(decoded)
    } else {
        Some(raw.to_vec())
    }
}

fn collect_context_text(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for key in ["content", "text", "message", "instructions", "prompt"] {
                if let Some(value) = object.get(key) {
                    if let Some(text) = value.as_str() {
                        output.push(text.to_string());
                    } else {
                        collect_context_text(value, output);
                    }
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

fn history_message(role: &str, text: String) -> Value {
    json!({
        "type": "message",
        "role": role,
        "content": [{
            "type": if role == "assistant" {"output_text"} else {"input_text"},
            "text": text
        }]
    })
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

async fn read_client_stream<S>(
    mut buffer: Vec<u8>,
    incoming: S,
    tx: mpsc::Sender<ClientMessage>,
    trace: Option<Arc<ProtocolTrace>>,
    request_id: u64,
) where
    S: futures::Stream<Item = Result<Bytes, axum::Error>> + Send + 'static,
{
    futures::pin_mut!(incoming);
    loop {
        while let Ok(Some(frame)) = first_connect_frame(&buffer) {
            let frame_len = frame.payload.len() + 5;
            if frame.flags & 0x02 == 0
                && let Ok(message) = decode_connect_message(frame.flags, frame.payload)
            {
                if let Some(trace) = &trace {
                    trace.record_bytes(
                        request_id,
                        "cursor_to_opensub",
                        "agent_client_protobuf",
                        &message,
                    );
                }
                if let Ok(Some(message)) = parse_exec_client_message(&message)
                    && tx.send(message).await.is_err()
                {
                    return;
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

fn parse_exec_client_message(message: &[u8]) -> Result<Option<ClientMessage>> {
    let client = WireMessage::parse(message)?;
    let Some(exec) = client.bytes(2).map(WireMessage::parse).transpose()? else {
        return Ok(None);
    };
    let result = exec.fields.iter().find_map(|field| {
        if matches!(
            field.number,
            2 | 3 | 5 | 7 | 8 | 10 | 11 | 14 | 28 | 29 | 36
        ) && let WireValue::Bytes(value) = &field.value
        {
            Some((field.number, value.to_vec()))
        } else {
            None
        }
    });
    Ok(result.map(|(result_field, result)| ClientMessage::Exec {
        id: exec.varint(1).unwrap_or_default() as u32,
        exec_id: exec
            .string(15)
            .ok()
            .flatten()
            .unwrap_or_default()
            .to_string(),
        result_field,
        result,
    }))
}

#[derive(Debug)]
struct ToolExecution {
    id: u32,
    exec_id: String,
    model_call_id: String,
    exec_field: u32,
    args: Vec<u8>,
    display_field: u32,
    display_args: Vec<u8>,
    started_at_ms: u64,
}

impl ToolExecution {
    fn from_call(
        call: &ToolCall,
        mcp_tools: &HashMap<String, &McpTool>,
        id: u32,
        parent_conversation_id: Option<&str>,
        default_subagent_model: Option<&str>,
    ) -> Result<Self> {
        let arguments: Value = serde_json::from_str(&call.arguments)
            .with_context(|| format!("tool {} returned invalid JSON arguments", call.name))?;
        let selected_mcp = if call.name == "CallMcpTool" {
            let server = required_string(&arguments, "server")?;
            let tool_name = required_string(&arguments, "toolName")?;
            mcp_tools
                .values()
                .copied()
                .find(|tool| {
                    (tool.server_id == server || tool.provider == server)
                        && tool.tool_name == tool_name
                })
                .ok_or_else(|| anyhow!("Cursor MCP tool {server}/{tool_name} is unavailable"))?
                .into()
        } else {
            mcp_tools.get(&call.name).copied()
        };
        let execution_arguments = if call.name == "CallMcpTool" {
            arguments
                .get("arguments")
                .ok_or_else(|| anyhow!("CallMcpTool arguments must be an object"))?
        } else {
            &arguments
        };
        let (exec_field, args) = match call.name.as_str() {
            "shell" | "Shell" => (14, shell_args(&arguments, &call.call_id)?),
            "write_file" | "WriteFile" => (3, write_args(&arguments, &call.call_id)?),
            "grep" | "Grep" => (5, grep_args(&arguments, &call.call_id)?),
            "read_file" | "ReadFile" => (7, read_args(&arguments, &call.call_id)?),
            "list_dir" | "Glob" => (8, list_args(&arguments, &call.call_id)?),
            "task" | "Task" => (
                28,
                subagent_args(
                    &arguments,
                    &call.call_id,
                    parent_conversation_id,
                    default_subagent_model,
                )?,
            ),
            name => {
                let tool =
                    selected_mcp.ok_or_else(|| anyhow!("model requested unknown tool {name}"))?;
                (11, mcp_args(tool, execution_arguments, &call.call_id)?)
            }
        };
        let native_display_args = match exec_field {
            7 => Some(read_display_args(&arguments)?),
            28 => Some(task_display_args(&arguments, default_subagent_model)?),
            _ => None,
        };
        let display_args = native_display_args.as_deref().unwrap_or(&args);
        let (display_field, display_args) =
            if let Some(display_field) = native_display_field(exec_field) {
                (display_field, display_args.to_vec())
            } else {
                let display_args = if let Some(tool) = selected_mcp {
                    mcp_args(tool, execution_arguments, &call.call_id)?
                } else {
                    generic_display_args(&call.name, &arguments, &call.call_id)?
                };
                (15, display_args)
            };
        Ok(Self {
            id,
            exec_id: call.call_id.clone(),
            model_call_id: call.item_id.clone(),
            exec_field,
            args,
            display_field,
            display_args,
            started_at_ms: now_ms().min(u128::from(u64::MAX)) as u64,
        })
    }
}

fn native_display_field(exec_field: u32) -> Option<u32> {
    match exec_field {
        14 => Some(1),  // shell_tool_call
        5 => Some(5),   // grep_tool_call
        7 => Some(8),   // read_tool_call
        8 => Some(13),  // ls_tool_call
        28 => Some(19), // task_tool_call
        _ => None,
    }
}

#[cfg(test)]
fn native_display_tool_call(exec_field: u32, args: &[u8]) -> Option<Vec<u8>> {
    native_display_field(exec_field)
        .map(|field| display_tool_call(field, args, None, None, None, None))
}

fn display_tool_call(
    field: u32,
    args: &[u8],
    result: Option<&[u8]>,
    call_id: Option<&str>,
    started_at_ms: Option<u64>,
    completed_at_ms: Option<u64>,
) -> Vec<u8> {
    let mut call = Vec::new();
    push_bytes_field(&mut call, 1, args);
    if let Some(result) = result {
        push_bytes_field(&mut call, 2, result);
    }
    let mut display = message(&[(field, &call)]);
    if let Some(call_id) = call_id {
        push_bytes_field(&mut display, 57, call_id.as_bytes());
    }
    if let Some(started_at_ms) = started_at_ms {
        push_varint_field(&mut display, 59, started_at_ms);
    }
    if let Some(completed_at_ms) = completed_at_ms {
        push_varint_field(&mut display, 60, completed_at_ms);
    }
    display
}

fn exec_server_frame(execution: &ToolExecution) -> Bytes {
    let mut exec = Vec::new();
    push_varint_field(&mut exec, 1, u64::from(execution.id));
    push_bytes_field(&mut exec, execution.exec_field, &execution.args);
    let server = message(&[(2, &exec)]);
    connect_envelope(0, &server)
}

fn tool_started_frame(execution: &ToolExecution) -> Bytes {
    let display_tool_call = display_tool_call(
        execution.display_field,
        &execution.display_args,
        None,
        Some(&execution.exec_id),
        Some(execution.started_at_ms),
        None,
    );
    let update = message(&[
        (1, execution.exec_id.as_bytes()),
        (2, &display_tool_call),
        (3, execution.model_call_id.as_bytes()),
    ]);
    let interaction = message(&[(2, &update)]);
    connect_envelope(0, &message(&[(1, &interaction)]))
}

fn tool_completed_frame(execution: &ToolExecution, result: &ToolResult) -> Bytes {
    let result_field = result.result_field;
    let raw_result = &result.raw_result;
    let converted_result;
    let display_result = if let Some(display_result) = &result.display_result {
        display_result.as_slice()
    } else if execution.display_field == 8 && matches!(result_field, 7 | 29) {
        converted_result = read_display_result(raw_result);
        converted_result.as_slice()
    } else if execution.display_field == 19 && result_field == 28 {
        converted_result = task_display_result(raw_result);
        converted_result.as_slice()
    } else if execution.display_field == 15 && result_field != 11 {
        converted_result = mcp_text_result(&result.output_text);
        converted_result.as_slice()
    } else {
        raw_result.as_slice()
    };
    let display_tool_call = display_tool_call(
        execution.display_field,
        &execution.display_args,
        Some(display_result),
        Some(&execution.exec_id),
        Some(execution.started_at_ms),
        Some(now_ms().min(u128::from(u64::MAX)) as u64),
    );
    let update = message(&[
        (1, execution.exec_id.as_bytes()),
        (2, &display_tool_call),
        (3, execution.model_call_id.as_bytes()),
    ]);
    let interaction = message(&[(3, &update)]);
    connect_envelope(0, &message(&[(1, &interaction)]))
}

async fn wait_for_exec_result(
    execution: &ToolExecution,
    client_rx: &mut mpsc::Receiver<ClientMessage>,
) -> Result<ToolResult> {
    let mut shell = (execution.exec_field == 14).then(ShellResultAccumulator::default);
    let result = tokio::time::timeout(std::time::Duration::from_secs(600), async {
        while let Some(message) = client_rx.recv().await {
            if let ClientMessage::Exec { id, exec_id, .. } = &message
                && (*id == execution.id || exec_id == &execution.exec_id)
            {
                if let Some(shell) = &mut shell {
                    if let Some(result) = shell.consume(&message, execution)? {
                        return Ok(result);
                    }
                } else {
                    return Ok(ToolResult::from_client(message));
                }
            }
        }
        bail!("Cursor closed the Agent execution stream")
    })
    .await
    .context("Cursor tool execution timed out")??;
    Ok(result)
}

struct ToolResult {
    result_field: u32,
    raw_result: Vec<u8>,
    output_text: String,
    display_result: Option<Vec<u8>>,
}

impl ToolResult {
    fn from_client(message: ClientMessage) -> Self {
        let output_text = exec_result_text(&message);
        let ClientMessage::Exec {
            result_field,
            result,
            ..
        } = message;
        Self {
            result_field,
            raw_result: result,
            output_text,
            display_result: None,
        }
    }
}

#[derive(Default)]
struct ShellResultAccumulator {
    stdout: String,
    stderr: String,
}

impl ShellResultAccumulator {
    fn consume(
        &mut self,
        message: &ClientMessage,
        execution: &ToolExecution,
    ) -> Result<Option<ToolResult>> {
        let ClientMessage::Exec {
            result_field,
            result,
            ..
        } = message;
        if *result_field != 14 {
            return Ok(None);
        }
        let event = WireMessage::parse(result)?;
        if let Some(chunk) = event.bytes(1).and_then(shell_stream_chunk) {
            self.stdout.push_str(chunk);
        }
        if let Some(chunk) = event.bytes(2).and_then(shell_stream_chunk) {
            self.stderr.push_str(chunk);
        }
        if let Some(raw_completion) = event.bytes(3) {
            let completion = WireMessage::parse(raw_completion)?;
            let exit_code = completion.varint(1).unwrap_or_default();
            let cwd = completion.string(2)?.unwrap_or_default();
            let message = completion.string(3)?.unwrap_or_default();
            let duration_ms = completion.varint(6).unwrap_or_default();
            let output_text = json!({
                "status": if exit_code == 0 {"success"} else {"failure"},
                "exit_code": exit_code,
                "stdout": self.stdout,
                "stderr": self.stderr,
                "message": message,
                "working_directory": cwd,
                "duration_ms": duration_ms,
            })
            .to_string();
            let display_result = shell_display_result(
                execution,
                &self.stdout,
                &self.stderr,
                cwd,
                exit_code,
                duration_ms,
            );
            return Ok(Some(ToolResult {
                result_field: 14,
                raw_result: result.clone(),
                output_text,
                display_result: Some(display_result),
            }));
        }
        if let Some(raw_background) = event.bytes(7) {
            let background = WireMessage::parse(raw_background)?;
            let pid = background.varint(1).unwrap_or_default();
            let command = background.string(2)?.unwrap_or_default();
            let cwd = background.string(3)?.unwrap_or_default();
            let output_text = json!({
                "status": "running",
                "pid": pid,
                "command": command,
                "working_directory": cwd,
                "stdout": self.stdout,
                "stderr": self.stderr,
            })
            .to_string();
            let display_result = shell_display_result(
                execution,
                &self.stdout,
                &self.stderr,
                cwd,
                0,
                background.varint(4).unwrap_or_default(),
            );
            return Ok(Some(ToolResult {
                result_field: 14,
                raw_result: result.clone(),
                output_text,
                display_result: Some(display_result),
            }));
        }
        Ok(None)
    }
}

fn shell_stream_chunk(raw: &[u8]) -> Option<&str> {
    WireMessage::parse(raw).ok()?.string(1).ok().flatten()
}

fn shell_display_result(
    execution: &ToolExecution,
    stdout: &str,
    stderr: &str,
    completion_cwd: &str,
    exit_code: u64,
    duration_ms: u64,
) -> Vec<u8> {
    let args = WireMessage::parse(&execution.args).ok();
    let command = args
        .as_ref()
        .and_then(|args| args.string(1).ok().flatten())
        .unwrap_or_default();
    let cwd = if completion_cwd.is_empty() {
        args.as_ref()
            .and_then(|args| args.string(2).ok().flatten())
            .unwrap_or_default()
    } else {
        completion_cwd
    };
    let mut detail = Vec::new();
    push_bytes_field(&mut detail, 1, command.as_bytes());
    if !cwd.is_empty() {
        push_bytes_field(&mut detail, 2, cwd.as_bytes());
    }
    if !stdout.is_empty() {
        push_bytes_field(&mut detail, 5, stdout.as_bytes());
        push_bytes_field(&mut detail, 10, stdout.as_bytes());
    }
    if !stderr.is_empty() {
        push_bytes_field(&mut detail, 6, stderr.as_bytes());
    }
    if duration_ms > 0 {
        push_varint_field(&mut detail, 13, duration_ms);
    }
    let mut result = Vec::new();
    push_bytes_field(&mut result, 1, &detail);
    push_varint_field(&mut result, 102, exit_code);
    result
}

fn mcp_text_result(text: &str) -> Vec<u8> {
    let text = message(&[(1, text.as_bytes())]);
    let content = message(&[(1, &text)]);
    let success = message(&[(1, &content)]);
    message(&[(1, &success)])
}

fn read_display_result(raw: &[u8]) -> Vec<u8> {
    let Ok(result) = WireMessage::parse(raw) else {
        return read_display_error("Cursor returned an unreadable read result");
    };
    let Some(success) = result.bytes(1) else {
        let message = generic_result_text(raw)
            .unwrap_or_else(|_| "Cursor could not read the requested file".to_string());
        return read_display_error(&message);
    };
    let Ok(success) = WireMessage::parse(success) else {
        return read_display_error("Cursor returned an unreadable read result");
    };

    let mut display = Vec::new();
    let mut has_output = false;
    if let Some(content) = success.bytes(2) {
        push_bytes_field(&mut display, 1, content);
        has_output = !content.is_empty();
    } else if let Some(data) = success.bytes(5) {
        push_bytes_field(&mut display, 6, data);
        has_output = !data.is_empty();
    }
    if !has_output {
        push_varint_field(&mut display, 2, 1);
    }
    if success.varint(6).unwrap_or_default() != 0 {
        push_varint_field(&mut display, 3, 1);
    }
    if let Some(total_lines) = success.varint(3) {
        push_varint_field(&mut display, 4, total_lines);
    }
    if let Some(file_size) = success.varint(4) {
        push_varint_field(&mut display, 5, file_size);
    }
    if let Some(path) = success.bytes(1) {
        push_bytes_field(&mut display, 7, path);
    }
    message(&[(1, &display)])
}

fn read_display_error(error: &str) -> Vec<u8> {
    let error = message(&[(1, error.as_bytes())]);
    message(&[(2, &error)])
}

fn task_display_result(raw: &[u8]) -> Vec<u8> {
    let Ok(result) = WireMessage::parse(raw) else {
        return task_display_error("Cursor returned an unreadable subagent result");
    };
    if let Some(raw_success) = result.bytes(1)
        && let Ok(success) = WireMessage::parse(raw_success)
    {
        let mut task_success = Vec::new();
        if let Some(final_message) = success
            .string(2)
            .ok()
            .flatten()
            .filter(|message| !message.is_empty())
        {
            let assistant_message = message(&[(1, final_message.as_bytes())]);
            let conversation_step = message(&[(1, &assistant_message)]);
            push_bytes_field(&mut task_success, 1, &conversation_step);
        }
        if let Some(agent_id) = success.string(1).ok().flatten() {
            push_bytes_field(&mut task_success, 2, agent_id.as_bytes());
        }
        if success.varint(4).unwrap_or_default() != 0 {
            push_varint_field(&mut task_success, 3, 1);
            push_varint_field(&mut task_success, 6, success.varint(4).unwrap_or_default());
        }
        if let Some(transcript_path) = success.string(5).ok().flatten() {
            push_bytes_field(&mut task_success, 7, transcript_path.as_bytes());
        }
        return message(&[(1, &task_success)]);
    }
    if let Some(raw_error) = result.bytes(2)
        && let Ok(error) = WireMessage::parse(raw_error)
    {
        return task_display_error(
            error
                .string(2)
                .ok()
                .flatten()
                .unwrap_or("Cursor subagent failed"),
        );
    }
    task_display_error("Cursor subagent returned no result")
}

fn task_display_error(error: &str) -> Vec<u8> {
    let task_error = message(&[(1, error.as_bytes())]);
    message(&[(2, &task_error)])
}

fn shell_args(arguments: &Value, call_id: &str) -> Result<Vec<u8>> {
    let command = required_string(arguments, "command")?;
    let executable = command
        .split_whitespace()
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("shell command must not be empty"))?;
    let mut args = Vec::new();
    push_bytes_field(&mut args, 1, command.as_bytes());
    if let Some(cwd) = optional_string(arguments, "working_directory") {
        push_bytes_field(&mut args, 2, cwd.as_bytes());
    }
    if let Some(timeout) = arguments.get("timeout").and_then(Value::as_u64) {
        push_varint_field(&mut args, 3, timeout.min(u64::from(u32::MAX)));
    }
    push_bytes_field(&mut args, 4, call_id.as_bytes());
    push_bytes_field(&mut args, 5, executable.as_bytes());
    let executable_command = message(&[(1, executable.as_bytes()), (3, command.as_bytes())]);
    let parsing_result = message(&[(2, &executable_command)]);
    push_bytes_field(&mut args, 8, &parsing_result);
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

fn subagent_args(
    arguments: &Value,
    call_id: &str,
    parent_conversation_id: Option<&str>,
    default_model: Option<&str>,
) -> Result<Vec<u8>> {
    let mut args = Vec::new();
    push_bytes_field(&mut args, 1, call_id.as_bytes());
    push_bytes_field(
        &mut args,
        2,
        required_string(arguments, "subagent_type")?.as_bytes(),
    );
    // The model that produced the Task call may suggest generic aliases such as
    // "fast". Cursor subagents spawned by OpenSub must inherit the model and
    // reasoning mode selected for their parent request.
    if let Some(model) = default_model.or_else(|| optional_string(arguments, "model")) {
        push_bytes_field(&mut args, 3, model.as_bytes());
    }
    push_bytes_field(
        &mut args,
        4,
        required_string(arguments, "prompt")?.as_bytes(),
    );
    if arguments
        .get("readonly")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        push_varint_field(&mut args, 5, 1);
    }
    if let Some(resume) = optional_string(arguments, "resume") {
        push_bytes_field(&mut args, 6, resume.as_bytes());
    }
    if arguments
        .get("run_in_background")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        push_varint_field(&mut args, 7, 1);
    }
    if let Some(parent) = parent_conversation_id {
        push_bytes_field(&mut args, 9, parent.as_bytes());
        push_bytes_field(&mut args, 16, parent.as_bytes());
    }
    Ok(args)
}

fn task_display_args(arguments: &Value, default_model: Option<&str>) -> Result<Vec<u8>> {
    let mut args = Vec::new();
    push_bytes_field(
        &mut args,
        1,
        required_string(arguments, "description")?.as_bytes(),
    );
    push_bytes_field(
        &mut args,
        2,
        required_string(arguments, "prompt")?.as_bytes(),
    );
    let subagent_type = subagent_type_message(required_string(arguments, "subagent_type")?);
    push_bytes_field(&mut args, 3, &subagent_type);
    if let Some(model) = default_model.or_else(|| optional_string(arguments, "model")) {
        push_bytes_field(&mut args, 4, model.as_bytes());
    }
    if let Some(resume) = optional_string(arguments, "resume") {
        push_bytes_field(&mut args, 5, resume.as_bytes());
    }
    Ok(args)
}

fn subagent_type_message(name: &str) -> Vec<u8> {
    let normalized = name
        .chars()
        .filter(|character| !matches!(character, '_' | '-'))
        .flat_map(char::to_lowercase)
        .collect::<String>();
    let field = match normalized.as_str() {
        "computeruse" => Some(2),
        "explore" => Some(4),
        "mediareview" | "videoreview" => Some(5),
        "bash" => Some(6),
        "browseruse" => Some(7),
        "shell" => Some(8),
        "vmsetuphelper" => Some(9),
        "debug" => Some(10),
        "cursorguide" => Some(11),
        "watchvideo" => Some(12),
        _ => None,
    };
    if let Some(field) = field {
        message(&[(field, &[])])
    } else {
        let custom = message(&[(1, name.as_bytes())]);
        message(&[(3, &custom)])
    }
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
    push_bytes_field(&mut args, 9, tool.server_id.as_bytes());
    Ok(args)
}

fn generic_display_args(name: &str, arguments: &Value, call_id: &str) -> Result<Vec<u8>> {
    let tool = McpTool {
        name: name.to_string(),
        provider: "opensub".to_string(),
        server_id: "opensub".to_string(),
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
        28 => subagent_result_text(result),
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

fn subagent_result_text(raw: &[u8]) -> Result<String> {
    let result = WireMessage::parse(raw)?;
    if let Some(success) = result.bytes(1) {
        let success = WireMessage::parse(success)?;
        return Ok(json!({
            "status": "success",
            "agent_id": success.string(1)?.unwrap_or_default(),
            "final_message": success.string(2)?.unwrap_or_default(),
            "tool_call_count": success.varint(3).unwrap_or_default(),
            "transcript_path": success.string(5)?.unwrap_or_default(),
        })
        .to_string());
    }
    if let Some(error) = result.bytes(2) {
        let error = WireMessage::parse(error)?;
        return Ok(json!({
            "status": "error",
            "agent_id": error.string(1)?.unwrap_or_default(),
            "error": error.string(2)?.unwrap_or("Cursor subagent failed"),
        })
        .to_string());
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
    root_prompt_messages_json: Vec<String>,
    history: Vec<Value>,
    conversation_summary: Option<String>,
    conversation_id: Option<String>,
    custom_system_prompt: Option<String>,
    cursor_context_instructions: Vec<String>,
    transcript_path: Option<PathBuf>,
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
        let prefetched_blobs = run
            .all_bytes(17)
            .filter_map(|raw| WireMessage::parse(raw).ok())
            .filter_map(|blob| Some((blob.bytes(1)?.to_vec(), blob.bytes(2)?.to_vec())))
            .collect::<HashMap<_, _>>();
        let root_prompt_messages_json = conversation_state
            .all_bytes(1)
            .filter_map(|id| prefetched_blobs.get(id))
            .filter_map(|value| decode_blob_text(value))
            .collect();
        let mut history = Vec::new();
        for turn_id in conversation_state.all_bytes(8) {
            let Some(turn) = prefetched_blobs.get(turn_id) else {
                continue;
            };
            if let Err(error) =
                parse_conversation_turn_structure(turn, &prefetched_blobs, &mut history)
            {
                tracing::debug!(error = %error, "ignored unsupported Cursor history turn");
            }
        }
        let conversation_summary = conversation_state
            .bytes(6)
            .and_then(|id| prefetched_blobs.get(id))
            .and_then(|value| parse_conversation_summary(value));
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
        let prompt = user_message_text(&user_message, &prefetched_blobs)?.unwrap_or_default();
        let user_context = user_action
            .bytes(2)
            .map(WireMessage::parse)
            .transpose()?
            .unwrap_or(WireMessage { fields: Vec::new() });
        let mcp_server_ids = cursor_mcp_server_ids(&user_context);
        let mut mcp_tools = user_context
            .all_bytes(7)
            .filter_map(|raw| McpTool::parse(raw).transpose())
            .collect::<Result<Vec<_>>>()?;
        for tool in &mut mcp_tools {
            tool.server_id = mcp_server_ids
                .get(&tool.provider)
                .cloned()
                .unwrap_or_else(|| tool.provider.clone());
        }
        let conversation_id = run.string(5)?.map(str::to_string);
        let parent_conversation_id = run.string(16)?.map(str::to_string);
        let transcript_path = conversation_id.as_deref().and_then(|conversation_id| {
            cursor_transcript_path(
                &user_context,
                conversation_id,
                parent_conversation_id.as_deref(),
            )
        });

        Ok(Self {
            requested_model,
            reasoning_effort,
            prompt,
            mcp_tools,
            root_prompt_messages_json,
            history,
            conversation_summary,
            conversation_id,
            custom_system_prompt: run.string(8)?.map(str::to_string),
            cursor_context_instructions: cursor_context_instructions(
                &user_context,
                &conversation_state,
            ),
            transcript_path,
        })
    }
}

fn cursor_mcp_server_ids(context: &WireMessage<'_>) -> HashMap<String, String> {
    context
        .bytes(34)
        .and_then(|raw| WireMessage::parse(raw).ok())
        .into_iter()
        .flat_map(|catalog| {
            catalog
                .all_bytes(2)
                .filter_map(|raw| WireMessage::parse(raw).ok())
                .filter_map(|server| {
                    Some((
                        server.string(1).ok().flatten()?.to_string(),
                        server.string(2).ok().flatten()?.to_string(),
                    ))
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn cursor_context_instructions(
    context: &WireMessage<'_>,
    conversation_state: &WireMessage<'_>,
) -> Vec<String> {
    let mut instructions = Vec::new();
    let mut bytes = 0usize;

    if let Some(environment) = context
        .bytes(4)
        .and_then(|raw| WireMessage::parse(raw).ok())
    {
        let workspace = environment.string(2).ok().flatten().unwrap_or_default();
        let shell = environment.string(3).ok().flatten().unwrap_or_default();
        let timezone = environment.string(10).ok().flatten().unwrap_or_default();
        append_capped_instruction(
            &mut instructions,
            &mut bytes,
            format!(
                "Cursor environment:\nWorkspace: {workspace}\nShell: {shell}\nTimezone: {timezone}"
            ),
        );
    }
    if let Some(repository) = context
        .bytes(11)
        .and_then(|raw| WireMessage::parse(raw).ok())
    {
        let root = repository.string(1).ok().flatten().unwrap_or_default();
        let branch = repository.string(3).ok().flatten().unwrap_or_default();
        append_capped_instruction(
            &mut instructions,
            &mut bytes,
            format!("Cursor repository:\nRoot: {root}\nBranch: {branch}"),
        );
    } else if let Some(workspace_uri) = conversation_state.string(9).ok().flatten() {
        append_capped_instruction(
            &mut instructions,
            &mut bytes,
            format!("Cursor workspace: {workspace_uri}"),
        );
    }

    let rules = context
        .all_bytes(2)
        .filter_map(|raw| WireMessage::parse(raw).ok())
        .filter_map(|rule| {
            let content = rule.string(2).ok().flatten()?.trim();
            if content.is_empty() {
                return None;
            }
            let path = rule.string(1).ok().flatten().unwrap_or("workspace rule");
            Some(format!("Rule: {path}\n{content}"))
        })
        .collect::<Vec<_>>();
    if !rules.is_empty() {
        append_capped_instruction(
            &mut instructions,
            &mut bytes,
            format!("Cursor rules:\n\n{}", rules.join("\n\n")),
        );
    }

    let skills = context
        .all_bytes(29)
        .filter_map(|raw| WireMessage::parse(raw).ok())
        .filter_map(|skill| {
            let path = skill.string(1).ok().flatten()?;
            let description = skill.string(3).ok().flatten().unwrap_or_default();
            Some(format!("- {path}: {description}"))
        })
        .collect::<Vec<_>>();
    if !skills.is_empty() {
        append_capped_instruction(
            &mut instructions,
            &mut bytes,
            format!("Available Cursor skills:\n{}", skills.join("\n")),
        );
    }

    let subagents = context
        .all_bytes(22)
        .filter_map(|raw| WireMessage::parse(raw).ok())
        .filter_map(|agent| {
            let name = agent.string(2).ok().flatten()?;
            let description = agent.string(3).ok().flatten().unwrap_or_default();
            Some(format!("- {name}: {description}"))
        })
        .collect::<Vec<_>>();
    if !subagents.is_empty() {
        append_capped_instruction(
            &mut instructions,
            &mut bytes,
            format!("Available Cursor subagents:\n{}", subagents.join("\n")),
        );
    }

    instructions
}

fn append_capped_instruction(output: &mut Vec<String>, total_bytes: &mut usize, mut value: String) {
    if *total_bytes >= MAX_CURSOR_INSTRUCTIONS_BYTES || value.trim().is_empty() {
        return;
    }
    let remaining = MAX_CURSOR_INSTRUCTIONS_BYTES - *total_bytes;
    if value.len() > remaining {
        let mut boundary = remaining;
        while !value.is_char_boundary(boundary) {
            boundary = boundary.saturating_sub(1);
        }
        value.truncate(boundary);
    }
    *total_bytes = total_bytes.saturating_add(value.len());
    output.push(value);
}

fn cursor_transcript_path(
    context: &WireMessage<'_>,
    conversation_id: &str,
    parent_conversation_id: Option<&str>,
) -> Option<PathBuf> {
    if !safe_cursor_id(conversation_id)
        || parent_conversation_id.is_some_and(|id| !safe_cursor_id(id))
    {
        return None;
    }
    let environment = context
        .bytes(4)
        .and_then(|raw| WireMessage::parse(raw).ok())?;
    let transcript_root = PathBuf::from(environment.string(12).ok().flatten()?);
    let trusted_root = PathBuf::from(std::env::var_os("HOME")?)
        .join(".cursor")
        .join("projects")
        .canonicalize()
        .ok()?;
    let root = transcript_root.canonicalize().ok()?;
    if !root.starts_with(&trusted_root) {
        return None;
    }

    let candidate = if let Some(parent) = parent_conversation_id {
        root.join(parent)
            .join("subagents")
            .join(format!("{conversation_id}.jsonl"))
    } else {
        root.join(conversation_id)
            .join(format!("{conversation_id}.jsonl"))
    };
    let canonical = candidate.canonicalize().ok()?;
    canonical.starts_with(&root).then_some(canonical)
}

fn safe_cursor_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn parse_conversation_turn_structure(
    raw: &[u8],
    prefetched_blobs: &HashMap<Vec<u8>, Vec<u8>>,
    output: &mut Vec<Value>,
) -> Result<()> {
    let decoded = decode_blob_bytes(raw).context("invalid compressed conversation turn")?;
    let turn = WireMessage::parse(&decoded)?;
    if let Some(raw_agent_turn) = turn.bytes(1) {
        let agent_turn = WireMessage::parse(raw_agent_turn)?;
        if let Some(user_message_id) = agent_turn.bytes(1)
            && let Some(raw_user_message) = prefetched_blobs.get(user_message_id)
            && let Some(decoded) = decode_blob_bytes(raw_user_message)
            && let Ok(user_message) = WireMessage::parse(&decoded)
            && let Some(text) = user_message_text(&user_message, prefetched_blobs)?
        {
            output.push(history_message("user", text));
        }
        for step_id in agent_turn.all_bytes(2) {
            let Some(raw_step) = prefetched_blobs.get(step_id) else {
                continue;
            };
            let Some(decoded) = decode_blob_bytes(raw_step) else {
                continue;
            };
            let Ok(step) = WireMessage::parse(&decoded) else {
                continue;
            };
            if let Some(raw_assistant_message) = step.bytes(1)
                && let Ok(assistant_message) = WireMessage::parse(raw_assistant_message)
                && let Some(text) = assistant_message
                    .string(1)?
                    .filter(|text| !text.trim().is_empty())
            {
                output.push(history_message("assistant", text.to_string()));
            }
        }
    } else if let Some(raw_shell_turn) = turn.bytes(2) {
        let shell_turn = WireMessage::parse(raw_shell_turn)?;
        if let Some(command_id) = shell_turn.bytes(1)
            && let Some(raw_command) = prefetched_blobs.get(command_id)
            && let Some(decoded) = decode_blob_bytes(raw_command)
            && let Ok(command) = WireMessage::parse(&decoded)
            && let Some(text) = command.string(1)?.filter(|text| !text.trim().is_empty())
        {
            output.push(history_message(
                "user",
                format!("Shell command executed: {text}"),
            ));
        }
        if let Some(result_id) = shell_turn.bytes(2)
            && let Some(raw_result) = prefetched_blobs.get(result_id)
            && let Some(decoded) = decode_blob_bytes(raw_result)
            && let Ok(result) = WireMessage::parse(&decoded)
        {
            let stdout = result.string(1)?.unwrap_or_default();
            let stderr = result.string(2)?.unwrap_or_default();
            let text = match (stdout.is_empty(), stderr.is_empty()) {
                (false, false) => format!("stdout:\n{stdout}\nstderr:\n{stderr}"),
                (false, true) => stdout.to_string(),
                (true, false) => stderr.to_string(),
                (true, true) => String::new(),
            };
            if !text.is_empty() {
                output.push(history_message("assistant", text));
            }
        }
    }
    Ok(())
}

fn parse_conversation_summary(raw: &[u8]) -> Option<String> {
    let decoded = decode_blob_bytes(raw)?;
    let summary = WireMessage::parse(&decoded).ok()?;
    summary
        .string(1)
        .ok()
        .flatten()
        .filter(|text| !text.trim().is_empty())
        .map(str::to_string)
}

fn user_message_text(
    message: &WireMessage<'_>,
    prefetched_blobs: &HashMap<Vec<u8>, Vec<u8>>,
) -> Result<Option<String>> {
    let inline_text = message.string(1)?.unwrap_or_default();
    let text = if !inline_text.trim().is_empty() {
        Some(inline_text.to_string())
    } else {
        message
            .bytes(18)
            .and_then(|id| prefetched_blobs.get(id))
            .and_then(|value| decode_blob_text(value))
    };
    Ok(text.filter(|text| !text.trim().is_empty()))
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
        let reasoning = requested
            .all_bytes(3)
            .find_map(|raw| {
                let parameter = WireMessage::parse(raw).ok()?;
                matches!(
                    parameter.string(1).ok().flatten(),
                    Some("reasoning" | "effort" | "reasoning_effort")
                )
                .then(|| parameter.string(2).ok().flatten().map(str::to_string))
                .flatten()
            })
            .or_else(|| reasoning_from_model_suffix(&model));
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
    server_id: String,
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
            server_id: tool.string(4)?.unwrap_or_default().to_string(),
            tool_name: tool.string(5)?.unwrap_or_default().to_string(),
            description: tool.string(2)?.map(str::to_string),
            parameters,
        }))
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

fn reasoning_from_model_suffix(model: &str) -> Option<String> {
    let effort = model.rsplit('-').next()?.to_ascii_lowercase();
    matches!(
        effort.as_str(),
        "none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max"
    )
    .then_some(effort)
}

fn model_with_reasoning_variant(model: &str, reasoning: Option<&str>) -> String {
    let Some(reasoning) = reasoning
        .map(str::trim)
        .filter(|reasoning| !reasoning.is_empty())
    else {
        return model.to_string();
    };
    if reasoning_from_model_suffix(model).as_deref() == Some(reasoning) {
        model.to_string()
    } else {
        format!("{model}-{reasoning}")
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
    fn protocol_trace_is_private_and_correlates_records() {
        let directory = std::env::temp_dir().join(format!(
            "opensub-trace-test-{}-{}.jsonl",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path = directory.join("trace.jsonl");
        let trace = ProtocolTrace::new(path.clone()).unwrap();
        trace.record_json(7, "opensub", "metadata", json!({"model": "gpt-test"}));
        trace.record_bytes(7, "cursor_to_cursor_cloud", "request_body_chunk", b"frame");
        drop(trace);

        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let records = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["sequence"], 1);
        assert_eq!(records[1]["sequence"], 2);
        assert_eq!(records[0]["request_id"], 7);
        assert_eq!(records[1]["data"], "ZnJhbWU=");

        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

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
    fn agent_request_preserves_cursor_conversation_history() {
        let root_id = b"root-prompt";
        let user_id = b"prior-user";
        let step_id = b"prior-step";
        let turn_id = b"prior-turn";
        let summary_id = b"summary";
        let prior_user = message(&[(1, b"Remember the token ivory-731"), (2, b"message-1")]);
        let prior_assistant = message(&[(1, b"I will remember ivory-731.")]);
        let prior_step = message(&[(1, &prior_assistant)]);
        let agent_turn = message(&[(1, user_id), (2, step_id)]);
        let turn = message(&[(1, &agent_turn)]);
        let summary = message(&[(1, b"The user is testing conversation continuity.")]);
        let state = message(&[(1, root_id), (6, summary_id), (8, turn_id)]);
        let root = message(&[
            (1, root_id),
            (
                2,
                br#"{"role":"system","content":[{"type":"text","text":"Follow workspace rules."}]}"#,
            ),
        ]);
        let user = message(&[(1, user_id), (2, &prior_user)]);
        let step = message(&[(1, step_id), (2, &prior_step)]);
        let turn = message(&[(1, turn_id), (2, &turn)]);
        let summary = message(&[(1, summary_id), (2, &summary)]);
        let current_user = message(&[(1, b"What token did I ask you to remember?")]);
        let user_action = message(&[(1, &current_user)]);
        let action = message(&[(1, &user_action)]);
        let requested_model = message(&[(1, b"gpt-5.5")]);
        let run_request = message(&[
            (1, &state),
            (2, &action),
            (5, b"conversation-123"),
            (9, &requested_model),
            (17, &root),
            (17, &user),
            (17, &step),
            (17, &turn),
            (17, &summary),
        ]);
        let run = WireMessage::parse(&run_request).unwrap();

        let agent = AgentRequest::parse(&run, "gpt-5.5".to_string(), None).unwrap();
        let material = load_conversation_material(&agent);

        assert_eq!(agent.prompt, "What token did I ask you to remember?");
        assert_eq!(agent.conversation_id.as_deref(), Some("conversation-123"));
        assert_eq!(material.input.len(), 2);
        assert_eq!(material.input[0]["role"], "user");
        assert_eq!(
            material.input[0]["content"][0]["text"],
            "Remember the token ivory-731"
        );
        assert_eq!(material.input[1]["role"], "assistant");
        assert_eq!(
            material.input[1]["content"][0]["text"],
            "I will remember ivory-731."
        );
        assert!(material.instructions.contains("Follow workspace rules."));
        assert!(material.instructions.contains("conversation continuity"));
    }

    #[test]
    fn agent_request_resolves_blob_backed_user_history() {
        let text_id = b"history-text";
        let user_id = b"history-user";
        let turn_id = b"history-turn";
        let prior_user = message(&[(18, text_id)]);
        let agent_turn = message(&[(1, user_id)]);
        let turn = message(&[(1, &agent_turn)]);
        let state = message(&[(8, turn_id)]);
        let prefetched_text = message(&[(1, text_id), (2, b"Blob-backed prior prompt")]);
        let prefetched_user = message(&[(1, user_id), (2, &prior_user)]);
        let prefetched_turn = message(&[(1, turn_id), (2, &turn)]);
        let current_user = message(&[(1, b"Continue")]);
        let user_action = message(&[(1, &current_user)]);
        let action = message(&[(1, &user_action)]);
        let requested_model = message(&[(1, b"gpt-5.5")]);
        let run_request = message(&[
            (1, &state),
            (2, &action),
            (9, &requested_model),
            (17, &prefetched_text),
            (17, &prefetched_user),
            (17, &prefetched_turn),
        ]);
        let run = WireMessage::parse(&run_request).unwrap();

        let agent = AgentRequest::parse(&run, "gpt-5.5".to_string(), None).unwrap();

        assert_eq!(agent.history.len(), 1);
        assert_eq!(
            agent.history[0]["content"][0]["text"],
            "Blob-backed prior prompt"
        );
    }

    #[test]
    fn conversation_cache_replays_completed_turns() {
        let cache = ConversationCache::default();
        cache.commit(
            "conversation-1".to_string(),
            vec![
                history_message("user", "Remember ivory-731".to_string()),
                history_message("assistant", "Remembered.".to_string()),
            ],
        );

        let snapshot = cache.snapshot("conversation-1");

        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0]["content"][0]["text"], "Remember ivory-731");
        assert_eq!(snapshot[1]["content"][0]["text"], "Remembered.");
        assert!(cache.snapshot("another-conversation").is_empty());
    }

    #[test]
    fn preserves_supported_reasoning_effort_for_gpt_5_5() {
        assert_eq!(map_reasoning_effort("none", "gpt-5.5"), Some("none"));
        assert_eq!(map_reasoning_effort("minimal", "gpt-5.5"), Some("low"));
        assert_eq!(map_reasoning_effort("xhigh", "gpt-5.5"), Some("xhigh"));
        assert_eq!(
            model_with_reasoning_variant("gpt-5.5", Some("xhigh")),
            "gpt-5.5-xhigh"
        );
        assert_eq!(
            reasoning_from_model_suffix("gpt-5.6-sol-xhigh").as_deref(),
            Some("xhigh")
        );
    }

    #[test]
    fn preserves_cursor_5_6_models_for_the_codex_backend() {
        assert_eq!(map_cursor_model("gpt-5.6-sol"), "gpt-5.6-sol");
        assert_eq!(map_cursor_model("gpt-5.6-sol-xhigh"), "gpt-5.6-sol");
        assert_eq!(map_cursor_model("gpt-5.6-terra"), "gpt-5.6-terra");
        assert_eq!(map_cursor_model("gpt-5.6-luna"), "gpt-5.6-luna");
    }

    #[test]
    fn extracts_responses_generation_error_details() {
        let event = json!({
            "type": "response.failed",
            "response": {
                "error": {
                    "code": "invalid_prompt",
                    "type": "invalid_request_error",
                    "message": "The request could not be processed."
                }
            }
        });

        assert_eq!(
            responses_error(&event),
            "invalid_prompt: invalid_request_error: The request could not be processed."
        );
    }

    #[test]
    fn parses_cursor_effort_parameter_for_model_variants() {
        let effort = message(&[(1, b"effort"), (2, b"xhigh")]);
        let requested_model = message(&[(1, b"gpt-5.6-sol"), (3, &effort)]);
        let run_request = message(&[(9, &requested_model)]);
        let run = WireMessage::parse(&run_request).unwrap();

        let (model, reasoning) = parse_requested_model(&run).unwrap();

        assert_eq!(model, "gpt-5.6-sol");
        assert_eq!(reasoning.as_deref(), Some("xhigh"));
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
    fn exec_parser_preserves_shell_stream_events_and_ignores_metadata() {
        let mut exec = Vec::new();
        push_varint_field(&mut exec, 1, 7);
        push_bytes_field(&mut exec, 15, b"call-7");
        let shell_event = message(&[(1, &message(&[(1, b"partial stdout")]))]);
        push_bytes_field(&mut exec, 14, &shell_event);
        push_bytes_field(&mut exec, 45, &message(&[(1, b"hook context")]));
        let client = message(&[(2, &exec)]);
        let parsed = parse_exec_client_message(&client).unwrap().unwrap();
        let ClientMessage::Exec {
            result_field,
            result,
            ..
        } = parsed;
        assert_eq!(result_field, 14);
        assert_eq!(result, shell_event);

        let metadata = message(&[(2, &message(&[(45, &message(&[(1, b"hook context")]))]))]);
        assert!(parse_exec_client_message(&metadata).unwrap().is_none());

        let final_result = message(&[(1, &message(&[(5, b"done")]))]);
        let mut exec = Vec::new();
        push_varint_field(&mut exec, 1, 7);
        push_bytes_field(&mut exec, 15, b"call-7");
        push_bytes_field(&mut exec, 2, &final_result);
        let client = message(&[(2, &exec)]);
        let parsed = parse_exec_client_message(&client).unwrap().unwrap();
        let ClientMessage::Exec {
            id,
            exec_id,
            result_field,
            result,
        } = parsed;
        assert_eq!(id, 7);
        assert_eq!(exec_id, "call-7");
        assert_eq!(result_field, 2);
        assert_eq!(result, final_result);
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
    fn shell_execution_includes_cursor_parsing_result() {
        let args = shell_args(&json!({"command": "pwd; ls -la"}), "call-shell").unwrap();
        let args = WireMessage::parse(&args).unwrap();
        assert_eq!(args.string(1).unwrap(), Some("pwd; ls -la"));
        assert_eq!(args.string(4).unwrap(), Some("call-shell"));
        assert_eq!(args.string(5).unwrap(), Some("pwd;"));

        let parsing = WireMessage::parse(args.bytes(8).unwrap()).unwrap();
        let executable = WireMessage::parse(parsing.bytes(2).unwrap()).unwrap();
        assert_eq!(executable.string(1).unwrap(), Some("pwd;"));
        assert_eq!(executable.string(3).unwrap(), Some("pwd; ls -la"));
    }

    #[test]
    fn shell_execution_uses_current_cursor_field_and_waits_for_completion() {
        let call = ToolCall {
            item_id: "item-shell".to_string(),
            call_id: "call-shell".to_string(),
            name: "Shell".to_string(),
            arguments: json!({"command": "printf ok", "working_directory": "/tmp"}).to_string(),
        };
        let execution = ToolExecution::from_call(&call, &HashMap::new(), 6, None, None).unwrap();
        assert_eq!(execution.exec_field, 14);

        let mut accumulator = ShellResultAccumulator::default();
        let started = ClientMessage::Exec {
            id: 6,
            exec_id: String::new(),
            result_field: 14,
            result: message(&[(4, &message(&[(1, &message(&[(1, &[])]))]))]),
        };
        assert!(accumulator.consume(&started, &execution).unwrap().is_none());

        let output = ClientMessage::Exec {
            id: 6,
            exec_id: String::new(),
            result_field: 14,
            result: message(&[(1, &message(&[(1, b"ok")]))]),
        };
        assert!(accumulator.consume(&output, &execution).unwrap().is_none());

        let mut completion = Vec::new();
        push_bytes_field(&mut completion, 2, b"/tmp");
        push_varint_field(&mut completion, 6, 12);
        let completed = ClientMessage::Exec {
            id: 6,
            exec_id: String::new(),
            result_field: 14,
            result: message(&[(3, &completion)]),
        };
        let result = accumulator
            .consume(&completed, &execution)
            .unwrap()
            .unwrap();
        assert!(result.output_text.contains("\"stdout\":\"ok\""));
        assert!(result.output_text.contains("\"status\":\"success\""));

        let frame = tool_completed_frame(&execution, &result);
        let frame = first_connect_frame(&frame).unwrap().unwrap();
        let server = WireMessage::parse(frame.payload).unwrap();
        let interaction = WireMessage::parse(server.bytes(1).unwrap()).unwrap();
        let update = WireMessage::parse(interaction.bytes(3).unwrap()).unwrap();
        let display = WireMessage::parse(update.bytes(2).unwrap()).unwrap();
        assert_eq!(display.string(57).unwrap(), Some("call-shell"));
        assert!(display.varint(59).is_some());
        assert!(display.varint(60).is_some());
        let shell_call = WireMessage::parse(display.bytes(1).unwrap()).unwrap();
        let shell_result = WireMessage::parse(shell_call.bytes(2).unwrap()).unwrap();
        assert_eq!(shell_result.varint(102), Some(0));
    }

    #[test]
    fn transcript_history_restores_prior_text_without_current_prompt() {
        let transcript = [
            json!({"role":"user","message":{"content":[{"type":"text","text":"first request"}]}}),
            json!({"role":"assistant","message":{"content":[
                {"type":"text","text":"first answer"},
                {"type":"tool_use","name":"ReadFile","input":{"path":"README.md"}}
            ]}}),
            json!({"role":"user","message":{"content":[{"type":"text","text":"<user_query>\ncurrent request\n</user_query>"}]}}),
        ]
        .into_iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("\n");

        let history = parse_transcript_history(&transcript, "current request");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].get("role").and_then(Value::as_str), Some("user"));
        assert_eq!(
            history[1].get("role").and_then(Value::as_str),
            Some("assistant")
        );
        assert_eq!(
            history[1]
                .pointer("/content/0/text")
                .and_then(Value::as_str),
            Some("first answer")
        );
    }

    #[test]
    fn cursor_context_preserves_workspace_rules_skills_and_subagents() {
        let environment = message(&[(2, b"/workspace"), (3, b"zsh"), (10, b"America/Sao_Paulo")]);
        let repository = message(&[(1, b"/workspace"), (3, b"dev")]);
        let rule = message(&[(1, b"/workspace/AGENTS.md"), (2, b"Run focused tests.")]);
        let skill = message(&[
            (1, b"/workspace/.agents/skills/review/SKILL.md"),
            (3, b"Review the finished diff."),
        ]);
        let subagent = message(&[(2, b"reviewer"), (3, b"Perform an independent review.")]);
        let mcp_server = message(&[(1, b"linear"), (2, b"plugin-linear-linear")]);
        let mcp_catalog = message(&[(2, &mcp_server)]);
        let context = message(&[
            (4, &environment),
            (11, &repository),
            (2, &rule),
            (29, &skill),
            (22, &subagent),
            (34, &mcp_catalog),
        ]);
        let context = WireMessage::parse(&context).unwrap();
        let instructions =
            cursor_context_instructions(&context, &WireMessage { fields: Vec::new() }).join("\n");

        assert!(instructions.contains("Workspace: /workspace"));
        assert!(instructions.contains("Branch: dev"));
        assert!(instructions.contains("Run focused tests."));
        assert!(instructions.contains("Review the finished diff."));
        assert!(instructions.contains("reviewer: Perform an independent review."));
        assert_eq!(
            cursor_mcp_server_ids(&context)
                .get("linear")
                .map(String::as_str),
            Some("plugin-linear-linear")
        );
    }

    #[test]
    fn mcp_tools_are_discovered_then_relayed_through_cursor() {
        let tools = vec![McpTool {
            name: "plugin-linear-linear-get_issue".to_string(),
            provider: "linear".to_string(),
            server_id: "plugin-linear-linear".to_string(),
            tool_name: "get_issue".to_string(),
            description: Some("Read a Linear issue.".to_string()),
            parameters: json!({
                "type":"object",
                "properties":{"id":{"type":"string"}},
                "required":["id"]
            }),
        }];
        let discovery = discover_mcp_tools(
            r#"{"server":"plugin-linear-linear","toolName":"get_issue"}"#,
            &tools,
        )
        .unwrap();
        let discovery: Value = serde_json::from_str(&discovery).unwrap();
        assert_eq!(
            discovery.pointer("/0/toolName").and_then(Value::as_str),
            Some("get_issue")
        );
        assert_eq!(
            discovery
                .pointer("/0/inputSchema/required/0")
                .and_then(Value::as_str),
            Some("id")
        );

        let by_name = tools
            .iter()
            .map(|tool| (tool.name.clone(), tool))
            .collect::<HashMap<_, _>>();
        let call = ToolCall {
            item_id: "item-mcp".to_string(),
            call_id: "call-mcp".to_string(),
            name: "CallMcpTool".to_string(),
            arguments: json!({
                "server":"plugin-linear-linear",
                "toolName":"get_issue",
                "arguments":{"id":"RKIT-317"}
            })
            .to_string(),
        };
        let execution = ToolExecution::from_call(&call, &by_name, 8, None, None).unwrap();
        assert_eq!(execution.exec_field, 11);
        let args = WireMessage::parse(&execution.args).unwrap();
        assert_eq!(
            args.string(1).unwrap(),
            Some("plugin-linear-linear-get_issue")
        );
        assert_eq!(args.string(4).unwrap(), Some("linear"));
        assert_eq!(args.string(5).unwrap(), Some("get_issue"));
        assert_eq!(args.string(9).unwrap(), Some("plugin-linear-linear"));
    }

    #[test]
    fn task_execution_is_relayed_to_cursor_subagent_harness() {
        let call = ToolCall {
            item_id: "item-task".to_string(),
            call_id: "call-task".to_string(),
            name: "task".to_string(),
            arguments: json!({
                "description": "Inspect tests",
                "prompt": "Run focused tests and report failures.",
                "subagent_type": "explore",
                "readonly": true
            })
            .to_string(),
        };
        let execution = ToolExecution::from_call(
            &call,
            &HashMap::new(),
            9,
            Some("conversation-parent"),
            Some("gpt-5.6-sol-xhigh"),
        )
        .unwrap();

        assert_eq!(execution.exec_field, 28);
        assert_eq!(execution.display_field, 19);
        let args = WireMessage::parse(&execution.args).unwrap();
        assert_eq!(args.string(1).unwrap(), Some("call-task"));
        assert_eq!(args.string(2).unwrap(), Some("explore"));
        assert_eq!(args.string(3).unwrap(), Some("gpt-5.6-sol-xhigh"));
        assert_eq!(
            args.string(4).unwrap(),
            Some("Run focused tests and report failures.")
        );
        assert_eq!(args.varint(5), Some(1));
        assert_eq!(args.string(9).unwrap(), Some("conversation-parent"));

        let frame = exec_server_frame(&execution);
        let frame = first_connect_frame(&frame).unwrap().unwrap();
        let server = WireMessage::parse(frame.payload).unwrap();
        let exec = WireMessage::parse(server.bytes(2).unwrap()).unwrap();
        assert_eq!(exec.varint(1), Some(9));
        assert!(exec.bytes(28).is_some());

        let started = tool_started_frame(&execution);
        let started = first_connect_frame(&started).unwrap().unwrap();
        let server = WireMessage::parse(started.payload).unwrap();
        let interaction = WireMessage::parse(server.bytes(1).unwrap()).unwrap();
        let update = WireMessage::parse(interaction.bytes(2).unwrap()).unwrap();
        let tool_call = WireMessage::parse(update.bytes(2).unwrap()).unwrap();
        let task_call = WireMessage::parse(tool_call.bytes(19).unwrap()).unwrap();
        let display_args = WireMessage::parse(task_call.bytes(1).unwrap()).unwrap();
        let subagent_type = WireMessage::parse(display_args.bytes(3).unwrap()).unwrap();
        assert!(subagent_type.bytes(4).is_some());
        assert_eq!(display_args.string(4).unwrap(), Some("gpt-5.6-sol-xhigh"));
    }

    #[test]
    fn cursor_subagent_result_completes_task_tool_call() {
        let call = ToolCall {
            item_id: "item-task".to_string(),
            call_id: "call-task".to_string(),
            name: "task".to_string(),
            arguments: json!({
                "description": "Inspect tests",
                "prompt": "Run focused tests.",
                "subagent_type": "explore"
            })
            .to_string(),
        };
        let execution = ToolExecution::from_call(
            &call,
            &HashMap::new(),
            9,
            Some("parent"),
            Some("gpt-5.6-sol-xhigh"),
        )
        .unwrap();
        let success = message(&[
            (1, b"agent-123"),
            (2, b"All focused tests passed."),
            (5, b"/tmp/subagent-transcript"),
        ]);
        let raw_result = message(&[(1, &success)]);
        let result = ClientMessage::Exec {
            id: 9,
            exec_id: String::new(),
            result_field: 28,
            result: raw_result,
        };

        assert!(exec_result_text(&result).contains("All focused tests passed."));
        let result = ToolResult::from_client(result);
        let completed = tool_completed_frame(&execution, &result);
        let completed = first_connect_frame(&completed).unwrap().unwrap();
        let server = WireMessage::parse(completed.payload).unwrap();
        let interaction = WireMessage::parse(server.bytes(1).unwrap()).unwrap();
        let update = WireMessage::parse(interaction.bytes(3).unwrap()).unwrap();
        let tool_call = WireMessage::parse(update.bytes(2).unwrap()).unwrap();
        let task_call = WireMessage::parse(tool_call.bytes(19).unwrap()).unwrap();
        let task_result = WireMessage::parse(task_call.bytes(2).unwrap()).unwrap();
        let task_success = WireMessage::parse(task_result.bytes(1).unwrap()).unwrap();
        let step = WireMessage::parse(task_success.bytes(1).unwrap()).unwrap();
        let assistant = WireMessage::parse(step.bytes(1).unwrap()).unwrap();
        assert_eq!(
            assistant.string(1).unwrap(),
            Some("All focused tests passed.")
        );
        assert_eq!(task_success.string(2).unwrap(), Some("agent-123"));
    }

    #[test]
    fn parent_model_overrides_model_suggested_by_task_call() {
        let args = subagent_args(
            &json!({
                "prompt": "Inspect the repository.",
                "subagent_type": "explore",
                "model": "fast"
            }),
            "call-task",
            Some("parent"),
            Some("gpt-5.6-sol-xhigh"),
        )
        .unwrap();
        let args = WireMessage::parse(&args).unwrap();

        assert_eq!(args.string(3).unwrap(), Some("gpt-5.6-sol-xhigh"));
    }

    #[test]
    fn explicit_subagent_model_is_preserved_without_a_parent_default() {
        let args = subagent_args(
            &json!({
                "prompt": "Inspect the repository.",
                "subagent_type": "explore",
                "model": "claude-4.5-sonnet"
            }),
            "call-task",
            Some("parent"),
            None,
        )
        .unwrap();
        let args = WireMessage::parse(&args).unwrap();

        assert_eq!(args.string(3).unwrap(), Some("claude-4.5-sonnet"));
    }

    #[test]
    fn tool_completion_includes_the_executor_result() {
        let call = ToolCall {
            item_id: "item-1".to_string(),
            call_id: "call-1".to_string(),
            name: "read_file".to_string(),
            arguments: r#"{"path":"README.md"}"#.to_string(),
        };
        let execution = ToolExecution::from_call(&call, &HashMap::new(), 1, None, None).unwrap();
        let raw_result = message(&[(1, &message(&[(1, b"README.md"), (2, b"contents")]))]);
        let result = ClientMessage::Exec {
            id: 1,
            exec_id: "call-1".to_string(),
            result_field: 7,
            result: raw_result.clone(),
        };

        let started = tool_started_frame(&execution);
        let started = first_connect_frame(&started).unwrap().unwrap();
        let server = WireMessage::parse(started.payload).unwrap();
        let interaction = WireMessage::parse(server.bytes(1).unwrap()).unwrap();
        let update = WireMessage::parse(interaction.bytes(2).unwrap()).unwrap();
        let tool_call = WireMessage::parse(update.bytes(2).unwrap()).unwrap();
        let read_call = WireMessage::parse(tool_call.bytes(8).unwrap()).unwrap();
        assert_eq!(update.string(1).unwrap(), Some("call-1"));
        assert_eq!(update.string(3).unwrap(), Some("item-1"));
        assert!(read_call.bytes(1).is_some());
        assert!(read_call.bytes(2).is_none());

        let result = ToolResult::from_client(result);
        let completed = tool_completed_frame(&execution, &result);
        let completed = first_connect_frame(&completed).unwrap().unwrap();
        let server = WireMessage::parse(completed.payload).unwrap();
        let interaction = WireMessage::parse(server.bytes(1).unwrap()).unwrap();
        let update = WireMessage::parse(interaction.bytes(3).unwrap()).unwrap();
        let tool_call = WireMessage::parse(update.bytes(2).unwrap()).unwrap();
        let read_call = WireMessage::parse(tool_call.bytes(8).unwrap()).unwrap();
        assert_eq!(update.string(1).unwrap(), Some("call-1"));
        assert_eq!(update.string(3).unwrap(), Some("item-1"));
        let result = WireMessage::parse(read_call.bytes(2).unwrap()).unwrap();
        let success = WireMessage::parse(result.bytes(1).unwrap()).unwrap();
        assert_eq!(success.string(1).unwrap(), Some("contents"));
        assert_eq!(success.string(7).unwrap(), Some("README.md"));
        assert_eq!(success.varint(2), None);
    }

    #[test]
    fn read_display_converts_executor_errors() {
        let raw_error = message(&[(4, &message(&[(1, b"missing.txt")]))]);
        let display = read_display_result(&raw_error);
        let result = WireMessage::parse(&display).unwrap();
        let error = WireMessage::parse(result.bytes(2).unwrap()).unwrap();
        assert!(!error.string(1).unwrap().unwrap().is_empty());
    }

    #[test]
    fn generic_display_completion_converts_result_to_mcp_shape() {
        let call = ToolCall {
            item_id: "item-2".to_string(),
            call_id: "call-2".to_string(),
            name: "write_file".to_string(),
            arguments: r#"{"path":"notes.txt","content":"done"}"#.to_string(),
        };
        let execution = ToolExecution::from_call(&call, &HashMap::new(), 2, None, None).unwrap();
        let result = ClientMessage::Exec {
            id: 2,
            exec_id: "call-2".to_string(),
            result_field: 3,
            result: message(&[(1, b"notes.txt")]),
        };

        let result = ToolResult::from_client(result);
        let completed = tool_completed_frame(&execution, &result);
        let completed = first_connect_frame(&completed).unwrap().unwrap();
        let server = WireMessage::parse(completed.payload).unwrap();
        let interaction = WireMessage::parse(server.bytes(1).unwrap()).unwrap();
        let update = WireMessage::parse(interaction.bytes(3).unwrap()).unwrap();
        let tool_call = WireMessage::parse(update.bytes(2).unwrap()).unwrap();
        let mcp_call = WireMessage::parse(tool_call.bytes(15).unwrap()).unwrap();
        let mcp_result = WireMessage::parse(mcp_call.bytes(2).unwrap()).unwrap();
        let success = WireMessage::parse(mcp_result.bytes(1).unwrap()).unwrap();
        let content = WireMessage::parse(success.bytes(1).unwrap()).unwrap();
        let text = WireMessage::parse(content.bytes(1).unwrap()).unwrap();
        assert!(!text.string(1).unwrap().unwrap().is_empty());
    }

    #[test]
    fn exec_server_frame_uses_local_executor_shape() {
        let call = ToolCall {
            item_id: "item-1".to_string(),
            call_id: "call-1".to_string(),
            name: "read_file".to_string(),
            arguments: r#"{"path":"README.md"}"#.to_string(),
        };
        let execution = ToolExecution::from_call(&call, &HashMap::new(), 1, None, None).unwrap();
        let frame = exec_server_frame(&execution);
        let parsed = first_connect_frame(&frame).unwrap().unwrap();
        let server = WireMessage::parse(parsed.payload).unwrap();
        let exec = WireMessage::parse(server.bytes(2).unwrap()).unwrap();

        assert_eq!(exec.varint(1), Some(1));
        assert!(exec.bytes(15).is_none());
        assert!(exec.bytes(7).is_some());
    }
}
