//! Translate the Responses SSE stream into a Chat Completions SSE stream.

use std::collections::HashMap;

use anyhow::Result;
use tokio::io::AsyncBufReadExt;

use crate::types::chat::{
    ChatCompletionChunk, ChunkChoice, ChunkToolCall, ChunkToolCallFunction, ChunkUsage, Delta,
};

/// State machine that converts a stream of Responses SSE events (lines read from
/// the upstream HTTP stream) into Chat Completions SSE chunks (bytes to write
/// back to Cursor).
pub struct StreamTranslator {
    model: String,
    /// Whether we've emitted the leading `role: assistant` delta.
    sent_role: bool,
    /// Maps a function-call item id → its positional index in the chunk stream.
    tool_calls: HashMap<String, ToolCallState>,
    /// Next tool-call index to assign.
    next_call_index: u32,
    /// Accumulated finish state from `response.completed`.
    finished: bool,
}

#[derive(Debug, Clone)]
struct ToolCallState {
    index: u32,
    args_len: usize,
}

impl StreamTranslator {
    pub fn new(model: String) -> Self {
        Self {
            model,
            sent_role: false,
            tool_calls: HashMap::new(),
            next_call_index: 0,
            finished: false,
        }
    }

    /// Emit the initial role chunk once.
    fn ensure_role(&mut self) -> Option<ChatCompletionChunk> {
        if self.sent_role {
            return None;
        }
        self.sent_role = true;
        Some(self.chunk(ChunkChoice {
            index: 0,
            delta: Some(Delta {
                role: Some("assistant".to_string()),
                ..Default::default()
            }),
            finish_reason: None,
        }))
    }

    fn chunk(&self, choice: ChunkChoice) -> ChatCompletionChunk {
        ChatCompletionChunk::new(self.model.clone(), vec![choice])
    }

    /// Handle one parsed Responses event, returning zero or more Chat Completions
    /// chunks to emit.
    pub fn handle_event(
        &mut self,
        event: &crate::types::responses::ResponsesStreamEvent,
    ) -> Vec<ChatCompletionChunk> {
        let mut out = Vec::new();
        match event.kind.as_str() {
            "response.created" => {
                if let Some(role_chunk) = self.ensure_role() {
                    out.push(role_chunk);
                }
            }

            // Text deltas.
            "response.output_text.delta" => {
                if let Some(role_chunk) = self.ensure_role() {
                    out.push(role_chunk);
                }
                if let Some(text) = &event.delta {
                    out.push(self.chunk(ChunkChoice {
                        index: 0,
                        delta: Some(Delta {
                            content: Some(text.clone()),
                            ..Default::default()
                        }),
                        finish_reason: None,
                    }));
                }
            }

            // A function call item appears.
            "response.output_item.added" => {
                if let Some(item) = &event.item {
                    let item_type = jstr(item, "type");
                    if matches!(
                        item_type.as_deref(),
                        Some("function_call") | Some("custom_tool_call")
                    ) {
                        if let Some(role_chunk) = self.ensure_role() {
                            out.push(role_chunk);
                        }
                        let item_id = jstr(item, "id")
                            .or_else(|| event.item_id.clone())
                            .or_else(|| event.call_id.clone())
                            .unwrap_or_default();
                        let call_id = jstr(item, "call_id")
                            .or_else(|| event.call_id.clone())
                            .unwrap_or_else(|| item_id.clone());
                        let idx = self.assign_index(item_id);
                        let name = jstr(item, "name").unwrap_or_default();
                        out.push(self.chunk(ChunkChoice {
                            index: 0,
                            delta: Some(Delta {
                                tool_calls: vec![ChunkToolCall {
                                    index: idx,
                                    id: Some(call_id),
                                    kind: Some("function".to_string()),
                                    function: Some(ChunkToolCallFunction {
                                        name: Some(name),
                                        arguments: Some(String::new()),
                                    }),
                                }],
                                ..Default::default()
                            }),
                            finish_reason: None,
                        }));
                    }
                }
            }

            // Partial function-call arguments.
            "response.function_call_arguments.delta" | "response.custom_tool_call_input.delta" => {
                let args = event.delta.as_ref().or(event.arguments.as_ref());
                if let Some(args) = args {
                    let id = event.item_id.clone().unwrap_or_default();
                    let idx = self.resolve_index(&id);
                    self.add_args_len(&id, args.len());
                    out.push(self.chunk(ChunkChoice {
                        index: 0,
                        delta: Some(Delta {
                            tool_calls: vec![ChunkToolCall {
                                index: idx,
                                function: Some(ChunkToolCallFunction {
                                    arguments: Some(args.clone()),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }],
                            ..Default::default()
                        }),
                        finish_reason: None,
                    }));
                }
            }

            // Some upstream variants only provide the full argument/input string
            // when the output item is done. If no deltas were forwarded, emit
            // that final payload as a single arguments chunk.
            "response.output_item.done" => {
                if let Some(item) = &event.item {
                    let item_type = jstr(item, "type");
                    if matches!(
                        item_type.as_deref(),
                        Some("function_call") | Some("custom_tool_call")
                    ) {
                        let item_id = jstr(item, "id")
                            .or_else(|| event.item_id.clone())
                            .or_else(|| event.call_id.clone())
                            .unwrap_or_default();
                        if item_id.is_empty() {
                            return out;
                        }
                        if !self.tool_calls.contains_key(&item_id) {
                            if let Some(role_chunk) = self.ensure_role() {
                                out.push(role_chunk);
                            }
                            let call_id = jstr(item, "call_id").unwrap_or_else(|| item_id.clone());
                            let idx = self.assign_index(item_id.clone());
                            let name = jstr(item, "name").unwrap_or_default();
                            out.push(self.chunk(ChunkChoice {
                                index: 0,
                                delta: Some(Delta {
                                    tool_calls: vec![ChunkToolCall {
                                        index: idx,
                                        id: Some(call_id),
                                        kind: Some("function".to_string()),
                                        function: Some(ChunkToolCallFunction {
                                            name: Some(name),
                                            arguments: Some(String::new()),
                                        }),
                                    }],
                                    ..Default::default()
                                }),
                                finish_reason: None,
                            }));
                        }
                        if self.args_len(&item_id) == 0 {
                            let args = if item_type.as_deref() == Some("custom_tool_call") {
                                jstr(item, "input")
                            } else {
                                jstr(item, "arguments")
                            };
                            if let Some(args) = args {
                                if !args.is_empty() {
                                    let idx = self.resolve_index(&item_id);
                                    self.add_args_len(&item_id, args.len());
                                    out.push(self.chunk(ChunkChoice {
                                        index: 0,
                                        delta: Some(Delta {
                                            tool_calls: vec![ChunkToolCall {
                                                index: idx,
                                                function: Some(ChunkToolCallFunction {
                                                    arguments: Some(args),
                                                    ..Default::default()
                                                }),
                                                ..Default::default()
                                            }],
                                            ..Default::default()
                                        }),
                                        finish_reason: None,
                                    }));
                                }
                            }
                        }
                    }
                }
            }

            // Completion.
            "response.completed" | "response.done" => {
                self.finished = true;
                if let Some(role_chunk) = self.ensure_role() {
                    out.push(role_chunk);
                }
                let finish_reason = if self.had_tool_calls()
                    || event.response.as_ref().is_some_and(response_has_tool_calls)
                {
                    "tool_calls"
                } else {
                    "stop"
                };
                let mut choice = ChunkChoice {
                    index: 0,
                    delta: Some(Delta::default()),
                    finish_reason: Some(finish_reason.to_string()),
                };
                let _ = &mut choice; // (placeholder for future per-choice tweaks)
                let mut chunk = self.chunk(choice);
                if let Some(usage) = event.response.as_ref().and_then(extract_usage) {
                    chunk.usage = Some(usage);
                }
                out.push(chunk);
            }

            "response.failed" | "response.incomplete" => {
                self.finished = true;
                out.push(self.chunk(ChunkChoice {
                    index: 0,
                    delta: Some(Delta::default()),
                    finish_reason: Some("stop".to_string()),
                }));
            }

            _ => {
                // Ignore reasoning/metadata/other events — they don't map to
                // Chat Completions chunks.
            }
        }
        out
    }

    fn assign_index(&mut self, id: String) -> u32 {
        if let Some(state) = self.tool_calls.get(&id) {
            return state.index;
        }
        let i = self.next_call_index;
        self.next_call_index += 1;
        self.tool_calls.insert(
            id,
            ToolCallState {
                index: i,
                args_len: 0,
            },
        );
        i
    }

    fn resolve_index(&self, id: &str) -> u32 {
        self.tool_calls.get(id).map(|s| s.index).unwrap_or(0)
    }

    fn add_args_len(&mut self, id: &str, len: usize) {
        if let Some(state) = self.tool_calls.get_mut(id) {
            state.args_len += len;
        }
    }

    fn args_len(&self, id: &str) -> usize {
        self.tool_calls.get(id).map(|s| s.args_len).unwrap_or(0)
    }

    fn had_tool_calls(&self) -> bool {
        !self.tool_calls.is_empty()
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

fn response_has_tool_calls(response: &serde_json::Value) -> bool {
    response
        .get("output")
        .and_then(|v| v.as_array())
        .map(|items| {
            items.iter().any(|item| {
                matches!(
                    jstr(item, "type").as_deref(),
                    Some("function_call") | Some("custom_tool_call")
                )
            })
        })
        .unwrap_or(false)
}

/// Pull usage stats out of a `response.completed` payload.
fn extract_usage(response: &serde_json::Value) -> Option<ChunkUsage> {
    let usage = jget(response, "usage")?;
    let prompt_tokens = jget(usage, "input_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let completion_tokens = jget(usage, "output_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    Some(ChunkUsage {
        prompt_tokens,
        completion_tokens,
        total_tokens: prompt_tokens + completion_tokens,
    })
}

fn jget<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = value;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

fn jstr(value: &serde_json::Value, path: &str) -> Option<String> {
    jget(value, path)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Read the upstream SSE byte stream line-by-line, parse events, and produce a
/// **live** stream of Chat Completions SSE frames. Each frame is emitted as soon
/// as its source event arrives — buffering the whole response causes the client
/// (Cursor via the tunnel) to time out and close the connection (broken pipe).
pub fn translate_stream(
    stream: crate::codex::client::ByteStream,
    model: String,
) -> impl futures::Stream<Item = Result<bytes::Bytes>> + Send {
    use futures::StreamExt;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes>>(32);
    let mapped = stream.map(|res| {
        res.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            .map(|b| b)
    });
    let reader = tokio_util::io::StreamReader::new(mapped);
    let mut buf = tokio::io::BufReader::new(reader);
    let mut translator = StreamTranslator::new(model);

    tokio::spawn(async move {
        let mut line = String::new();
        let mut error: Option<anyhow::Error> = None;
        loop {
            line.clear();
            let n = match buf.read_line(&mut line).await {
                Ok(n) => n,
                Err(e) => {
                    error = Some(e.into());
                    break;
                }
            };
            if n == 0 {
                break; // upstream closed
            }
            let trimmed = line.trim_end_matches('\n');
            let trimmed = trimmed.trim_end_matches('\r');

            let Some(rest) = trimmed.strip_prefix("data:") else {
                continue;
            };
            let rest = rest.trim();
            if rest.is_empty() {
                continue;
            }
            let event =
                match serde_json::from_str::<crate::types::responses::ResponsesStreamEvent>(rest) {
                    Ok(ev) => ev,
                    Err(e) => {
                        tracing::warn!(data = rest, err = %e, "unparseable SSE event");
                        continue;
                    }
                };
            for chunk in translator.handle_event(&event) {
                match serde_json::to_string(&chunk) {
                    Ok(json) => {
                        if tx
                            .send(Ok(bytes::Bytes::from(format!("data: {json}\n\n"))))
                            .await
                            .is_err()
                        {
                            // Client disconnected — stop.
                            return;
                        }
                    }
                    Err(e) => {
                        error = Some(e.into());
                        break;
                    }
                }
            }
            if error.is_some() {
                break;
            }
        }

        // Emit a finish chunk if the upstream ended without one.
        if error.is_none() && !translator.is_finished() {
            let chunk = ChatCompletionChunk::new(
                translator_model(&translator),
                vec![ChunkChoice {
                    index: 0,
                    delta: Some(Delta::default()),
                    finish_reason: Some("stop".to_string()),
                }],
            );
            if let Ok(json) = serde_json::to_string(&chunk) {
                let _ = tx
                    .send(Ok(bytes::Bytes::from(format!("data: {json}\n\n"))))
                    .await;
            }
        }
        let _ = tx.send(Ok(bytes::Bytes::from("data: [DONE]\n\n"))).await;
        if let Some(e) = error {
            let _ = tx.send(Err(e)).await;
        }
    });

    tokio_stream::wrappers::ReceiverStream::new(rx)
}

fn translator_model(t: &StreamTranslator) -> String {
    t.model.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(value: serde_json::Value) -> crate::types::responses::ResponsesStreamEvent {
        serde_json::from_value(value).unwrap()
    }

    fn chunk_value(chunk: &ChatCompletionChunk) -> serde_json::Value {
        serde_json::to_value(chunk).unwrap()
    }

    #[test]
    fn function_call_arguments_use_delta_and_item_id_slot() {
        let mut translator = StreamTranslator::new("gpt-test".to_string());

        let start = translator.handle_event(&event(json!({
            "type": "response.output_item.added",
            "item": {
                "id": "item_1",
                "type": "function_call",
                "call_id": "call_1",
                "name": "read_file"
            }
        })));
        assert_eq!(start.len(), 2);
        let start_json = chunk_value(&start[1]);
        assert_eq!(
            start_json["choices"][0]["delta"]["tool_calls"][0]["id"],
            "call_1"
        );
        assert_eq!(
            start_json["choices"][0]["delta"]["tool_calls"][0]["function"]["name"],
            "read_file"
        );

        let args = translator.handle_event(&event(json!({
            "type": "response.function_call_arguments.delta",
            "item_id": "item_1",
            "delta": "{\"path\":\"README.md\"}"
        })));
        assert_eq!(args.len(), 1);
        let args_json = chunk_value(&args[0]);
        assert_eq!(
            args_json["choices"][0]["delta"]["tool_calls"][0]["index"],
            0
        );
        assert_eq!(
            args_json["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            "{\"path\":\"README.md\"}"
        );
    }

    #[test]
    fn custom_tool_call_done_emits_full_input_fallback() {
        let mut translator = StreamTranslator::new("gpt-test".to_string());

        translator.handle_event(&event(json!({
            "type": "response.output_item.added",
            "item": {
                "id": "item_custom",
                "type": "custom_tool_call",
                "call_id": "call_custom",
                "name": "ApplyPatch"
            }
        })));

        let done = translator.handle_event(&event(json!({
            "type": "response.output_item.done",
            "item": {
                "id": "item_custom",
                "type": "custom_tool_call",
                "call_id": "call_custom",
                "name": "ApplyPatch",
                "input": "*** Begin Patch\n*** End Patch"
            }
        })));
        assert_eq!(done.len(), 1);
        let done_json = chunk_value(&done[0]);
        assert_eq!(
            done_json["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            "*** Begin Patch\n*** End Patch"
        );

        let completed = translator.handle_event(&event(json!({
            "type": "response.completed",
            "response": {"status": "completed", "output": []}
        })));
        assert_eq!(
            chunk_value(&completed[0])["choices"][0]["finish_reason"],
            "tool_calls"
        );
    }
}
