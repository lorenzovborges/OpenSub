//! Translate a Chat Completions request into a Responses request.

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::types::chat::ChatCompletionRequest;
use crate::types::responses::{MessageContent, ResponseInputItem, ResponsesRequest};

/// Convert Cursor's Chat Completions request into the Responses shape the Codex
/// backend expects.
pub fn translate(req: &ChatCompletionRequest) -> Result<ResponsesRequest> {
    let mut out = ResponsesRequest::new(req.model.clone());
    out.stream = req.stream;

    let mut instructions = String::new();
    for msg in &req.messages {
        match msg.role.as_str() {
            "system" => {
                if let Some(text) = content_to_string(&msg.content) {
                    if !instructions.is_empty() {
                        instructions.push_str("\n\n");
                    }
                    instructions.push_str(&text);
                }
            }
            "user" => {
                out.input.push(ResponseInputItem::Message {
                    kind: "message".to_string(),
                    role: "user".to_string(),
                    content: vec![MessageContent::input(
                        content_to_string(&msg.content).unwrap_or_default(),
                    )],
                });
            }
            "assistant" => {
                // Emit any prior text content first.
                if let Some(text) = content_to_string(&msg.content)
                    && !text.trim().is_empty()
                {
                    out.input.push(ResponseInputItem::Message {
                        kind: "message".to_string(),
                        role: "assistant".to_string(),
                        content: vec![MessageContent::output(text)],
                    });
                }
                // Then any tool calls the assistant made.
                for tc in &msg.tool_calls {
                    out.input.push(ResponseInputItem::FunctionCall {
                        kind: "function_call".to_string(),
                        call_id: normalize_call_id(&tc.id),
                        name: tc.function.name.clone(),
                        arguments: tc.function.arguments.clone(),
                    });
                }
            }
            "tool" => {
                let call_id = normalize_call_id(msg.tool_call_id.as_deref().unwrap_or_default());
                out.input.push(ResponseInputItem::FunctionCallOutput {
                    kind: "function_call_output".to_string(),
                    call_id,
                    output: content_to_string(&msg.content).unwrap_or_default(),
                });
            }
            other => {
                // Unknown role: treat as a user message to avoid dropping it.
                out.input.push(ResponseInputItem::Message {
                    kind: "message".to_string(),
                    role: other.to_string(),
                    content: vec![MessageContent::input(
                        content_to_string(&msg.content).unwrap_or_default(),
                    )],
                });
            }
        }
    }

    // Tools: only `function`-type tools are forwarded to the Codex backend
    // (reshaped to its flat {type,name,description,parameters} form). Non-function
    // tools (web_search, code_interpreter, etc.) are dropped — the backend can't
    // serve them anyway.
    for t in &req.tools {
        let Some(func) = t.as_function() else {
            tracing::debug!(
                tool_type =
                    t.0.get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown"),
                "dropping non-function tool"
            );
            continue;
        };
        let mut tool = serde_json::Map::new();
        tool.insert("type".to_string(), serde_json::json!("function"));
        tool.insert("name".to_string(), serde_json::Value::String(func.name));
        if let Some(d) = &func.description {
            tool.insert(
                "description".to_string(),
                serde_json::Value::String(d.clone()),
            );
        }
        tool.insert(
            "parameters".to_string(),
            if func.parameters.is_null() {
                serde_json::json!({})
            } else {
                func.parameters.clone()
            },
        );
        out.tools.push(serde_json::Value::Object(tool));
    }
    if let Some(tc) = &req.tool_choice
        && let Some(s) = tc.as_str()
    {
        out.tool_choice = s.to_string();
    }

    out.instructions = instructions;
    Ok(out)
}

pub(crate) fn normalize_call_id(call_id: &str) -> String {
    const MAX_CALL_ID_CHARS: usize = 64;
    if call_id.chars().count() <= MAX_CALL_ID_CHARS {
        return call_id.to_string();
    }

    let digest = Sha256::digest(call_id.as_bytes());
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("call_{}", &hex[..MAX_CALL_ID_CHARS - 5])
}

/// Normalize a message's `content` (which may be a string or an array of content
/// parts) into a single string.
fn content_to_string(content: &Option<serde_json::Value>) -> Option<String> {
    let value = content.as_ref()?;
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(parts) => {
            let mut out = String::new();
            for part in parts {
                if let Some(t) = part.get("text").and_then(|v| v.as_str()) {
                    out.push_str(t);
                }
            }
            if out.is_empty() { None } else { Some(out) }
        }
        _ => Some(value.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::chat::ChatCompletionRequest;

    #[test]
    fn long_tool_call_ids_remain_correlated_after_translation() {
        let long_id = "cursor-tool-call-".repeat(6);
        let request: ChatCompletionRequest = serde_json::from_value(serde_json::json!({
            "model": "gpt-5.6-sol",
            "messages": [
                {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": long_id,
                        "type": "function",
                        "function": {"name": "lookup", "arguments": "{}"}
                    }]
                },
                {"role": "tool", "tool_call_id": long_id, "content": "done"}
            ]
        }))
        .unwrap();

        let translated = translate(&request).unwrap();
        let call_id = match &translated.input[0] {
            ResponseInputItem::FunctionCall { call_id, .. } => call_id,
            item => panic!("expected function call, got {item:?}"),
        };
        let output_call_id = match &translated.input[1] {
            ResponseInputItem::FunctionCallOutput { call_id, .. } => call_id,
            item => panic!("expected function call output, got {item:?}"),
        };

        assert_eq!(call_id, output_call_id);
        assert_eq!(call_id.chars().count(), 64);
        assert!(call_id.starts_with("call_"));
    }
}
