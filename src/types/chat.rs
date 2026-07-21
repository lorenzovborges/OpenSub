//! OpenAI Chat Completions types (what Cursor sends and expects).

use base64::Engine;
use serde::{Deserialize, Serialize};

/// Incoming `POST /v1/chat/completions` request from Cursor.
#[derive(Debug, Clone, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub stream: bool,
    #[serde(default)]
    pub tools: Vec<ChatTool>,
    #[serde(default)]
    pub tool_choice: Option<serde_json::Value>,
}

/// A single message in a Chat Completions request.
///
/// `content` can be a string or an array of content parts; we keep it as raw
/// JSON to preserve whatever Cursor sends.
#[derive(Debug, Clone, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    #[serde(default)]
    pub content: Option<serde_json::Value>,
    #[serde(default)]
    pub tool_call_id: Option<String>,
    #[serde(default)]
    pub tool_calls: Vec<ChatToolCall>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChatToolCall {
    pub id: String,
    pub function: ChatToolCallFunction,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChatToolCallFunction {
    pub name: String,
    pub arguments: String,
}

/// A tool in a Chat Completions request. Kept as raw JSON so we accept any tool
/// shape Cursor sends (`function`, but also built-in tools like `web_search`,
/// `code_interpreter`, `image_generation`, etc., which don't have a `function`
/// field and would otherwise fail deserialization).
#[derive(Debug, Clone, Deserialize)]
pub struct ChatTool(pub serde_json::Value);

impl ChatTool {
    /// If this is a `function`-type tool, return its parsed definition.
    pub fn as_function(&self) -> Option<ChatToolFunction> {
        let v = &self.0;
        if v.get("type").and_then(|t| t.as_str()) == Some("function") {
            serde_json::from_value::<ChatToolFunction>(v.get("function")?.clone()).ok()
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChatToolFunction {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub parameters: serde_json::Value,
}

// ---------- Streaming chunk (what we emit back to Cursor) ----------

/// A single SSE chunk in the Chat Completions stream format.
#[derive(Debug, Clone, Serialize)]
pub struct ChatCompletionChunk {
    pub id: String,
    pub object: &'static str, // "chat.completion.chunk"
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChunkChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<ChunkUsage>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChunkChoice {
    pub index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<Delta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Delta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ChunkToolCall>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ChunkToolCall {
    pub index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<ChunkToolCallFunction>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ChunkToolCallFunction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChunkUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

impl ChatCompletionChunk {
    pub fn new(model: String, choices: Vec<ChunkChoice>) -> Self {
        Self {
            id: format!("chatcmpl-opensub-{}", rand_id()),
            object: "chat.completion.chunk",
            created: now_ts(),
            model,
            choices,
            usage: None,
        }
    }
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn rand_id() -> String {
    let bytes: [u8; 12] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
