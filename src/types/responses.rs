//! OpenAI Responses API types (what the Codex backend expects/returns).

use serde::{Deserialize, Serialize};

/// Outgoing `POST /responses` request built from a Chat Completions request.
#[derive(Debug, Clone, Serialize)]
pub struct ResponsesRequest {
    pub model: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub instructions: String,
    pub input: Vec<ResponseInputItem>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<serde_json::Value>,
    pub tool_choice: String,
    pub parallel_tool_calls: bool,
    pub store: bool,
    pub stream: bool,
    pub include: Vec<String>,
}

impl ResponsesRequest {
    pub fn new(model: String) -> Self {
        Self {
            model,
            instructions: String::new(),
            input: Vec::new(),
            tools: Vec::new(),
            tool_choice: "auto".to_string(),
            parallel_tool_calls: true,
            store: false,
            stream: true,
            include: vec!["reasoning.encrypted_content".to_string()],
        }
    }
}

/// A single item in the `input` array.
/// We build these as raw JSON values to keep shapes flexible.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ResponseInputItem {
    Message {
        #[serde(rename = "type")]
        kind: String, // "message"
        role: String,
        content: Vec<MessageContent>,
    },
    FunctionCall {
        #[serde(rename = "type")]
        kind: String, // "function_call"
        call_id: String,
        name: String,
        arguments: String,
    },
    FunctionCallOutput {
        #[serde(rename = "type")]
        kind: String, // "function_call_output"
        call_id: String,
        output: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct MessageContent {
    #[serde(rename = "type")]
    pub kind: String, // "input_text" | "output_text"
    pub text: String,
}

impl MessageContent {
    pub fn input(text: impl Into<String>) -> Self {
        Self {
            kind: "input_text".to_string(),
            text: text.into(),
        }
    }
    pub fn output(text: impl Into<String>) -> Self {
        Self {
            kind: "output_text".to_string(),
            text: text.into(),
        }
    }
}

// ---------- SSE stream events from /responses ----------

/// A single parsed SSE event from the Responses stream.
///
/// The Codex backend emits events with `type` strings like
/// `response.output_text.delta`, `response.completed`, etc. We keep the payload
/// as raw JSON and dispatch on the `type` field.
#[derive(Debug, Clone, Deserialize)]
pub struct ResponsesStreamEvent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub delta: Option<String>,
    #[serde(default)]
    pub item: Option<serde_json::Value>,
    #[serde(default)]
    pub response: Option<serde_json::Value>,
    #[serde(default)]
    pub item_id: Option<String>,
    #[serde(default)]
    pub call_id: Option<String>,
    /// partial JSON arguments string for function calls (some event variants).
    #[serde(default)]
    pub arguments: Option<String>,
}
