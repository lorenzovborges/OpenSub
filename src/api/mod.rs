//! HTTP API: `/v1/models` and `/v1/chat/completions`.

pub mod models;

use axum::Json;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Map, Value};

use crate::auth;
use crate::codex;
use crate::config;
use crate::translate;

#[derive(Clone)]
pub struct AppState;

pub fn router() -> axum::Router {
    axum::Router::new()
        .route("/v1/models", get(models::list))
        .route("/v1/chat/completions", post(chat_completions))
        // Also accept the path without the /v1 prefix — some clients call it.
        .route("/chat/completions", post(chat_completions))
        .route("/models", get(models::list))
        .layer(middleware::from_fn(require_api_key))
        .with_state(AppState)
}

/// Middleware: require a Bearer token matching the configured API key.
///
/// OpenSub is exposed via a public tunnel, so this gates access to your
/// subscription. The key is `config::api_key()` (auto-generated on first run,
/// printed at `serve` startup).
async fn require_api_key(req: Request, next: Next) -> Result<Response, StatusCode> {
    let expected = config::api_key();
    let provided = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .or_else(|| {
            req.headers()
                .get("x-api-key")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.trim().to_string())
        });

    match provided {
        Some(k) if k == expected => Ok(next.run(req).await),
        _ => {
            tracing::warn!("rejected request: missing or invalid API key");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

async fn chat_completions(
    State(_state): State<AppState>,
    Json(raw): Json<Value>,
) -> Result<Response, ApiError> {
    let client_wants_stream = raw.get("stream").and_then(Value::as_bool).unwrap_or(false);

    // The ChatGPT/Codex backend rejects `stream:false`. So we ALWAYS stream to
    // upstream, and if the client asked for non-streaming we buffer the whole
    // translated stream and collapse it into a single Chat Completions object.
    let mut prepared = prepare_upstream_body(raw).map_err(ApiError::Translate)?;
    prepared.body["stream"] = Value::Bool(true);

    tracing::debug!(
        model = %prepared.model,
        input_count = json_array_len(&prepared.body, "input"),
        tool_count = json_array_len(&prepared.body, "tools"),
        has_prompt_cache_key = prepared.body.get("prompt_cache_key").is_some(),
        "prepared upstream request"
    );

    let tokens = auth::require_token().await.map_err(ApiError::Auth)?;
    let upstream = codex::client::post_responses_stream(&tokens, &prepared.body)
        .await
        .map_err(ApiError::Upstream)?;

    if client_wants_stream {
        // Stream frames to the client as they arrive (keeps the connection live
        // so the tunnel/client doesn't time out → broken pipe).
        let out = translate::stream::translate_stream(upstream, prepared.model);
        Ok((
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            )],
            Body::from_stream(out),
        )
            .into_response())
    } else {
        // Non-streaming: collect all frames, then collapse into one object.
        use futures::TryStreamExt;
        let collected: Vec<_> = translate::stream::translate_stream(upstream, prepared.model)
            .try_collect()
            .await
            .map_err(ApiError::Translate)?;
        let buf: Vec<u8> = collected.into_iter().flatten().collect();
        Ok(non_streaming_response(&buf).into_response())
    }
}

struct PreparedBody {
    body: Value,
    model: String,
}

fn prepare_upstream_body(raw: Value) -> anyhow::Result<PreparedBody> {
    let mut body = if raw.get("input").and_then(Value::as_array).is_some() {
        sanitize_responses_request(raw)?
    } else {
        let req = serde_json::from_value::<crate::types::chat::ChatCompletionRequest>(raw)?;
        serde_json::to_value(translate::translate(&req)?)?
    };

    normalize_responses_request(&mut body)?;
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("gpt-5.5")
        .to_string();
    Ok(PreparedBody { body, model })
}

fn sanitize_responses_request(raw: Value) -> anyhow::Result<Value> {
    const ALLOWED: &[&str] = &[
        "model",
        "instructions",
        "input",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "reasoning",
        "store",
        "stream",
        "include",
        "service_tier",
        "prompt_cache_key",
        "text",
        "client_metadata",
    ];

    let obj = raw
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("request body must be a JSON object"))?;
    let mut out = Map::new();
    for key in ALLOWED {
        if let Some(value) = obj.get(*key) {
            out.insert((*key).to_string(), value.clone());
        }
    }
    Ok(Value::Object(out))
}

fn normalize_responses_request(body: &mut Value) -> anyhow::Result<()> {
    let obj = body
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("prepared body must be a JSON object"))?;

    lift_system_instructions(obj);

    if let Some(model) = obj.get("model").and_then(Value::as_str) {
        if let Some(stripped) = model.strip_suffix("-extra") {
            obj.insert("model".to_string(), Value::String(stripped.to_string()));
        }
    }

    obj.insert("store".to_string(), Value::Bool(false));
    obj.entry("service_tier".to_string())
        .or_insert_with(|| Value::String("priority".to_string()));
    obj.entry("prompt_cache_key".to_string())
        .or_insert_with(|| Value::String(config::session_id().to_string()));

    let reasoning = obj
        .entry("reasoning".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(reasoning_obj) = reasoning.as_object_mut() {
        reasoning_obj
            .entry("effort".to_string())
            .or_insert_with(|| Value::String("xhigh".to_string()));
    }

    let include = obj
        .entry("include".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Some(items) = include.as_array_mut() {
        let encrypted = Value::String("reasoning.encrypted_content".to_string());
        if !items.contains(&encrypted) {
            items.push(encrypted);
        }
    }

    if !obj
        .get("parallel_tool_calls")
        .map(Value::is_boolean)
        .unwrap_or(false)
    {
        obj.insert("parallel_tool_calls".to_string(), Value::Bool(true));
    }

    Ok(())
}

fn lift_system_instructions(obj: &mut Map<String, Value>) {
    let Some(input) = obj.get_mut("input").and_then(Value::as_array_mut) else {
        return;
    };

    let mut system_text = Vec::new();
    let mut remaining = Vec::with_capacity(input.len());
    for item in std::mem::take(input) {
        let is_system = item
            .as_object()
            .map(|o| {
                let kind = o.get("type").and_then(Value::as_str);
                let role = o.get("role").and_then(Value::as_str);
                (kind == Some("message") || kind.is_none())
                    && (role == Some("system") || role == Some("developer"))
            })
            .unwrap_or(false);
        if is_system {
            if let Some(text) = item.get("content").and_then(content_value_to_string) {
                if !text.trim().is_empty() {
                    system_text.push(text);
                }
            }
        } else {
            remaining.push(item);
        }
    }
    *input = remaining;

    if system_text.is_empty() {
        return;
    }
    let mut parts = Vec::new();
    if let Some(existing) = obj.get("instructions").and_then(Value::as_str) {
        if !existing.trim().is_empty() {
            parts.push(existing.to_string());
        }
    }
    parts.extend(system_text);
    obj.insert(
        "instructions".to_string(),
        Value::String(parts.join("\n\n")),
    );
}

fn content_value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Array(parts) => {
            let mut out = String::new();
            for part in parts {
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    out.push_str(text);
                }
            }
            if out.is_empty() { None } else { Some(out) }
        }
        _ => None,
    }
}

fn json_array_len(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

/// Build a non-streaming Chat Completions JSON response from the translated
/// stream bytes.
fn non_streaming_response(sse_bytes: &[u8]) -> Json<serde_json::Value> {
    // Concatenate all `data:` JSON deltas into a single response.
    let mut content = String::new();
    let mut finish_reason = "stop".to_string();
    for line in std::str::from_utf8(sse_bytes).unwrap_or("").lines() {
        if let Some(rest) = line.strip_prefix("data: ") {
            if rest == "[DONE]" {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(rest) {
                if let Some(delta) = v
                    .get("choices")
                    .and_then(|c| c.get(0))
                    .and_then(|c| c.get("delta"))
                {
                    if let Some(t) = delta.get("content").and_then(|c| c.as_str()) {
                        content.push_str(t);
                    }
                }
                if let Some(fr) = v
                    .get("choices")
                    .and_then(|c| c.get(0))
                    .and_then(|c| c.get("finish_reason"))
                    .and_then(|c| c.as_str())
                {
                    finish_reason = fr.to_string();
                }
            }
        }
    }
    Json(serde_json::json!({
        "id": format!("chatcmpl-opensub-{}", chrono_id()),
        "object": "chat.completion",
        "created": now_ts(),
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": finish_reason,
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }))
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn chrono_id() -> String {
    use base64::Engine;
    let bytes: [u8; 12] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Error type that maps cleanly to HTTP responses.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("translate error: {0}")]
    Translate(#[source] anyhow::Error),
    #[error("auth error: {0}")]
    Auth(#[source] anyhow::Error),
    #[error("upstream error: {0}")]
    Upstream(#[source] anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (code, msg) = match &self {
            ApiError::Auth(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            ApiError::Upstream(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            ApiError::Translate(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        tracing::error!(err = %self, "chat completions error");
        (
            code,
            Json(serde_json::json!({
                "error": { "message": msg, "type": "opensub_error" }
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn responses_shaped_cursor_body_preserves_custom_tools() {
        let raw = json!({
            "model": "gpt-5.5-extra",
            "stream": true,
            "input": [
                {
                    "type": "message",
                    "role": "system",
                    "content": [{"type": "input_text", "text": "Be precise."}]
                },
                {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "Edit the file."}]
                }
            ],
            "tools": [
                {
                    "type": "custom",
                    "name": "ApplyPatch",
                    "description": "Apply a patch",
                    "format": {"type": "grammar", "syntax": "lark", "definition": "start: /.+/"}
                }
            ],
            "prompt_cache_key": "cursor-session"
        });

        let prepared = prepare_upstream_body(raw).unwrap();

        assert_eq!(prepared.model, "gpt-5.5");
        assert_eq!(prepared.body["model"], "gpt-5.5");
        assert_eq!(prepared.body["instructions"], "Be precise.");
        assert_eq!(prepared.body["input"].as_array().unwrap().len(), 1);
        assert_eq!(prepared.body["tools"][0]["type"], "custom");
        assert_eq!(prepared.body["prompt_cache_key"], "cursor-session");
        assert_eq!(prepared.body["parallel_tool_calls"], true);
        assert_eq!(prepared.body["store"], false);
        assert!(
            prepared.body["include"]
                .as_array()
                .unwrap()
                .contains(&json!("reasoning.encrypted_content"))
        );
    }
}
