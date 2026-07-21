//! Client that posts to the Codex `/responses` endpoint and returns the SSE stream.

use anyhow::{Context, Result, bail};
use reqwest::Client;
use std::sync::OnceLock;

use crate::auth::store::TokenData;
use crate::config;
use crate::types::responses::ResponsesRequest;

/// A boxed byte-chunk stream from the upstream. `Item = Result<Bytes, reqwest::Error>`.
pub type ByteStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send>>;

static CODEX_CLIENT: OnceLock<Client> = OnceLock::new();

fn codex_client() -> Result<&'static Client> {
    if let Some(client) = CODEX_CLIENT.get() {
        return Ok(client);
    }
    let client = Client::builder()
        .user_agent(config::codex_user_agent())
        .build()?;
    let _ = CODEX_CLIENT.set(client);
    Ok(CODEX_CLIENT
        .get()
        .expect("Codex client is initialized by this function"))
}

/// Open a streaming `POST {upstream}/responses` call and return the byte stream.
pub async fn post_responses_stream(
    tokens: &TokenData,
    body: &serde_json::Value,
) -> Result<ByteStream> {
    let client = codex_client()?;

    let upstream = config::validated_upstream()?;
    let url = format!("{}/responses", upstream.trim_end_matches('/'));
    let prompt_cache_key = body
        .get("prompt_cache_key")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| config::session_id());
    let req = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .header("Accept", "text/event-stream")
        .header("Content-Type", "application/json")
        .header("openai-beta", "responses=experimental")
        .header("session_id", prompt_cache_key)
        .header("x-codex-installation-id", config::session_id())
        .json(body);

    // ChatGPT backend (fallback upstream) requires extra identity headers.
    let req = if config::is_chatgpt_upstream_url(&upstream) {
        let mut h = req;
        if let Some(acct) = &tokens.account_id {
            h = h.header("chatgpt-account-id", acct);
        }
        h.header("originator", "codex_cli_rs")
    } else {
        req
    };

    let resp = req.send().await.context("POST /responses failed")?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        bail!("upstream returned {status}: {}", truncate(&text, 500));
    }
    tracing::debug!(status = %status, "stream opened from upstream");

    Ok(Box::pin(resp.bytes_stream()))
}

/// A cheap helper to format error bodies without dumping megabytes.
fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let mut end = n;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

/// Tiny diagnostic: probe whether the configured upstream accepts the token
/// with a minimal request. Used by `opensub probe`.
///
/// The ChatGPT/Codex backend requires `stream: true`, so this always streams
/// and prints the first chunk of SSE events.
pub async fn probe(tokens: &TokenData) -> Result<()> {
    let body = ResponsesRequest::new("gpt-5.5".to_string());
    // minimal input
    let mut body = body;
    body.instructions = "You are a test.".to_string();
    body.input = vec![crate::types::responses::ResponseInputItem::Message {
        kind: "message".to_string(),
        role: "user".to_string(),
        content: vec![crate::types::responses::MessageContent::input("ping")],
    }];
    body.stream = true; // the Codex backend rejects non-streaming requests

    let client = codex_client()?;
    let upstream = config::validated_upstream()?;
    let url = format!("{}/responses", upstream.trim_end_matches('/'));
    let body_json = serde_json::to_value(&body)?;
    let prompt_cache_key = body_json
        .get("prompt_cache_key")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| config::session_id());
    let mut req = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", tokens.access_token))
        .header("Accept", "text/event-stream")
        .header("Content-Type", "application/json")
        .header("openai-beta", "responses=experimental")
        .header("session_id", prompt_cache_key)
        .header("x-codex-installation-id", config::session_id())
        .json(&body_json);
    if config::is_chatgpt_upstream_url(&upstream) {
        if let Some(acct) = &tokens.account_id {
            req = req.header("chatgpt-account-id", acct);
        }
        req = req.header("originator", "codex_cli_rs");
    }
    let resp = req.send().await.context("probe request failed")?;
    println!("→ upstream: {}", upstream);
    println!(
        "→ account identity: {}",
        if tokens.account_id.is_some() {
            "available"
        } else {
            "unavailable"
        }
    );
    println!("→ status:   {}", resp.status());

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        println!("→ body:     {}", truncate(&text, 1000));
        return Ok(());
    }

    // Stream is open — read the first ~2KB of events as proof of life.
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                buf.extend_from_slice(&bytes);
                if buf.len() > 2048 {
                    break;
                }
            }
            Err(e) => {
                println!("→ stream error: {e}");
                break;
            }
        }
    }
    let text = String::from_utf8_lossy(&buf);
    println!("→ first events:\n{}", text.trim());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuses_one_codex_http_client() {
        let first = codex_client().unwrap();
        let second = codex_client().unwrap();
        assert!(std::ptr::eq(first, second));
    }
}
