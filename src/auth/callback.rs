//! Ephemeral localhost callback server for the OAuth redirect.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use axum::extract::Query;
use axum::response::Html;
use axum::routing::get;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Wait for the OAuth callback on `http://localhost:1455/auth/callback`,
/// returning `(code, state)`. Times out after 5 minutes.
pub async fn wait_for_code(expected_state: &str) -> Result<String> {
    let (tx, rx) = oneshot::channel::<Result<String>>();
    let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
    let expected_state = expected_state.to_string();

    // Bind first so the port is ready before we open the browser.
    let listener = TcpListener::bind(("127.0.0.1", crate::config::CALLBACK_PORT)).await?;

    let app = axum::Router::new().route(
        "/auth/callback",
        get(move |Query(params): Query<CallbackParams>| {
            let tx = tx.clone();
            let expected_state = expected_state.clone();
            async move {
                let result = match (params.code, params.error, params.state) {
                    (Some(code), _, Some(state)) if state == expected_state => Ok(code),
                    (_, Some(err), _) => Err(anyhow::anyhow!("auth error: {err}")),
                    (Some(_), _, Some(state)) => {
                        Err(anyhow::anyhow!("state mismatch (got {state})"))
                    }
                    _ => Err(anyhow::anyhow!("missing code in callback")),
                };
                // Send exactly once.
                if let Some(sender) = tx.lock().unwrap().take() {
                    let _ = sender.send(result);
                }
                Html(success_page())
            }
        }),
    );

    let server = axum::serve(listener, app);
    let serve_fut = tokio::time::timeout(Duration::from_secs(300), server);

    tokio::pin!(serve_fut);
    tokio::select! {
        // Result arrived — return it (the server task is dropped on return).
        res = rx => match res {
            Ok(Ok(code)) => Ok(code),
            Ok(Err(e)) => bail!(e),
            Err(_) => bail!("callback channel closed"),
        },
        // Server timed out or errored before a callback arrived.
        _ = &mut serve_fut => {
            bail!("timed out waiting for OAuth callback")
        }
    }
}

#[derive(Deserialize)]
struct CallbackParams {
    code: Option<String>,
    error: Option<String>,
    state: Option<String>,
}

fn success_page() -> String {
    r#"<!doctype html><html><head><meta charset="utf-8"><title>OpenSub</title>
<style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0d1117;color:#e6edf3}
.box{text-align:center;padding:2rem}h1{font-size:1.4rem}p{color:#8b949e}</style></head>
<body><div class="box"><h1>✅ Logged in</h1><p>You can close this tab and return to the terminal.</p></div></body></html>"#
        .to_string()
}
