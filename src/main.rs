//! OpenSub — a lightweight OpenAI-compatible proxy that routes to Codex using
//! your ChatGPT subscription.

mod api;
mod auth;
mod codex;
mod config;
mod cursor_agent;
mod cursor_proxy;
mod translate;
mod types;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "opensub",
    version,
    about = "OpenAI-compatible API that routes to Codex via your ChatGPT subscription",
    long_about = "OpenSub routes OpenAI model requests to the Codex backend, authenticated\nwith your ChatGPT (Plus/Pro) subscription via OAuth.\n\nFor transparent Cursor routing on macOS, run:\n  opensub cursor proxy\n\nOpenSub restarts Cursor automatically when needed. No Cursor API key or\nbase URL override is required."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Sign in with ChatGPT (opens a browser).
    Login,
    /// Sign out and delete stored tokens.
    Logout,
    /// Show or rotate your API key.
    Key {
        #[command(subcommand)]
        command: Option<KeyCommand>,
    },
    /// Route selected official Cursor model traffic through OpenSub.
    Cursor {
        #[command(subcommand)]
        command: Option<CursorCommand>,
    },
    /// Probe the configured upstream with a minimal request (for debugging).
    Probe,
    /// Start the OpenAI-compatible API server (and optionally a public tunnel).
    Serve {
        /// Port to listen on (default: OPENSUB_PORT or 8788).
        #[arg(long)]
        port: Option<u16>,
        /// Host to bind (default: OPENSUB_HOST or 127.0.0.1).
        #[arg(long)]
        host: Option<String>,
        /// Start a Cloudflare quick tunnel so Cursor (which blocks private
        /// networks) can reach the server over a public HTTPS URL.
        #[arg(long)]
        tunnel: bool,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Show your current API key.
    Show,
    /// Generate and persist a new API key.
    Rotate,
}

#[derive(Subcommand)]
enum CursorCommand {
    /// Launch the official Cursor through OpenSub's selective local proxy.
    Proxy {
        /// Save the latest Agent request for protocol analysis. The capture may
        /// contain prompt context and is stored locally with mode 0600.
        #[arg(long)]
        capture_protocol: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("opensub=info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        None => {
            // Default: login if not authenticated, otherwise serve.
            if auth::is_logged_in() {
                serve(None, None, false).await
            } else {
                auth::login().await
            }
        }
        Some(Command::Login) => auth::login().await,
        Some(Command::Logout) => auth::logout(),
        Some(Command::Key { command }) => key_command(command),
        Some(Command::Cursor { command }) => cursor_command(command).await,
        Some(Command::Probe) => {
            let tokens = auth::require_token().await?;
            codex::client::probe(&tokens).await
        }
        Some(Command::Serve { port, host, tunnel }) => serve(port, host, tunnel).await,
    }
}

async fn cursor_command(command: Option<CursorCommand>) -> Result<()> {
    match command.unwrap_or(CursorCommand::Proxy {
        capture_protocol: false,
    }) {
        CursorCommand::Proxy { capture_protocol } => cursor_proxy::run(capture_protocol).await,
    }
}

fn key_command(command: Option<KeyCommand>) -> Result<()> {
    match command.unwrap_or(KeyCommand::Show) {
        KeyCommand::Show => {
            println!("→ API key: {}", config::api_key());
            println!("  Use this as the 'OpenAI API Key' in Cursor.");
        }
        KeyCommand::Rotate => {
            if std::env::var_os("OPENSUB_API_KEY").is_some() {
                anyhow::bail!(
                    "OPENSUB_API_KEY is set, so ~/.opensub/api_key is ignored. \
                     Change OPENSUB_API_KEY or unset it before rotating the persisted key."
                );
            }
            let key = config::rotate_api_key()?;
            println!("→ New API key: {key}");
            println!("  Update Cursor's 'OpenAI API Key' with this value.");
            println!("  Restart any running OpenSub server so it uses the new key.");
        }
    }
    Ok(())
}

async fn serve(port: Option<u16>, host: Option<String>, tunnel: bool) -> Result<()> {
    if !auth::is_logged_in() {
        anyhow::bail!("not logged in — run `opensub login` first");
    }

    let host = host.unwrap_or_else(config::host);
    let port = port.unwrap_or_else(config::port);
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address {host}:{port}: {e}"))?;

    // Ensure an API key exists and surface it (required now that auth is enforced).
    let api_key = config::api_key();

    let app = api::router();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("→ OpenSub listening on http://{}", addr);
    println!("→ Upstream: {}", config::upstream());
    println!("→ API key: {api_key}");
    println!("  (set this as the 'OpenAI API Key' in Cursor)");

    let _tunnel = if tunnel {
        // Spawn a Cloudflare quick tunnel pointing at the local port. Cursor
        // blocks private-network addresses, so a public HTTPS URL is required.
        Some(start_cloudflare_tunnel(port)?)
    } else {
        println!("\n  NOTE: Cursor blocks private networks. For Cursor to reach");
        println!("  this server, run with --tunnel (needs `cloudflared`) or");
        println!("  expose it another way.");
        None
    };
    println!("→ Ctrl-C to stop.\n");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    println!("\n→ stopped.");
    Ok(())
}

struct TunnelGuard {
    child: Arc<Mutex<Option<Child>>>,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            if let Some(child) = child.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            *child = None;
        }
    }
}

fn start_cloudflare_tunnel(port: u16) -> Result<TunnelGuard> {
    println!("→ Cloudflare tunnel: starting...");
    let mut child = ProcessCommand::new("cloudflared")
        .arg("tunnel")
        .arg("--url")
        .arg(format!("http://localhost:{port}"))
        .arg("--metrics")
        .arg("127.0.0.1:8789")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to start cloudflared: {e}\ninstall it with: brew install cloudflared"
            )
        })?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let child = Arc::new(Mutex::new(Some(child)));
    let (tx, rx) = std::sync::mpsc::channel::<TunnelEvent>();

    if let Some(stdout) = stdout {
        drain_cloudflared_output(stdout, tx.clone());
    }
    if let Some(stderr) = stderr {
        drain_cloudflared_output(stderr, tx.clone());
    }
    watch_cloudflared_exit(Arc::clone(&child), tx);

    std::thread::spawn(move || {
        let mut printed_url = false;
        for event in rx {
            match event {
                TunnelEvent::Url(url) if !printed_url => {
                    printed_url = true;
                    println!("→ Tunnel URL:      {url}");
                    println!("→ Cursor Base URL: {url}/v1");
                }
                TunnelEvent::Exited(code) if !printed_url => {
                    eprintln!("→ Cloudflare tunnel stopped before publishing a URL ({code}).");
                }
                TunnelEvent::Exited(_) => break,
                TunnelEvent::Url(_) => {}
            }
        }
    });

    Ok(TunnelGuard { child })
}

enum TunnelEvent {
    Url(String),
    Exited(String),
}

fn drain_cloudflared_output<R>(reader: R, tx: std::sync::mpsc::Sender<TunnelEvent>)
where
    R: std::io::Read + Send + 'static,
{
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(|line| line.ok()) {
            if let Some(url) = extract_trycloudflare_url(&line) {
                let _ = tx.send(TunnelEvent::Url(url));
            }
        }
    });
}

fn watch_cloudflared_exit(
    child: Arc<Mutex<Option<Child>>>,
    tx: std::sync::mpsc::Sender<TunnelEvent>,
) {
    std::thread::spawn(move || {
        loop {
            let status = match child.lock() {
                Ok(mut child) => match child.as_mut() {
                    Some(child) => child.try_wait(),
                    None => return,
                },
                Err(_) => return,
            };
            match status {
                Ok(Some(status)) => {
                    let code = status
                        .code()
                        .map(|code| format!("exit code {code}"))
                        .unwrap_or_else(|| "terminated by signal".to_string());
                    let _ = tx.send(TunnelEvent::Exited(code));
                    return;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(250)),
                Err(e) => {
                    let _ = tx.send(TunnelEvent::Exited(format!("wait failed: {e}")));
                    return;
                }
            }
        }
    });
}

fn extract_trycloudflare_url(line: &str) -> Option<String> {
    line.split_whitespace()
        .find(|part| part.starts_with("https://") && part.contains(".trycloudflare.com"))
        .map(|url| {
            url.trim_matches(|c: char| {
                matches!(
                    c,
                    '"' | '\'' | '`' | ',' | '.' | ';' | ')' | '(' | '[' | ']'
                )
            })
            .trim_end_matches('/')
            .to_string()
        })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("installed ctrl-c handler");
    };

    #[cfg(unix)]
    let sigterm = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = sigterm => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_trycloudflare_url_from_noisy_log_line() {
        let line = "INF +--------------------------------------------------------------------------------------------+ https://quiet-lake.trycloudflare.com";

        assert_eq!(
            extract_trycloudflare_url(line).as_deref(),
            Some("https://quiet-lake.trycloudflare.com")
        );
    }

    #[test]
    fn ignores_non_tunnel_urls() {
        assert!(
            extract_trycloudflare_url("metrics server listening on http://127.0.0.1:8789")
                .is_none()
        );
    }
}
