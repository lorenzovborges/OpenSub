//! Selective HTTPS proxy for the official Cursor application.
//!
//! Only Cursor's agent hosts are decrypted. Everything else stays inside a
//! normal CONNECT tunnel and is forwarded without inspection.

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::sync::{mpsc, mpsc::RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine;
use http_body_util::BodyExt;
use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::hyper::{Request, Response};
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use hudsucker::rustls::{self, ServerConfig, crypto::aws_lc_rs};
use hudsucker::{Body, HttpContext, HttpHandler, Proxy, RequestOrResponse};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio_rustls::TlsAcceptor;

use crate::config;

const CURSOR_APP: &str = "/Applications/Cursor.app";
const CA_CERT_NAME: &str = "cursor-proxy-ca.pem";
const CA_KEY_NAME: &str = "cursor-proxy-ca-key.pem";
const CURSOR_SETTINGS_BACKUP_NAME: &str = "cursor-settings-backup.json";
const UNDICI_PRELOAD_NAME: &str = "undici-proxy-preload.cjs";
const MITMPROXY_ADDON_NAME: &str = "opensub_capture.py";
const UPSTREAM_CA_BUNDLE_NAME: &str = "upstream-ca-bundle.pem";

const MITMPROXY_ADDON: &str = r#"from mitmproxy import http
import json
import os
import re

CAPTURE = os.environ.get("OPENSUB_CAPTURE_PROTOCOL") == "1"
CAPTURE_PATH = os.environ.get("OPENSUB_CAPTURE_PATH", "")
BRIDGE_PORT = int(os.environ.get("OPENSUB_BRIDGE_PORT", "0"))
BRIDGE_SECRET = os.environ.get("OPENSUB_BRIDGE_SECRET", "")
MODEL_PATTERN = re.compile(br"gpt-[A-Za-z0-9_.-]+")


def running() -> None:
    print("OPENSUB_READY", flush=True)


def protocol_candidate(path: str) -> bool:
    path = path.lower()
    return "agent" in path or "composer" in path or ".aiservice/" in path


def should_capture(path: str, model: str | None) -> bool:
    operation = path.rsplit("/", 1)[-1].lower()
    return model is not None or any(
        token in operation
        for token in ("stream", "chat", "run", "generate", "complete")
    )


def write_capture(body: bytes) -> None:
    temporary = CAPTURE_PATH + ".tmp"
    descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as capture:
            capture.write(body)
            capture.flush()
            os.fsync(capture.fileno())
        os.replace(temporary, CAPTURE_PATH)
        os.chmod(CAPTURE_PATH, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def requestheaders(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host.lower().rstrip(".")
    if host != "cursor.sh" and not host.endswith(".cursor.sh"):
        return
    if flow.request.path != "/agent.v1.AgentService/Run" or CAPTURE:
        return

    flow.request.headers["x-opensub-original-host"] = host
    flow.request.headers["x-opensub-bridge-secret"] = BRIDGE_SECRET
    flow.request.scheme = "https"
    flow.request.host = "127.0.0.1"
    flow.request.port = BRIDGE_PORT
    flow.request.stream = True

    print("OPENSUB_EVENT\t" + json.dumps({
        "phase": "bridge",
        "host": host,
        "method": flow.request.method,
        "path": flow.request.path,
        "content_type": flow.request.headers.get("content-type", "unknown"),
        "content_length": flow.request.headers.get("content-length", "stream"),
        "http_version": flow.request.http_version,
        "model": None,
        "blocked": False,
    }, separators=(",", ":")), flush=True)


def responseheaders(flow: http.HTTPFlow) -> None:
    if (
        flow.request.path == "/agent.v1.AgentService/Run"
        and flow.request.headers.get("x-opensub-original-host")
    ):
        flow.response.stream = True


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host.lower().rstrip(".")
    if host != "cursor.sh" and not host.endswith(".cursor.sh"):
        return
    path = flow.request.path
    if not protocol_candidate(path):
        return

    body = flow.request.raw_content or b""
    match = MODEL_PATTERN.search(body)
    model = match.group(0).decode("ascii") if match else None
    blocked = CAPTURE and bool(body) and should_capture(path, model)
    if blocked:
        write_capture(body)
        flow.response = http.Response.make(
            502,
            b"OpenSub protocol capture completed",
            {"content-type": "text/plain"},
        )

    print("OPENSUB_EVENT\t" + json.dumps({
        "host": host,
        "method": flow.request.method,
        "path": path,
        "content_type": flow.request.headers.get("content-type", "unknown"),
        "bytes": len(body),
        "model": model,
        "blocked": blocked,
    }, separators=(",", ":")), flush=True)
"#;

#[derive(Clone, Default)]
struct CursorProxyHandler {
    announced_hosts: Arc<Mutex<HashSet<String>>>,
    capture_protocol: bool,
}

impl HttpHandler for CursorProxyHandler {
    async fn should_intercept_connect(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        let host = req
            .uri()
            .host()
            .or_else(|| req.uri().authority().map(|authority| authority.host()))
            .unwrap_or_default();
        let intercept = is_cursor_backend_host(host);
        if intercept
            && let Ok(mut announced) = self.announced_hosts.lock()
            && announced.insert(host.to_string())
        {
            println!("→ Intercepting Cursor backend: {host}");
        }
        intercept
    }

    async fn should_intercept_tls(
        &mut self,
        _ctx: &HttpContext,
        client_hello: hudsucker::rustls::server::ClientHello<'_>,
    ) -> bool {
        client_hello
            .server_name()
            .is_some_and(is_cursor_backend_host)
    }

    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        if req.method() == hudsucker::hyper::Method::CONNECT {
            return req.into();
        }

        let method = req.method().clone();
        let uri = req.uri().clone();
        if !is_protocol_candidate_path(uri.path()) {
            return req.into();
        }
        let content_type = req
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("unknown")
            .to_string();
        let (parts, body) = req.into_parts();
        match body.collect().await {
            Ok(collected) => {
                let bytes = collected.to_bytes();
                let detected_model = detect_model(&bytes);
                let model = detected_model.as_deref().unwrap_or("unknown");
                let captured = match capture_agent_request(
                    uri.path(),
                    &bytes,
                    detected_model.as_deref(),
                    self.capture_protocol,
                ) {
                    Ok(captured) => captured,
                    Err(error) => {
                        eprintln!("→ Failed to write requested protocol capture: {error}");
                        false
                    }
                };
                println!(
                    "→ Agent {} {} [{}; {} bytes; model={}]",
                    method,
                    uri.path(),
                    content_type,
                    bytes.len(),
                    model
                );
                if captured {
                    println!("→ Protocol captured locally; upstream request blocked.");
                    return Response::builder()
                        .status(502)
                        .body(Body::from("OpenSub protocol capture completed"))
                        .expect("static proxy response must be valid")
                        .into();
                }
                Request::from_parts(parts, Body::from(bytes)).into()
            }
            Err(error) => {
                eprintln!("→ Failed to inspect Cursor request {}: {error}", uri.path());
                Response::builder()
                    .status(502)
                    .body(Body::from("OpenSub could not inspect the Cursor request"))
                    .expect("static proxy response must be valid")
                    .into()
            }
        }
    }
}

pub async fn run(capture_protocol: bool) -> Result<()> {
    require_macos()?;
    require_official_cursor()?;
    require_mitmdump()?;
    if !crate::auth::is_logged_in() {
        bail!("not logged in - run `opensub login` first");
    }

    let (confdir, addon_path, cert_path, key_path, upstream_ca_bundle) =
        prepare_local_capture_files()?;
    let capture_path = protocol_capture_path();
    if capture_path.exists() {
        fs::remove_file(&capture_path)?;
    }

    let cursor_was_running = stop_cursor_if_running()?;
    let mut relaunch_guard = CursorRelaunchGuard::new(cursor_was_running, cert_path.clone());

    let bridge_secret =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let bridge_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let bridge_port = bridge_listener.local_addr()?.port();
    let bridge_listener = crate::cursor_agent::TlsListener::new(
        bridge_listener,
        bridge_tls_acceptor(&cert_path, &key_path)?,
    );
    let bridge = crate::cursor_agent::router(crate::cursor_agent::BridgeState::new(
        bridge_secret.clone(),
    )?);
    let bridge_task = tokio::spawn(async move { axum::serve(bridge_listener, bridge).await });

    let (guard, events) = start_local_capture(
        &confdir,
        &addon_path,
        &capture_path,
        capture_protocol,
        bridge_port,
        &bridge_secret,
        &upstream_ca_bundle,
    )?;
    wait_for_local_capture(&events)?;
    launch_cursor_direct(&cert_path)?;
    relaunch_guard.disarm();

    println!("→ Cursor traffic capture: active");
    println!("→ Official Cursor launched; only Cursor processes are captured.");
    println!("→ Non-Cursor applications are not routed through OpenSub.");
    println!(
        "→ Bridge events: {}",
        crate::cursor_agent::event_log_path().display()
    );
    if capture_protocol {
        println!("→ GPT protocol requests are captured locally and blocked upstream.");
        println!("→ Protocol capture: {}", capture_path.display());
    }
    println!("→ Ctrl-C stops the capture.\n");

    let exit_wait = tokio::task::spawn_blocking(move || events.recv());
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        event = exit_wait => {
            match event {
                Ok(Ok(LocalCaptureEvent::Exited(code))) => {
                    bail!("local capture stopped unexpectedly ({code})");
                }
                Ok(Ok(LocalCaptureEvent::Ready)) => {
                    bail!("local capture emitted an unexpected duplicate ready event");
                }
                Ok(Err(_)) | Err(_) => {
                    bail!("lost contact with the local capture process");
                }
            }
        }
    }
    drop(guard);
    bridge_task.abort();
    println!("\n→ Cursor traffic capture stopped.");
    Ok(())
}

#[allow(dead_code)]
async fn run_explicit_proxy(port: u16, capture_protocol: bool) -> Result<()> {
    require_macos()?;
    require_official_cursor()?;
    if !crate::auth::is_logged_in() {
        bail!("not logged in - run `opensub login` first");
    }

    let (cert_path, key_path) = ensure_proxy_ca()?;
    let cursor_was_running = stop_cursor_if_running()?;
    let mut relaunch_guard = CursorRelaunchGuard::new(cursor_was_running, cert_path.clone());
    let cert_pem = fs::read_to_string(&cert_path)
        .with_context(|| format!("failed to read {}", cert_path.display()))?;
    let key_pem = fs::read_to_string(&key_path)
        .with_context(|| format!("failed to read {}", key_path.display()))?;
    let key_pair = KeyPair::from_pem(&key_pem).context("invalid OpenSub proxy CA key")?;
    let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)
        .context("invalid OpenSub proxy CA certificate")?;
    let ca = RcgenAuthority::new(issuer, 128, aws_lc_rs::default_provider());

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind Cursor proxy at {addr}"))?;
    let spki = certificate_spki_hash(&cert_path)?;
    let preload_path = ensure_undici_preload(port)?;
    if capture_protocol {
        let capture_path = protocol_capture_path();
        if capture_path.exists() {
            fs::remove_file(&capture_path)?;
        }
    }

    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(CursorProxyHandler {
            capture_protocol,
            ..CursorProxyHandler::default()
        })
        .with_graceful_shutdown(shutdown_signal())
        .build()
        .context("failed to create Cursor proxy")?;

    let settings_guard = CursorSettingsGuard::apply(port)?;
    launch_cursor(port, &spki, &cert_path, &preload_path)?;
    relaunch_guard.disarm();
    println!("→ Cursor proxy listening on http://{addr}");
    println!("→ Official Cursor launched; GPT routing discovery is active.");
    println!("→ Other Cursor traffic is passed through without inspection.");
    if capture_protocol {
        println!(
            "→ Protocol capture: {}",
            config::data_dir()
                .join("cursor-proxy")
                .join("last-agent-request.bin")
                .display()
        );
    }
    println!("→ Ctrl-C stops the proxy.\n");

    let proxy_result = proxy
        .start()
        .await
        .context("Cursor proxy stopped unexpectedly");
    let restore_result = settings_guard.restore();
    proxy_result.and(restore_result)
}

enum LocalCaptureEvent {
    Ready,
    Exited(String),
}

struct LocalCaptureGuard {
    child: Arc<Mutex<Option<Child>>>,
}

impl Drop for LocalCaptureGuard {
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

fn require_mitmdump() -> Result<()> {
    let status = Command::new("mitmdump")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if status.is_ok_and(|status| status.success()) {
        Ok(())
    } else {
        bail!(
            "mitmdump is required for process-level Cursor capture; install it with \
             `brew install --cask mitmproxy`"
        )
    }
}

fn prepare_local_capture_files() -> Result<(PathBuf, PathBuf, PathBuf, PathBuf, PathBuf)> {
    let (cert_path, key_path) = ensure_proxy_ca()?;
    ensure_proxy_ca_trusted(&cert_path)?;
    let dir = config::data_dir().join("cursor-proxy").join("mitmproxy");
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;

    let cert = fs::read(&cert_path)?;
    let key = fs::read(&key_path)?;
    let mut combined = key;
    if !combined.ends_with(b"\n") {
        combined.push(b'\n');
    }
    combined.extend_from_slice(&cert);
    replace_file(&dir.join("mitmproxy-ca.pem"), &combined, 0o600)?;
    replace_file(&dir.join("mitmproxy-ca-cert.pem"), &cert, 0o600)?;

    let addon_path = dir.join(MITMPROXY_ADDON_NAME);
    replace_file(&addon_path, MITMPROXY_ADDON.as_bytes(), 0o600)?;
    let upstream_ca_bundle = dir.join(UPSTREAM_CA_BUNDLE_NAME);
    write_upstream_ca_bundle(&upstream_ca_bundle, &cert)?;
    Ok((dir, addon_path, cert_path, key_path, upstream_ca_bundle))
}

fn write_upstream_ca_bundle(path: &Path, opensub_ca: &[u8]) -> Result<()> {
    let roots = Command::new("security")
        .args([
            "find-certificate",
            "-a",
            "-p",
            "/System/Library/Keychains/SystemRootCertificates.keychain",
        ])
        .output()
        .context("failed to read macOS system root certificates")?;
    if !roots.status.success() || roots.stdout.is_empty() {
        bail!("macOS did not provide its system root certificates");
    }
    let mut bundle = roots.stdout;
    if !bundle.ends_with(b"\n") {
        bundle.push(b'\n');
    }
    bundle.extend_from_slice(opensub_ca);
    replace_file(path, &bundle, 0o600)
}

fn bridge_tls_acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor> {
    let ca_cert = fs::read_to_string(cert_path)
        .with_context(|| format!("failed to read {}", cert_path.display()))?;
    let ca_key = fs::read_to_string(key_path)
        .with_context(|| format!("failed to read {}", key_path.display()))?;
    let ca_key = KeyPair::from_pem(&ca_key).context("invalid OpenSub proxy CA key")?;
    let issuer = Issuer::from_ca_cert_pem(&ca_cert, ca_key)
        .context("invalid OpenSub proxy CA certificate")?;

    let leaf_key = KeyPair::generate().context("failed to generate local bridge TLS key")?;
    let mut params = CertificateParams::new(vec!["127.0.0.1".to_string()])?;
    params
        .distinguished_name
        .push(DnType::CommonName, "OpenSub Cursor Bridge");
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let leaf = params
        .signed_by(&leaf_key, &issuer)
        .context("failed to sign local bridge TLS certificate")?;

    let provider = Arc::new(aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], leaf_key.into())?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn ensure_proxy_ca_trusted(cert_path: &Path) -> Result<()> {
    let keychain = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")?
        .join("Library/Keychains/login.keychain-db");
    if proxy_ca_is_trusted(cert_path, &keychain)? {
        return Ok(());
    }

    println!("→ Trusting the OpenSub local capture certificate...");
    let status = Command::new("security")
        .args(["add-trusted-cert", "-r", "trustRoot", "-k"])
        .arg(&keychain)
        .arg(cert_path)
        .status()?;
    if status.success() && proxy_ca_is_trusted(cert_path, &keychain)? {
        Ok(())
    } else {
        bail!("macOS did not trust the OpenSub local capture certificate")
    }
}

fn proxy_ca_is_trusted(cert_path: &Path, keychain: &Path) -> Result<bool> {
    let fingerprint = certificate_sha256_fingerprint(cert_path)?;
    let installed = Command::new("security")
        .args(["find-certificate", "-a", "-c", "OpenSub Cursor Proxy", "-Z"])
        .arg(keychain)
        .output()
        .context("failed to inspect the macOS login keychain")?;
    if !installed.status.success()
        || !String::from_utf8_lossy(&installed.stdout).contains(&fingerprint)
    {
        return Ok(false);
    }

    let trust = Command::new("security")
        .arg("dump-trust-settings")
        .output()
        .context("failed to inspect macOS user trust settings")?;
    Ok(trust.status.success()
        && String::from_utf8_lossy(&trust.stdout).contains("OpenSub Cursor Proxy"))
}

fn certificate_sha256_fingerprint(cert_path: &Path) -> Result<String> {
    let output = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(cert_path)
        .args(["-noout", "-fingerprint", "-sha256"])
        .output()
        .context("failed to fingerprint the OpenSub proxy CA")?;
    if !output.status.success() {
        bail!("openssl could not fingerprint the OpenSub proxy CA");
    }

    let fingerprint = String::from_utf8_lossy(&output.stdout)
        .split_once('=')
        .map(|(_, value)| value.trim().replace(':', ""))
        .filter(|value| !value.is_empty())
        .context("openssl returned an invalid proxy CA fingerprint")?;
    Ok(fingerprint)
}

fn start_local_capture(
    confdir: &Path,
    addon_path: &Path,
    capture_path: &Path,
    capture_protocol: bool,
    bridge_port: u16,
    bridge_secret: &str,
    upstream_ca_bundle: &Path,
) -> Result<(LocalCaptureGuard, mpsc::Receiver<LocalCaptureEvent>)> {
    let process_filter = "local:Cursor,Cursor Helper,Cursor Helper (Plugin)";
    let mut child = Command::new("mitmdump")
        .args(["--mode", process_filter])
        .args(["--allow-hosts", r"(^|\.)cursor\.sh:443$"])
        .arg("--set")
        .arg(format!("confdir={}", confdir.display()))
        .args(["--set", "flow_detail=0"])
        .args(["--set", "termlog_verbosity=info"])
        .args(["--set", "block_global=false"])
        .args(["--set", "connection_strategy=lazy"])
        .arg("--set")
        .arg(format!(
            "ssl_verify_upstream_trusted_ca={}",
            upstream_ca_bundle.display()
        ))
        .args(["--scripts"])
        .arg(addon_path)
        .env(
            "OPENSUB_CAPTURE_PROTOCOL",
            if capture_protocol { "1" } else { "0" },
        )
        .env("OPENSUB_CAPTURE_PATH", capture_path)
        .env("OPENSUB_BRIDGE_PORT", bridge_port.to_string())
        .env("OPENSUB_BRIDGE_SECRET", bridge_secret)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to start mitmdump local capture")?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let child = Arc::new(Mutex::new(Some(child)));
    let (events_tx, events_rx) = mpsc::channel();
    let ready_sent = Arc::new(AtomicBool::new(false));
    if let Some(stdout) = stdout {
        drain_local_capture_output(stdout, events_tx.clone(), Arc::clone(&ready_sent));
    }
    if let Some(stderr) = stderr {
        drain_local_capture_output(stderr, events_tx.clone(), ready_sent);
    }
    watch_local_capture_exit(Arc::clone(&child), events_tx);
    Ok((LocalCaptureGuard { child }, events_rx))
}

fn drain_local_capture_output<R>(
    reader: R,
    events: mpsc::Sender<LocalCaptureEvent>,
    ready_sent: Arc<AtomicBool>,
) where
    R: std::io::Read + Send + 'static,
{
    thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if (line.contains("Local redirector started") || line.contains("OPENSUB_READY"))
                && !ready_sent.swap(true, Ordering::SeqCst)
            {
                let _ = events.send(LocalCaptureEvent::Ready);
            }
            if let Some(event) = line.split("OPENSUB_EVENT\t").nth(1) {
                print_local_capture_event(event);
            }
        }
    });
}

fn print_local_capture_event(raw: &str) {
    let Ok(event) = serde_json::from_str::<serde_json::Value>(raw) else {
        return;
    };
    let method = event["method"].as_str().unwrap_or("?");
    let path = event["path"].as_str().unwrap_or("?");
    if event["phase"].as_str() == Some("bridge") {
        let content_length = event["content_length"].as_str().unwrap_or("stream");
        let http_version = event["http_version"].as_str().unwrap_or("unknown");
        println!(
            "→ Agent bridge {method} {path} [content-length={content_length}; {http_version}]"
        );
        return;
    }
    let bytes = event["bytes"].as_u64().unwrap_or_default();
    let model = event["model"].as_str().unwrap_or("unknown");
    println!("→ Agent {method} {path} [{bytes} bytes; model={model}]");
    if event["blocked"].as_bool() == Some(true) {
        println!("→ Protocol captured locally; upstream request blocked.");
    }
}

fn watch_local_capture_exit(
    child: Arc<Mutex<Option<Child>>>,
    events: mpsc::Sender<LocalCaptureEvent>,
) {
    thread::spawn(move || {
        loop {
            let status = {
                let Ok(mut child) = child.lock() else {
                    return;
                };
                let Some(child) = child.as_mut() else {
                    return;
                };
                child.try_wait()
            };
            match status {
                Ok(Some(status)) => {
                    let _ = events.send(LocalCaptureEvent::Exited(status.to_string()));
                    return;
                }
                Ok(None) => thread::sleep(Duration::from_millis(100)),
                Err(error) => {
                    let _ = events.send(LocalCaptureEvent::Exited(error.to_string()));
                    return;
                }
            }
        }
    });
}

fn wait_for_local_capture(events: &mpsc::Receiver<LocalCaptureEvent>) -> Result<()> {
    match events.recv_timeout(Duration::from_secs(45)) {
        Ok(LocalCaptureEvent::Ready) => Ok(()),
        Ok(LocalCaptureEvent::Exited(code)) => {
            bail!("local capture stopped during startup ({code})")
        }
        Err(RecvTimeoutError::Timeout) => {
            bail!("timed out waiting for the macOS local capture redirector")
        }
        Err(RecvTimeoutError::Disconnected) => {
            bail!("lost contact with the local capture process during startup")
        }
    }
}

fn launch_cursor_direct(cert_path: &Path) -> Result<()> {
    let extra_ca = format!("NODE_EXTRA_CA_CERTS={}", cert_path.display());
    let output = Command::new("open")
        .arg("-n")
        .args(["--env", &extra_ca])
        .arg(CURSOR_APP)
        .output()
        .context("failed to launch official Cursor")?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "failed to launch official Cursor: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}

#[derive(Serialize, Deserialize)]
struct CursorSettingsBackup {
    existed: bool,
    mode: u32,
    contents_base64: String,
}

struct CursorSettingsGuard {
    settings_path: PathBuf,
    backup_path: PathBuf,
    restored: bool,
}

impl CursorSettingsGuard {
    fn apply(port: u16) -> Result<Self> {
        let settings_path = cursor_settings_path()?;
        let backup_path = config::data_dir()
            .join("cursor-proxy")
            .join(CURSOR_SETTINGS_BACKUP_NAME);
        if backup_path.exists() {
            restore_cursor_settings(&settings_path, &backup_path)
                .context("failed to recover Cursor settings from a previous proxy run")?;
        }

        let existed = settings_path.exists();
        let original = if existed {
            fs::read(&settings_path)
                .with_context(|| format!("failed to read {}", settings_path.display()))?
        } else {
            b"{}\n".to_vec()
        };
        let mode = if existed {
            fs::metadata(&settings_path)?.permissions().mode() & 0o777
        } else {
            0o600
        };
        let backup = CursorSettingsBackup {
            existed,
            mode,
            contents_base64: base64::engine::general_purpose::STANDARD.encode(&original),
        };
        write_private_file(&backup_path, &serde_json::to_vec_pretty(&backup)?)?;

        let patched = patch_cursor_settings(&original, port)?;
        if let Err(error) = replace_file(&settings_path, &patched, mode) {
            let _ = restore_cursor_settings(&settings_path, &backup_path);
            return Err(error);
        }

        Ok(Self {
            settings_path,
            backup_path,
            restored: false,
        })
    }

    fn restore(mut self) -> Result<()> {
        let result = restore_cursor_settings(&self.settings_path, &self.backup_path);
        self.restored = result.is_ok();
        result
    }
}

impl Drop for CursorSettingsGuard {
    fn drop(&mut self) {
        if !self.restored
            && let Err(error) = restore_cursor_settings(&self.settings_path, &self.backup_path)
        {
            eprintln!("→ Failed to restore Cursor proxy settings: {error}");
        }
    }
}

fn cursor_settings_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join("Library/Application Support/Cursor/User/settings.json"))
}

fn patch_cursor_settings(original: &[u8], port: u16) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(original).context("Cursor settings are not valid UTF-8")?;
    let mut value: serde_json::Value =
        jsonc_parser::parse_to_serde_value(text, &Default::default())
            .context("Cursor settings.json is not valid JSONC")?;
    let object = value
        .as_object_mut()
        .context("Cursor settings.json must contain a JSON object")?;
    object.insert(
        "http.proxy".to_string(),
        serde_json::Value::String(format!("http://127.0.0.1:{port}")),
    );
    object.insert(
        "http.proxySupport".to_string(),
        serde_json::Value::String("override".to_string()),
    );
    let mut output = serde_json::to_vec_pretty(&value)?;
    output.push(b'\n');
    Ok(output)
}

fn restore_cursor_settings(settings_path: &Path, backup_path: &Path) -> Result<()> {
    let backup: CursorSettingsBackup = serde_json::from_slice(
        &fs::read(backup_path)
            .with_context(|| format!("failed to read {}", backup_path.display()))?,
    )?;
    if backup.existed {
        let contents = base64::engine::general_purpose::STANDARD
            .decode(backup.contents_base64)
            .context("invalid Cursor settings backup")?;
        replace_file(settings_path, &contents, backup.mode)?;
    } else if settings_path.exists() {
        fs::remove_file(settings_path)?;
    }
    fs::remove_file(backup_path)?;
    Ok(())
}

fn replace_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("opensub-{}.tmp", std::process::id()));
    if temp.exists() {
        fs::remove_file(&temp)?;
    }
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .with_context(|| format!("failed to create {}", temp.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(mode))?;
    fs::rename(&temp, path)?;
    Ok(())
}

fn ensure_proxy_ca() -> Result<(PathBuf, PathBuf)> {
    let dir = config::data_dir().join("cursor-proxy");
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let cert_path = dir.join(CA_CERT_NAME);
    let key_path = dir.join(CA_KEY_NAME);
    if cert_path.exists() && key_path.exists() {
        return Ok((cert_path, key_path));
    }
    if cert_path.exists() || key_path.exists() {
        bail!(
            "incomplete Cursor proxy CA at {}; remove that directory and retry",
            dir.display()
        );
    }

    let key_pair = KeyPair::generate().context("failed to generate Cursor proxy CA key")?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "OpenSub Cursor Proxy");
    name.push(DnType::OrganizationName, "OpenSub");
    params.distinguished_name = name;
    let cert = params
        .self_signed(&key_pair)
        .context("failed to create Cursor proxy CA certificate")?;

    write_private_file(&key_path, key_pair.serialize_pem().as_bytes())?;
    write_private_file(&cert_path, cert.pem().as_bytes())?;
    Ok((cert_path, key_path))
}

fn ensure_undici_preload(port: u16) -> Result<PathBuf> {
    let path = config::data_dir()
        .join("cursor-proxy")
        .join(UNDICI_PRELOAD_NAME);
    let proxy_url = format!("http://127.0.0.1:{port}");
    let script = format!(
        r#"'use strict';
try {{
  const undici = require('/Applications/Cursor.app/Contents/Resources/app/node_modules/undici');
  undici.setGlobalDispatcher(new undici.EnvHttpProxyAgent({{
    httpProxy: {proxy},
    httpsProxy: {proxy},
    noProxy: '127.0.0.1,localhost,::1',
    allowH2: true
  }}));
}} catch (_) {{}}
"#,
        proxy = serde_json::to_string(&proxy_url)?
    );
    if path.exists() {
        fs::remove_file(&path)?;
    }
    write_private_file(&path, script.as_bytes())?;
    Ok(path)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn certificate_spki_hash(cert_path: &Path) -> Result<String> {
    let public_key = Command::new("openssl")
        .args(["x509", "-pubkey", "-noout", "-in"])
        .arg(cert_path)
        .output()
        .context("failed to run openssl while reading proxy CA")?;
    if !public_key.status.success() {
        bail!("openssl could not read the proxy CA certificate");
    }

    let mut der = Command::new("openssl")
        .args(["pkey", "-pubin", "-outform", "DER"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to run openssl while hashing proxy CA")?;
    der.stdin
        .take()
        .context("failed to open openssl stdin")?
        .write_all(&public_key.stdout)?;
    let der = der.wait_with_output()?;
    if !der.status.success() {
        bail!("openssl could not parse the proxy CA public key");
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(der.stdout)))
}

fn launch_cursor(port: u16, spki: &str, cert_path: &Path, preload_path: &Path) -> Result<()> {
    let proxy_url = format!("http://127.0.0.1:{port}");
    let proxy = format!("--proxy-server={proxy_url}");
    let trust = format!("--ignore-certificate-errors-spki-list={spki}");
    let https_proxy = format!("HTTPS_PROXY={proxy_url}");
    let http_proxy = format!("HTTP_PROXY={proxy_url}");
    let lower_https_proxy = format!("https_proxy={proxy_url}");
    let lower_http_proxy = format!("http_proxy={proxy_url}");
    let extra_ca = format!("NODE_EXTRA_CA_CERTS={}", cert_path.display());
    let preload_option = format!("--require={}", preload_path.display());
    let node_options = match std::env::var("NODE_OPTIONS") {
        Ok(existing) if !existing.trim().is_empty() => {
            format!("NODE_OPTIONS={existing} {preload_option}")
        }
        _ => format!("NODE_OPTIONS={preload_option}"),
    };
    let output = Command::new("open")
        .arg("-n")
        .args(["--env", &https_proxy])
        .args(["--env", &http_proxy])
        .args(["--env", &lower_https_proxy])
        .args(["--env", &lower_http_proxy])
        .args(["--env", "NODE_USE_ENV_PROXY=1"])
        .args(["--env", &node_options])
        .args(["--env", &extra_ca])
        .args(["--env", "NO_PROXY=127.0.0.1,localhost,::1"])
        .args(["--env", "no_proxy=127.0.0.1,localhost,::1"])
        .args([CURSOR_APP, "--args"])
        .args([proxy.as_str(), trust.as_str()])
        .output()
        .context("failed to launch official Cursor")?;
    if !output.status.success() {
        bail!(
            "failed to launch official Cursor: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn detect_model(bytes: &[u8]) -> Option<String> {
    let start = bytes.windows(4).position(|window| window == b"gpt-")?;
    let slug = bytes[start..]
        .iter()
        .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        .copied()
        .collect::<Vec<_>>();
    String::from_utf8(slug).ok()
}

fn capture_agent_request(
    path: &str,
    bytes: &[u8],
    model: Option<&str>,
    enabled: bool,
) -> Result<bool> {
    if !enabled || bytes.is_empty() || !should_capture_protocol(path, model) {
        return Ok(false);
    }
    let path = protocol_capture_path();
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(true)
}

fn protocol_capture_path() -> PathBuf {
    config::data_dir()
        .join("cursor-proxy")
        .join("last-agent-request.bin")
}

fn should_capture_protocol(path: &str, model: Option<&str>) -> bool {
    let path = path.to_ascii_lowercase();
    path.contains("agent") || path.contains("composer") || model.is_some()
}

fn is_protocol_candidate_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.contains("agent") || path.contains("composer") || path.contains(".aiservice/")
}

fn is_cursor_backend_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    matches!(
        host.as_str(),
        "api2.cursor.sh" | "api3.cursor.sh" | "api4.cursor.sh" | "api5.cursor.sh"
    ) || host == "agent.api5.cursor.sh"
        || (host.starts_with("agent-") && host.ends_with(".api5.cursor.sh"))
        || (host.starts_with("agentn-") && host.ends_with(".api5.cursor.sh"))
        || host == "agentn.api5.cursor.sh"
}

fn require_macos() -> Result<()> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        bail!("`opensub cursor proxy` is currently supported only on macOS")
    }
}

fn require_official_cursor() -> Result<()> {
    if Path::new(CURSOR_APP).exists() {
        Ok(())
    } else {
        bail!("official Cursor installation not found at {CURSOR_APP}")
    }
}

fn cursor_is_running() -> bool {
    Command::new("pgrep")
        .args(["-x", "Cursor"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn stop_cursor_if_running() -> Result<bool> {
    if !cursor_is_running() {
        return Ok(false);
    }

    println!("→ Restarting Cursor to activate traffic capture…");
    let status = Command::new("osascript")
        .args(["-e", "tell application \"Cursor\" to quit"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to request a graceful Cursor restart")?;
    if !status.success() {
        bail!("Cursor refused the restart request; quit it once and retry");
    }

    let deadline = Instant::now() + Duration::from_secs(30);
    while cursor_is_running() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    if cursor_is_running() {
        bail!("Cursor did not finish closing within 30 seconds");
    }
    Ok(true)
}

struct CursorRelaunchGuard {
    cursor_was_running: bool,
    cert_path: PathBuf,
}

impl CursorRelaunchGuard {
    fn new(cursor_was_running: bool, cert_path: PathBuf) -> Self {
        Self {
            cursor_was_running,
            cert_path,
        }
    }

    fn disarm(&mut self) {
        self.cursor_was_running = false;
    }
}

impl Drop for CursorRelaunchGuard {
    fn drop(&mut self) {
        if self.cursor_was_running {
            let _ = launch_cursor_direct(&self.cert_path);
        }
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intercepts_only_cursor_backend_hosts() {
        assert!(is_cursor_backend_host("api2.cursor.sh"));
        assert!(is_cursor_backend_host("api4.cursor.sh"));
        assert!(is_cursor_backend_host("agent.api5.cursor.sh"));
        assert!(is_cursor_backend_host("agent-gcpp-uswest.api5.cursor.sh"));
        assert!(is_cursor_backend_host(
            "agentn-gcpp-eucentral.api5.cursor.sh"
        ));
        assert!(!is_cursor_backend_host("authentication.cursor.sh"));
        assert!(!is_cursor_backend_host("example.com"));
    }

    #[test]
    fn detects_dynamic_gpt_model_names() {
        assert_eq!(
            detect_model(b"prefix gpt-5.6-sol-none\0suffix"),
            Some("gpt-5.6-sol-none".to_string())
        );
        assert_eq!(detect_model(b"composer-2"), None);
    }

    #[test]
    fn buffers_only_protocol_candidate_requests() {
        assert!(is_protocol_candidate_path("/aiserver.v1.AgentService/Run"));
        assert!(is_protocol_candidate_path(
            "/aiserver.v1.BackgroundComposerService/Start"
        ));
        assert!(is_protocol_candidate_path(
            "/aiserver.v1.AiService/StreamChat"
        ));
        assert!(!is_protocol_candidate_path(
            "/aiserver.v1.CodebaseSnapshotService/UploadPackfileChunk"
        ));
    }

    #[test]
    fn patches_jsonc_cursor_proxy_settings() {
        let patched = patch_cursor_settings(
            br#"{
                // Cursor settings may contain comments and trailing commas.
                "window.autoDetectColorScheme": true,
            }"#,
            9876,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&patched).unwrap();
        assert_eq!(value["http.proxy"], "http://127.0.0.1:9876");
        assert_eq!(value["http.proxySupport"], "override");
        assert_eq!(value["window.autoDetectColorScheme"], true);
    }

    #[test]
    fn telemetry_does_not_replace_protocol_capture() {
        assert!(!should_capture_protocol(
            "/aiserver.v1.AiService/ReportClientNumericMetrics",
            None
        ));
        assert!(should_capture_protocol(
            "/aiserver.v1.AgentService/Run",
            None
        ));
        assert!(should_capture_protocol(
            "/aiserver.v1.AiService/StreamChat",
            Some("gpt-5.6-sol-none")
        ));
    }

    #[test]
    fn local_capture_streams_agent_responses() {
        assert!(MITMPROXY_ADDON.contains("def responseheaders"));
        assert!(MITMPROXY_ADDON.contains("flow.response.stream = True"));
    }
}
