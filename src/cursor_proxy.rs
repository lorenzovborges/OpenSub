//! Selective HTTPS proxy for the official Cursor application.
//!
//! Only Cursor's agent hosts are decrypted. Everything else stays inside a
//! normal CONNECT tunnel and is forwarded without inspection.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::sync::{mpsc, mpsc::RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::Engine;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, ServerConfig, crypto::ring},
};

use crate::config;

const CURSOR_APP: &str = "/Applications/Cursor.app";
const CA_CERT_NAME: &str = "cursor-proxy-ca.pem";
const CA_KEY_NAME: &str = "cursor-proxy-ca-key.pem";
const MITMPROXY_ADDON_NAME: &str = "opensub_capture.py";
const UPSTREAM_CA_BUNDLE_NAME: &str = "upstream-ca-bundle.pem";
const SERVICE_LABEL: &str = "com.opensub.cursor-proxy";
const SERVICE_PLIST_NAME: &str = "com.opensub.cursor-proxy.plist";
const SERVICE_STATE_NAME: &str = "service-state.json";
const SERVICE_LOG_NAME: &str = "service.log";
const SERVICE_ERROR_LOG_NAME: &str = "service-error.log";
const MAX_SERVICE_LOG_BYTES: u64 = 1024 * 1024;

const MITMPROXY_ADDON: &str = r#"from mitmproxy import http
import os

BRIDGE_PORT = int(os.environ.get("OPENSUB_BRIDGE_PORT", "0"))
BRIDGE_SECRET = os.environ.get("OPENSUB_BRIDGE_SECRET", "")


def running() -> None:
    print("OPENSUB_READY", flush=True)


def requestheaders(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host.lower().rstrip(".")
    if host != "cursor.sh" and not host.endswith(".cursor.sh"):
        return
    if flow.request.path != "/agent.v1.AgentService/Run":
        return

    flow.request.headers["x-opensub-original-host"] = host
    flow.request.headers["x-opensub-bridge-secret"] = BRIDGE_SECRET
    flow.request.scheme = "https"
    flow.request.host = "127.0.0.1"
    flow.request.port = BRIDGE_PORT
    flow.request.stream = True


def responseheaders(flow: http.HTTPFlow) -> None:
    if (
        flow.request.path == "/agent.v1.AgentService/Run"
        and flow.request.headers.get("x-opensub-original-host")
    ):
        flow.response.stream = True
"#;

#[derive(Serialize, Deserialize)]
struct CursorServiceState {
    pid: u32,
    ready_at_ms: u64,
}

pub async fn ensure_service() -> Result<()> {
    require_macos()?;
    require_official_cursor()?;
    let mitmdump = require_mitmdump()?;
    if !crate::auth::is_logged_in() {
        bail!("not logged in - run `opensub login` first");
    }

    let (_, _, cert_path, _, _) = prepare_local_capture_files()?;
    let executable = std::env::current_exe()
        .context("failed to locate the OpenSub executable")?
        .canonicalize()
        .context("failed to resolve the OpenSub executable")?;
    let plist = service_plist(&executable, &mitmdump)?;
    let plist_path = service_plist_path()?;
    set_service_enabled(true)?;
    let installed_current = fs::read(&plist_path).is_ok_and(|current| current == plist.as_bytes());
    let healthy = installed_current && service_is_loaded()? && service_is_ready();

    if healthy {
        println!("→ Cursor proxy service: active");
        println!("→ Starts automatically at login.");
        if !cursor_is_running() {
            launch_cursor_direct(&cert_path)?;
            println!("→ Official Cursor launched.");
        }
        return Ok(());
    }

    let cursor_was_running = cursor_is_running();
    let _ = stop_legacy_proxy_processes()?;
    bootout_service()?;
    remove_service_state_if_present()?;
    prepare_service_logs()?;
    replace_file(&plist_path, plist.as_bytes(), 0o600)?;
    validate_service_plist(&plist_path)?;
    bootstrap_service(&plist_path)?;
    wait_for_service_ready()?;

    if cursor_was_running {
        if refresh_cursor_network_service()? {
            println!("→ Cursor remained open; network connections refreshed.");
        } else {
            let cursor_stopped = stop_cursor_if_running()?;
            let mut relaunch_guard = CursorRelaunchGuard::new(cursor_stopped, cert_path.clone());
            launch_cursor_direct(&cert_path)?;
            relaunch_guard.disarm();
            println!("→ Official Cursor relaunched.");
        }
    } else {
        launch_cursor_direct(&cert_path)?;
        println!("→ Official Cursor launched.");
    }
    println!("→ Cursor proxy service: installed and active");
    println!("→ Starts automatically at login.");
    println!("→ No terminal needs to stay open.");
    Ok(())
}

pub fn service_status() -> Result<()> {
    require_macos()?;
    let installed = service_plist_path()?.exists();
    let loaded = service_is_loaded()?;
    let enabled = service_is_enabled()?;
    let ready = loaded && service_is_ready();
    println!(
        "→ Cursor proxy service: {}",
        if ready {
            "active"
        } else if loaded {
            "starting"
        } else if installed {
            "installed, stopped"
        } else {
            "not installed"
        }
    );
    if installed {
        if enabled {
            println!("→ Starts automatically at login.");
        } else {
            println!("→ Disabled until `opensub cursor proxy` is run.");
        }
        println!("→ Logs: {}", service_log_path().display());
    }
    Ok(())
}

pub fn service_stop() -> Result<()> {
    require_macos()?;
    bootout_service()?;
    remove_service_state_if_present()?;
    set_service_enabled(false)?;
    println!("→ Cursor proxy service stopped.");
    println!("→ Run `opensub cursor proxy` to start it again.");
    Ok(())
}

pub fn service_uninstall() -> Result<()> {
    require_macos()?;
    bootout_service()?;
    remove_service_state_if_present()?;
    remove_file_if_present(&service_plist_path()?)?;
    remove_file_if_present(&service_log_path())?;
    remove_file_if_present(&service_error_log_path())?;
    set_service_enabled(true)?;
    println!("→ Cursor proxy service uninstalled.");
    println!("→ OAuth tokens and the local CA were kept.");
    Ok(())
}

pub async fn run_diagnostic() -> Result<()> {
    require_macos()?;
    let restart_service = service_plist_path()?.exists();
    bootout_service()?;
    remove_service_state_if_present()?;
    let result = run_capture(true, true, false).await;
    if restart_service {
        let restart = ensure_service().await;
        result.and(restart)
    } else {
        result
    }
}

pub async fn run_service_worker() -> Result<()> {
    truncate_service_logs_if_oversized()?;
    run_capture(false, false, true).await
}

async fn run_capture(
    capture_protocol: bool,
    manage_cursor: bool,
    service_worker: bool,
) -> Result<()> {
    require_macos()?;
    require_official_cursor()?;
    let mitmdump = require_mitmdump()?;
    if !crate::auth::is_logged_in() {
        bail!("not logged in - run `opensub login` first");
    }

    let (confdir, addon_path, cert_path, key_path, upstream_ca_bundle) =
        prepare_local_capture_files()?;
    let capture_path = protocol_capture_path();
    if capture_path.exists() {
        fs::remove_file(&capture_path)?;
    }

    let cursor_was_running = manage_cursor && stop_cursor_if_running()?;
    let mut relaunch_guard = CursorRelaunchGuard::new(cursor_was_running, cert_path.clone());
    if manage_cursor {
        let _ = stop_legacy_proxy_processes()?;
    }

    let bridge_secret =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let bridge_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let bridge_port = bridge_listener.local_addr()?.port();
    let bridge_listener =
        crate::cursor_agent::TlsListener::new(bridge_listener, bridge_tls_acceptor(&key_path)?);
    let bridge = crate::cursor_agent::router(crate::cursor_agent::BridgeState::new(
        bridge_secret.clone(),
        capture_protocol,
    )?);
    let bridge_task = tokio::spawn(async move { axum::serve(bridge_listener, bridge).await });

    let (guard, events) = start_local_capture(LocalCaptureConfig {
        mitmdump: &mitmdump,
        confdir: &confdir,
        addon_path: &addon_path,
        bridge_port,
        bridge_secret: &bridge_secret,
        upstream_ca_bundle: &upstream_ca_bundle,
    })?;
    wait_for_local_capture(&events)?;
    let _service_ready = if service_worker {
        Some(ServiceReadyGuard::activate()?)
    } else {
        None
    };
    if manage_cursor {
        launch_cursor_direct(&cert_path)?;
        relaunch_guard.disarm();
    }

    println!("→ Cursor traffic capture: active");
    if manage_cursor {
        println!("→ Official Cursor launched; only Cursor processes are captured.");
        println!("→ Non-Cursor applications are not routed through OpenSub.");
    }
    println!(
        "→ Bridge events: {}",
        crate::cursor_agent::event_log_path().display()
    );
    if capture_protocol {
        println!("→ GPT protocol requests are captured locally and blocked upstream.");
        println!("→ Protocol capture: {}", capture_path.display());
    }
    if manage_cursor {
        println!("→ Ctrl-C stops the capture.\n");
    }

    let exit_wait = tokio::task::spawn_blocking(move || events.recv());
    tokio::select! {
        _ = shutdown_signal() => {}
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

enum LocalCaptureEvent {
    Ready,
    Exited(String),
}

struct LocalCaptureGuard {
    child: Arc<Mutex<Option<Child>>>,
}

struct LocalCaptureConfig<'a> {
    mitmdump: &'a Path,
    confdir: &'a Path,
    addon_path: &'a Path,
    bridge_port: u16,
    bridge_secret: &'a str,
    upstream_ca_bundle: &'a Path,
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

struct ServiceReadyGuard {
    pid: u32,
}

impl ServiceReadyGuard {
    fn activate() -> Result<Self> {
        let pid = std::process::id();
        let ready_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or_default();
        let state = serde_json::to_vec(&CursorServiceState { pid, ready_at_ms })?;
        replace_file(&service_state_path(), &state, 0o600)?;
        Ok(Self { pid })
    }
}

impl Drop for ServiceReadyGuard {
    fn drop(&mut self) {
        let path = service_state_path();
        let owns_state = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<CursorServiceState>(&bytes).ok())
            .is_some_and(|state| state.pid == self.pid);
        if owns_state {
            let _ = fs::remove_file(path);
        }
    }
}

fn require_mitmdump() -> Result<PathBuf> {
    let executable = mitmdump_executable();
    let status = Command::new(&executable)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if status.is_ok_and(|status| status.success()) {
        Ok(executable)
    } else {
        bail!(
            "mitmdump is required for process-level Cursor capture; install it with \
             `brew install --cask mitmproxy`"
        )
    }
}

fn mitmdump_executable() -> PathBuf {
    if let Some(path) = std::env::var_os("OPENSUB_MITMDUMP") {
        return PathBuf::from(path);
    }
    [
        "/opt/homebrew/bin/mitmdump",
        "/usr/local/bin/mitmdump",
        "/usr/bin/mitmdump",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
    .unwrap_or_else(|| PathBuf::from("mitmdump"))
}

fn service_dir() -> PathBuf {
    config::data_dir().join("cursor-proxy")
}

fn service_state_path() -> PathBuf {
    service_dir().join(SERVICE_STATE_NAME)
}

fn service_log_path() -> PathBuf {
    service_dir().join(SERVICE_LOG_NAME)
}

fn service_error_log_path() -> PathBuf {
    service_dir().join(SERVICE_ERROR_LOG_NAME)
}

fn service_plist_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(SERVICE_PLIST_NAME))
}

fn service_plist(executable: &Path, mitmdump: &Path) -> Result<String> {
    let home = std::env::var("HOME").context("HOME is not set")?;
    let executable_hash = hex_sha256(&fs::read(executable)?);
    let mut environment = vec![
        ("HOME".to_string(), home),
        (
            "PATH".to_string(),
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string(),
        ),
        (
            "OPENSUB_MITMDUMP".to_string(),
            mitmdump.display().to_string(),
        ),
        (
            "OPENSUB_SERVICE_EXECUTABLE_SHA256".to_string(),
            executable_hash,
        ),
        ("NO_COLOR".to_string(), "1".to_string()),
    ];
    for name in [
        "OPENSUB_HOME",
        "OPENSUB_CURSOR_MODEL",
        "OPENSUB_UPSTREAM",
        "OPENSUB_ALLOW_CUSTOM_UPSTREAM",
        "OPENSUB_USER_AGENT_VERSION",
        "RUST_LOG",
    ] {
        if let Ok(value) = std::env::var(name) {
            environment.push((name.to_string(), value));
        }
    }
    environment.sort_by(|left, right| left.0.cmp(&right.0));
    let environment = environment
        .into_iter()
        .map(|(key, value)| {
            format!(
                "        <key>{}</key>\n        <string>{}</string>",
                xml_escape(&key),
                xml_escape(&value)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{executable}</string>
        <string>cursor</string>
        <string>worker</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
{environment}
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>{stdout}</string>
    <key>StandardErrorPath</key>
    <string>{stderr}</string>
</dict>
</plist>
"#,
        label = SERVICE_LABEL,
        executable = xml_escape(&executable.display().to_string()),
        stdout = xml_escape(&service_log_path().display().to_string()),
        stderr = xml_escape(&service_error_log_path().display().to_string()),
    ))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn prepare_service_logs() -> Result<()> {
    fs::create_dir_all(service_dir())?;
    fs::set_permissions(service_dir(), fs::Permissions::from_mode(0o700))?;
    for path in [service_log_path(), service_error_log_path()] {
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn truncate_service_logs_if_oversized() -> Result<()> {
    for path in [service_log_path(), service_error_log_path()] {
        if fs::metadata(&path).is_ok_and(|metadata| metadata.len() > MAX_SERVICE_LOG_BYTES) {
            fs::OpenOptions::new().write(true).open(path)?.set_len(0)?;
        }
    }
    Ok(())
}

fn launchctl_domain() -> Result<String> {
    let output = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .context("failed to determine the macOS user ID")?;
    if !output.status.success() {
        bail!("could not determine the macOS user ID");
    }
    Ok(format!(
        "gui/{}",
        String::from_utf8_lossy(&output.stdout).trim()
    ))
}

fn launchctl_target() -> Result<String> {
    Ok(format!("{}/{}", launchctl_domain()?, SERVICE_LABEL))
}

fn service_is_loaded() -> Result<bool> {
    Ok(Command::new("/bin/launchctl")
        .args(["print", &launchctl_target()?])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to inspect the Cursor proxy service")?
        .success())
}

fn service_is_enabled() -> Result<bool> {
    let output = Command::new("/bin/launchctl")
        .args(["print-disabled", &launchctl_domain()?])
        .output()
        .context("failed to inspect the Cursor proxy service policy")?;
    if !output.status.success() {
        bail!("could not inspect the Cursor proxy service policy");
    }
    let disabled = format!("\"{SERVICE_LABEL}\" => disabled");
    Ok(!String::from_utf8_lossy(&output.stdout).contains(&disabled))
}

fn service_is_ready() -> bool {
    fs::read(service_state_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice::<CursorServiceState>(&bytes).ok())
        .is_some_and(|state| worker_pid_is_alive(state.pid))
}

fn worker_pid_is_alive(pid: u32) -> bool {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output();
    output.is_ok_and(|output| {
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("cursor worker")
    })
}

fn validate_service_plist(path: &Path) -> Result<()> {
    let output = Command::new("/usr/bin/plutil")
        .args(["-lint", "--"])
        .arg(path)
        .output()
        .context("failed to validate the Cursor proxy LaunchAgent")?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "invalid Cursor proxy LaunchAgent: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}

fn bootstrap_service(plist_path: &Path) -> Result<()> {
    let output = Command::new("/bin/launchctl")
        .args(["bootstrap", &launchctl_domain()?])
        .arg(plist_path)
        .output()
        .context("failed to start the Cursor proxy service")?;
    if !output.status.success() {
        bail!(
            "launchctl could not start the Cursor proxy service: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn set_service_enabled(enabled: bool) -> Result<()> {
    let action = if enabled { "enable" } else { "disable" };
    let output = Command::new("/bin/launchctl")
        .args([action, &launchctl_target()?])
        .output()
        .with_context(|| format!("failed to {action} the Cursor proxy service"))?;
    if !output.status.success() {
        bail!(
            "launchctl could not {action} the Cursor proxy service: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn bootout_service() -> Result<()> {
    if !service_is_loaded()? {
        return Ok(());
    }
    let output = Command::new("/bin/launchctl")
        .args(["bootout", &launchctl_target()?])
        .output()
        .context("failed to stop the Cursor proxy service")?;
    if !output.status.success() {
        bail!(
            "launchctl could not stop the Cursor proxy service: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while service_is_ready() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn wait_for_service_ready() -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline {
        if service_is_ready() {
            return Ok(());
        }
        if !service_is_loaded()? {
            bail!(
                "Cursor proxy service exited during startup; inspect {}",
                service_error_log_path().display()
            );
        }
        thread::sleep(Duration::from_millis(200));
    }
    bail!(
        "timed out waiting for the Cursor proxy service; inspect {}",
        service_error_log_path().display()
    )
}

fn remove_service_state_if_present() -> Result<()> {
    remove_file_if_present(&service_state_path())
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn stop_legacy_proxy_processes() -> Result<bool> {
    let output = Command::new("/usr/bin/pgrep")
        .args(["-x", "opensub"])
        .output();
    let Ok(output) = output else {
        return Ok(false);
    };
    let current_pid = std::process::id();
    let mut legacy_pids = Vec::new();
    for pid in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .filter(|pid| *pid != current_pid)
    {
        let command = Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "command="])
            .output();
        if command.is_ok_and(|command| {
            let command = String::from_utf8_lossy(&command.stdout);
            command.contains("cursor proxy") && !command.contains("cursor worker")
        }) {
            legacy_pids.push(pid);
        }
    }
    for pid in &legacy_pids {
        let _ = Command::new("/bin/kill")
            .args(["-INT", &pid.to_string()])
            .status();
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while legacy_pids.iter().any(|pid| process_exists(*pid)) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    if legacy_pids.iter().any(|pid| process_exists(*pid)) {
        bail!("an older foreground Cursor proxy did not stop cleanly");
    }
    Ok(!legacy_pids.is_empty())
}

fn refresh_cursor_network_service() -> Result<bool> {
    let output = Command::new("/bin/ps")
        .args(["-axo", "pid=,command="])
        .output()
        .context("failed to inspect Cursor network processes")?;
    let pids = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| {
            line.contains("/Applications/Cursor.app/")
                && line.contains("Cursor Helper")
                && line.contains("network.mojom.NetworkService")
        })
        .filter_map(|line| line.split_whitespace().next()?.parse::<u32>().ok())
        .collect::<Vec<_>>();
    for pid in &pids {
        let status = Command::new("/bin/kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .context("failed to refresh Cursor network connections")?;
        if !status.success() {
            bail!("could not refresh Cursor network connections");
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while pids.iter().any(|pid| process_exists(*pid)) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    Ok(!pids.is_empty())
}

fn process_exists(pid: u32) -> bool {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
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

fn bridge_tls_acceptor(key_path: &Path) -> Result<TlsAcceptor> {
    let ca_key = fs::read_to_string(key_path)
        .with_context(|| format!("failed to read {}", key_path.display()))?;
    let ca_key = KeyPair::from_pem(&ca_key).context("invalid OpenSub proxy CA key")?;
    let (leaf, leaf_key) = bridge_certificate(ca_key)?;

    let provider = Arc::new(ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], leaf_key.into())?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn bridge_certificate(ca_key: KeyPair) -> Result<(Certificate, KeyPair)> {
    let issuer = Issuer::new(proxy_ca_params(), ca_key);

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
    Ok((leaf, leaf_key))
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
    config: LocalCaptureConfig<'_>,
) -> Result<(LocalCaptureGuard, mpsc::Receiver<LocalCaptureEvent>)> {
    let process_filter = "local:Cursor,Cursor Helper,Cursor Helper (Plugin)";
    let mut child = Command::new(config.mitmdump)
        .args(["--mode", process_filter])
        .args(["--allow-hosts", r"(^|\.)cursor\.sh:443$"])
        .arg("--set")
        .arg(format!("confdir={}", config.confdir.display()))
        .args(["--set", "flow_detail=0"])
        .args(["--set", "termlog_verbosity=info"])
        .args(["--set", "block_global=false"])
        .args(["--set", "connection_strategy=lazy"])
        .arg("--set")
        .arg(format!(
            "ssl_verify_upstream_trusted_ca={}",
            config.upstream_ca_bundle.display()
        ))
        .args(["--scripts"])
        .arg(config.addon_path)
        .env("OPENSUB_BRIDGE_PORT", config.bridge_port.to_string())
        .env("OPENSUB_BRIDGE_SECRET", config.bridge_secret)
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
        }
    });
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
        .mode(mode)
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
    let cert = proxy_ca_params()
        .self_signed(&key_pair)
        .context("failed to create Cursor proxy CA certificate")?;

    write_private_file(&key_path, key_pair.serialize_pem().as_bytes())?;
    write_private_file(&cert_path, cert.pem().as_bytes())?;
    Ok((cert_path, key_path))
}

fn proxy_ca_params() -> CertificateParams {
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
    params
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn protocol_capture_path() -> PathBuf {
    config::data_dir()
        .join("cursor-proxy")
        .join("last-agent-request.bin")
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
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_agent_runs_persistent_hidden_worker() {
        let executable = std::env::current_exe().unwrap();
        let plist = service_plist(&executable, Path::new("/tmp/mitm&dump")).unwrap();
        assert!(plist.contains("<string>cursor</string>"));
        assert!(plist.contains("<string>worker</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("/tmp/mitm&amp;dump"));
        assert!(!plist.contains("auth.json"));
        assert!(!plist.contains("access_token"));
    }

    #[test]
    fn bridge_certificate_chains_to_proxy_ca_for_localhost() {
        use rustls::client::danger::ServerCertVerifier;

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = proxy_ca_params().self_signed(&ca_key).unwrap();
        let (leaf, _) = bridge_certificate(ca_key).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_cert.der().clone()).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(ring::default_provider()),
        )
        .build()
        .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();

        verifier
            .verify_server_cert(
                leaf.der(),
                &[],
                &server_name,
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .unwrap();
    }

    #[test]
    fn local_capture_streams_agent_responses() {
        assert!(MITMPROXY_ADDON.contains("def responseheaders"));
        assert!(MITMPROXY_ADDON.contains("flow.response.stream = True"));
        assert!(!MITMPROXY_ADDON.contains("OPENSUB_EVENT"));
        assert!(!MITMPROXY_ADDON.contains("MODEL_PATTERN"));
    }
}
