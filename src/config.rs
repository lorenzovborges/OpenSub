//! Configuration: paths, env vars, version, model list.

use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

/// OAuth identity — identical to `sst/opencode`.
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";
pub const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub const REDIRECT_URI: &str = "http://localhost:1455/auth/callback";
pub const CALLBACK_PORT: u16 = 1455;
pub const SCOPES: &str = "openid profile email offline_access";

/// Default Codex models exposed via `/v1/models`.
/// Editable list — Cursor must add these names under Settings → Models.
pub const DEFAULT_MODELS: &[&str] = &[
    "gpt-5.5",
    "gpt-5.1-codex",
    "gpt-5.1",
    "gpt-5.2",
    "gpt-5.2-codex",
    "codex-mini-latest",
];

/// Resolve the data directory (`~/.opensub`), honoring `OPENSUB_HOME`.
pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("OPENSUB_HOME") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".opensub")
}

/// Path to the stored auth file (`~/.opensub/auth.json`).
pub fn auth_file() -> PathBuf {
    data_dir().join("auth.json")
}

/// The API key that clients (Cursor) must present. Because OpenSub is often
/// exposed via a public tunnel, this gates access to your subscription. Set via
/// `OPENSUB_API_KEY` or stored in `~/.opensub/api_key` (auto-generated if absent).
pub fn api_key() -> String {
    if let Ok(k) = std::env::var("OPENSUB_API_KEY") {
        return k;
    }
    if let Ok(k) = std::fs::read_to_string(api_key_file()) {
        return k.trim().to_string();
    }
    // Generate and persist a key on first run.
    let key = generate_api_key();
    let _ = write_api_key(&key);
    key
}

/// Generate and persist a fresh API key, replacing the existing persisted key.
pub fn rotate_api_key() -> std::io::Result<String> {
    let key = generate_api_key();
    write_api_key(&key)?;
    Ok(key)
}

fn generate_api_key() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 24];
    use rand::RngCore;
    rand::rng().fill_bytes(&mut bytes);
    format!(
        "sk-opensub-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

fn write_api_key(key: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(data_dir())?;
    let path = api_key_file();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)?;
    file.write_all(key.as_bytes())?;
    file.write_all(b"\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Path to the persisted API key file.
pub fn api_key_file() -> PathBuf {
    data_dir().join("api_key")
}

/// Bind host for the API server (default `127.0.0.1`).
pub fn host() -> String {
    std::env::var("OPENSUB_HOST").unwrap_or_else(|_| "127.0.0.1".to_string())
}

/// Bind port for the API server (default `8788`).
pub fn port() -> u16 {
    std::env::var("OPENSUB_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8788)
}

/// Upstream base URL for inference.
///
/// Default is the ChatGPT/Codex backend (`chatgpt.com/backend-api/codex`), which
/// is the path the Codex CLI and the opencode plugin actually use with a
/// ChatGPT subscription token. It sends `Authorization: Bearer`, plus the
/// `chatgpt-account-id` and `originator: codex_cli_rs` headers automatically
/// (see `is_chatgpt_upstream`).
///
/// Override with `OPENSUB_UPSTREAM=https://api.openai.com/v1` to use the public
/// OpenAI Responses endpoint instead (requires an API-key scope, not a
/// subscription token).
pub fn upstream() -> String {
    std::env::var("OPENSUB_UPSTREAM")
        .unwrap_or_else(|_| "https://chatgpt.com/backend-api/codex".to_string())
}

/// Whether the upstream is the ChatGPT backend (requires extra headers).
pub fn is_chatgpt_upstream() -> bool {
    upstream().contains("chatgpt.com")
}

/// User-Agent version sent on token calls as `opencode/<v>` (default `local`,
/// matching opencode dev builds).
pub fn ua_version() -> String {
    std::env::var("OPENSUB_USER_AGENT_VERSION").unwrap_or_else(|_| "local".to_string())
}

/// Full User-Agent string for OAuth/token requests.
pub fn opencode_user_agent() -> String {
    format!("opencode/{}", ua_version())
}

/// Per-process Codex session id. The ChatGPT/Codex backend uses this together
/// with `prompt_cache_key` to keep reasoning/tool-call continuity across turns.
pub fn session_id() -> &'static str {
    static SESSION_ID: OnceLock<String> = OnceLock::new();
    SESSION_ID.get_or_init(|| {
        use base64::Engine;
        let mut bytes = [0u8; 16];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    })
}

/// User-Agent for inference requests. OAuth still presents as OpenCode; the
/// inference path mirrors Codex CLI identity headers because tool-call behavior
/// depends on being treated as a normal Codex session.
pub fn codex_user_agent() -> &'static str {
    "codex_cli_rs/0.120.0 (opensub)"
}
