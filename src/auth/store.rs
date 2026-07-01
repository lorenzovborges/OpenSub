//! Token storage: `~/.opensub/auth.json` with mode 0600.

use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config;

/// Stored OAuth tokens (shape mirrors opencode's `auth.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenData {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
    /// Unix epoch seconds when the access token expires.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// `chatgpt_account_id` extracted from the JWT (used by the fallback upstream).
    #[serde(default)]
    pub account_id: Option<String>,
}

impl TokenData {
    /// True if the access token is expired or expires within `secs` seconds.
    pub fn expiring_within(&self, secs: u64) -> bool {
        let Some(exp) = self.expires_at else {
            return true; // no expiry known — assume expiring to be safe
        };
        let now = now_ts();
        exp <= now + secs
    }

    /// Best-effort: set `expires_at` and `account_id` from the JWT claims.
    pub fn enrich_from_jwt(&mut self) {
        if let Some(claims) = jwt_claims(&self.access_token) {
            if let Some(exp) = claims.get("exp").and_then(|v| v.as_u64()) {
                self.expires_at = Some(exp);
            }
            if self.account_id.is_none() {
                self.account_id = claims
                    .get("https://api.openai.com/auth")
                    .and_then(|a| a.get("chatgpt_account_id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| {
                        claims
                            .get("chatgpt_account_id")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    });
            }
        }
    }
}

/// Where tokens live on disk.
pub fn path() -> PathBuf {
    config::auth_file()
}

/// Load stored tokens, if any.
pub fn load() -> Result<Option<TokenData>> {
    let p = path();
    if !p.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
    let mut data: TokenData =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", p.display()))?;
    data.enrich_from_jwt();
    Ok(Some(data))
}

/// Save tokens to disk with mode 0600.
pub fn save(data: &TokenData) -> Result<()> {
    let p = path();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(data)?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut f = opts
        .open(&p)
        .with_context(|| format!("open {}", p.display()))?;
    use std::io::Write;
    f.write_all(json.as_bytes())
        .with_context(|| format!("write {}", p.display()))?;
    Ok(())
}

/// Delete stored tokens (logout).
pub fn clear() -> Result<()> {
    let p = path();
    if p.exists() {
        std::fs::remove_file(&p)?;
    }
    Ok(())
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Decode the payload (middle) part of a JWT into a JSON object. No signature
/// verification — we only use it locally to read `exp` / claim metadata.
fn jwt_claims(token: &str) -> Option<serde_json::Value> {
    use base64::Engine;
    let mid = token.split('.').nth(1)?;
    // JWT uses base64url without padding; pad for the decoding engine.
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(mid)
        .or_else(|_| {
            let padded = match mid.len() % 4 {
                2 => format!("{mid}=="),
                3 => format!("{mid}="),
                _ => mid.to_string(),
            };
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(padded)
        })
        .ok()?;
    serde_json::from_slice(&decoded).ok()
}
