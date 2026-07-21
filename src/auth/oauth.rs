//! OAuth flow: PKCE, authorize URL, code exchange, token refresh.
//!
//! Constants and request shapes mirror `sst/opencode` exactly so we present the
//! same identity to OpenAI's auth server.

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::auth::store::TokenData;
use crate::config;

/// PKCE pair.
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// Generate a PKCE pair (S256), matching opencode's alphabet and length.
pub fn generate_pkce() -> Pkce {
    use rand::Rng;
    // opencode: 43 random bytes mapped via `byte % 64` into `A-Za-z0-9-._~`.
    let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        .chars()
        .collect();
    let mut bytes = [0u8; 43];
    rand::rng().fill_bytes(&mut bytes);
    let verifier: String = bytes
        .iter()
        .map(|b| chars[(*b as usize) % chars.len()])
        .collect();
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    Pkce {
        verifier,
        challenge,
    }
}

/// Generate a random `state` (32 bytes, base64url-no-pad) — matches Codex CLI.
pub fn generate_state() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Build the authorize URL (opens in the user's browser).
pub fn build_authorize_url(state: &str, pkce: &Pkce) -> String {
    // Build query manually with urlencoding, matching opencode's query params.
    let q = format!(
        "response_type=code&client_id={client_id}&redirect_uri={redirect}&scope={scope}\
         &code_challenge={challenge}&code_challenge_method=S256\
         &id_token_add_organizations=true&codex_cli_simplified_flow=true\
         &state={state}&originator=opencode",
        client_id = urlencoding::encode(config::CLIENT_ID),
        redirect = urlencoding::encode(config::REDIRECT_URI),
        scope = urlencoding::encode(config::SCOPES),
        challenge = urlencoding::encode(&pkce.challenge),
        state = urlencoding::encode(state),
    );
    format!("{}?{}", config::AUTHORIZE_URL, q)
}

/// Token response from the OAuth server.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

impl TokenResponse {
    fn into_stored(mut self) -> TokenData {
        let mut data = TokenData {
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            id_token: self.id_token.take(),
            expires_at: self.expires_in.map(|s| now_ts() + s),
            account_id: None,
        };
        data.enrich_from_jwt();
        data
    }
}

/// Exchange an authorization code for tokens.
pub async fn exchange_code(code: &str, pkce: &Pkce) -> Result<TokenData> {
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={redirect}&client_id={client_id}&code_verifier={verifier}",
        code = urlencoding::encode(code),
        redirect = urlencoding::encode(config::REDIRECT_URI),
        client_id = urlencoding::encode(config::CLIENT_ID),
        verifier = urlencoding::encode(&pkce.verifier),
    );
    let resp = token_post_form(&body).await?;
    Ok(resp.into_stored())
}

/// Refresh the access token using a refresh token.
pub async fn refresh(refresh_token: &str) -> Result<TokenData> {
    let body = format!(
        "grant_type=refresh_token&refresh_token={refresh}&client_id={client_id}",
        refresh = urlencoding::encode(refresh_token),
        client_id = urlencoding::encode(config::CLIENT_ID),
    );
    let resp = token_post_form(&body).await?;
    Ok(resp.into_stored())
}

/// POST a form-encoded body to the token endpoint and parse the response.
async fn token_post_form(body: &str) -> Result<TokenResponse> {
    let client = reqwest::Client::builder()
        .user_agent(config::opencode_user_agent())
        .build()?;
    let resp = client
        .post(config::TOKEN_URL)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .body(body.to_string())
        .send()
        .await
        .context("token request failed")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("token endpoint returned {status}: {text}");
    }
    serde_json::from_str::<TokenResponse>(&text)
        .with_context(|| format!("parse token response: {text}"))
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
