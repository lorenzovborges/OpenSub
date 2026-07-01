//! Authentication module: OAuth login, token storage, refresh.

pub mod callback;
pub mod oauth;
pub mod store;

use anyhow::{Context, Result, bail};

/// Run the interactive browser OAuth flow and persist tokens.
pub async fn login() -> Result<()> {
    let pkce = oauth::generate_pkce();
    let state = oauth::generate_state();
    let url = oauth::build_authorize_url(&state, &pkce);

    println!("\n→ Opening your browser to sign in with ChatGPT…");
    println!("  If it doesn't open, visit:\n  {}\n", url);

    // Try to open the browser (non-fatal if it fails — the URL is printed above).
    let _ = webbrowser::open(&url);

    // Wait for the redirect callback in parallel.
    let code = callback::wait_for_code(&state)
        .await
        .context("OAuth callback")?;

    println!("→ Exchanging authorization code for tokens…");
    let tokens = oauth::exchange_code(&code, &pkce)
        .await
        .context("token exchange")?;

    store::save(&tokens).context("saving tokens")?;
    println!("→ Logged in. Tokens saved to {}", store::path().display());
    Ok(())
}

/// Ensure we have a valid (non-expiring) access token; refresh if needed.
/// Loads from disk, refreshes lazily, and persists the refreshed token.
pub async fn ensure_valid_token() -> Result<store::TokenData> {
    let mut data = store::load()?.context("not logged in — run `opensub login`")?;
    // Refresh if the access token expires within the next 5 minutes.
    if data.expiring_within(300) {
        println!("→ Refreshing access token…");
        let refreshed = oauth::refresh(&data.refresh_token)
            .await
            .context("refreshing token")?;
        // Preserve account_id if the refresh response didn't carry it.
        let account_id = refreshed.account_id.clone().or(data.account_id.clone());
        data = refreshed;
        if data.account_id.is_none() {
            data.account_id = account_id;
        }
        let _ = store::save(&data);
    }
    Ok(data)
}

/// Log out: delete stored tokens.
pub fn logout() -> Result<()> {
    store::clear()?;
    println!("→ Logged out (removed {}).", store::path().display());
    Ok(())
}

/// Report whether the user is currently logged in.
pub fn is_logged_in() -> bool {
    store::path().exists()
}

/// Small helper for commands that require login: returns a token or a friendly
/// error pointing the user to `opensub login`.
pub async fn require_token() -> Result<store::TokenData> {
    match ensure_valid_token().await {
        Ok(t) => Ok(t),
        Err(_) => {
            bail!("not logged in — run `{}` first", binary_name())
        }
    }
}

fn binary_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "opensub".to_string())
}
