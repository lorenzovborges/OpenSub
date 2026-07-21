# Security Policy

OpenSub handles ChatGPT OAuth tokens, installs a trusted local CA for
transparent Cursor routing, and can expose an HTTP endpoint through a public
tunnel. Treat its configuration directory as credential material.

## Supported versions

Only the latest commit on `main` is supported. Before reporting a defect,
reinstall the latest checkout with:

```bash
cargo install --path . --locked --force
```

## Report a vulnerability

Use GitHub private vulnerability reporting from the repository's **Security**
tab when available. Do not put working exploits, credentials, captured Agent
requests, or private tunnel URLs in a public issue.

If private reporting is unavailable, open a minimal issue at
<https://github.com/lorenzovborges/OpenSub/issues> describing the affected
component and impact. The maintainer can arrange a private channel for details.

Include:

- The OpenSub commit or installed version.
- macOS and Cursor versions when transparent routing is involved.
- Reproduction steps with all credentials and user content removed.
- Whether the issue affects transparent mode, `serve`, or both.

## Threat model

### ChatGPT OAuth tokens

OAuth tokens are stored in `~/.opensub/auth.json` and sent to the configured
inference upstream. By default, OpenSub only permits HTTPS hosts
`chatgpt.com` and `api.openai.com`. Enabling
`OPENSUB_ALLOW_CUSTOM_UPSTREAM=1` allows that custom host to receive the bearer
token and must be treated as a deliberate trust decision.

### Trusted local CA

Transparent mode creates a CA private key under
`~/.opensub/cursor-proxy/` and trusts its certificate in the user's login
Keychain. mitmproxy Local Capture is restricted to Cursor processes, and the
addon intercepts only `/agent.v1.AgentService/Run`, but compromise of the CA
private key would still be security-sensitive. Never copy, publish, or back up
this directory to an untrusted location.

### Public HTTP API

`opensub serve --tunnel` publishes an ephemeral public URL. Every API route
requires the OpenSub API key through `Authorization: Bearer` or `x-api-key`.
The quick-tunnel URL is not a secret and must not be treated as authentication.

### Loopback Agent bridge

The transparent bridge binds to loopback, uses TLS/HTTP2, and requires a random
per-process secret inserted by the local mitmproxy addon. That secret is not the
persisted HTTP API key.

### Logs and protocol captures

Normal logs contain route and lifecycle metadata only. The diagnostic
`opensub cursor proxy --capture-protocol` file can contain prompt context and
must be handled as sensitive user data. It is not suitable for normal usage.

## Operational requirements

- Never commit `.env` files, `~/.opensub`, tokens, API keys, logs, CA keys,
  Cloudflare credentials, or protocol captures.
- Keep API-key middleware enabled on all HTTP API routes.
- Keep custom upstreams denied by default.
- Do not add prompt bodies, authorization headers, tool arguments, tool
  outputs, or blob contents to logs.
- Run `cargo audit` and the full test suite before publishing a release.

## Credential incident response

Stop transparent routing first:

```bash
opensub cursor stop
```

If the HTTP API key was exposed:

```bash
opensub key rotate
```

If ChatGPT OAuth tokens or `auth.json` were exposed:

```bash
opensub logout
```

Also revoke the relevant application/session from the account provider when
available, then authenticate again with `opensub login`.

If the local CA private key was exposed, remove the service, trusted
certificate, and local proxy directory before recreating it:

```bash
opensub cursor uninstall
security delete-certificate -c "OpenSub Cursor Proxy" \
  ~/Library/Keychains/login.keychain-db
rm -rf ~/.opensub/cursor-proxy
opensub cursor proxy
```

## Full removal

```bash
opensub cursor uninstall
opensub logout
security delete-certificate -c "OpenSub Cursor Proxy" \
  ~/Library/Keychains/login.keychain-db
rm -rf ~/.opensub
cargo uninstall opensub
```
