# Security Policy

OpenSub is security-sensitive because it can expose a local proxy through a
public tunnel and forward requests using a ChatGPT OAuth token.

## Supported versions

Only the latest commit on `main` is supported.

## Reporting a vulnerability

If you find a vulnerability, please avoid posting working exploits, tokens, or
private tunnel URLs in public issues.

Preferred reporting options:

1. Open a private vulnerability report on GitHub if it is available for this
   repository.
2. If private reporting is not available, open a public issue with a minimal
   description and omit secrets, account identifiers, tunnel URLs, and exploit
   payloads.

## Security expectations

- Never commit `~/.opensub/auth.json`, `~/.opensub/api_key`, `.env` files,
  Cloudflare credentials, logs, or captured request/response bodies.
- Keep API-key authentication enabled for public tunnel usage.
- Do not send OAuth tokens to arbitrary custom upstream hosts.
- Redact API keys, bearer tokens, cookies, request bodies, response bodies, and
  tool payloads from logs.
- Rotate `opensub` API keys after any accidental disclosure:

```bash
opensub key rotate
```
