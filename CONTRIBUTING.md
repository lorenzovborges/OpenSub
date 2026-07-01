# Contributing to OpenSub

OpenSub is a personal-use proxy that handles OAuth tokens, API keys, and public
tunnel traffic. Keep changes small, auditable, and defensive by default.

## Local setup

```bash
cargo build
cargo test
```

For Cursor testing:

```bash
cargo install --path . --force
opensub login
opensub serve --tunnel
```

## Pull request checklist

- Do not commit real tokens, API keys, tunnel credentials, logs, or local
  `~/.opensub` data.
- Keep OAuth/client identity constants and upstream headers documented when
  they change.
- Preserve API-key auth for all public routes.
- Redact request bodies, response bodies, tokens, API keys, and tool payloads
  from logs.
- Add or update tests for request translation, stream translation, auth, and
  security-sensitive behavior.
- Run `cargo test` before opening a PR.

## Development notes

- Prefer narrow fixes over broad rewrites.
- Keep the OpenAI-compatible surface stable unless the README and architecture
  docs are updated in the same change.
- Treat custom upstream support as dangerous: OAuth tokens must only be sent to
  trusted hosts and should remain allowlisted by default.
