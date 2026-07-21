# Contributing to OpenSub

OpenSub handles OAuth tokens, API keys, a trusted local CA, public tunnel
traffic, and an internal Cursor protocol. Keep changes narrow, auditable, and
defensive by default.

Read these documents before changing behavior:

- [README.md](README.md) for the public contract and operating workflow.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for routing, translation,
  streaming, identity constants, and service lifecycle.
- [SECURITY.md](SECURITY.md) for the threat model and reporting policy.

## Local setup

```bash
git clone https://github.com/lorenzovborges/OpenSub.git
cd OpenSub
cargo build
cargo test --all-targets --all-features
```

Transparent Cursor testing additionally requires macOS, the official Cursor
application, and mitmproxy:

```bash
brew install --cask mitmproxy
cargo install --path . --locked --force
opensub login
opensub cursor proxy
```

This installs a persistent per-user LaunchAgent and a trusted local CA. Stop it
after testing when continuous routing is not desired:

```bash
opensub cursor stop
```

The separate OpenAI-compatible tunnel test requires `cloudflared`:

```bash
brew install cloudflared
opensub serve --tunnel
```

## Required validation

Run before opening a pull request:

```bash
cargo install cargo-audit --locked # once, if `cargo audit` is unavailable
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo audit
cargo build --release
```

For routing or protocol changes, also perform focused live checks:

1. An OpenAI-family text turn records `route_opensub` and completes.
2. A workspace-tool turn records `tool_requested`, `tool_completed`, and
   `generation_completed`.
3. Composer or Grok records `route_cursor` and remains on Cursor.
4. `opensub cursor stop` leaves the LaunchAgent disabled and both the OpenSub
   worker and `mitmdump` stopped.

Never attach `last-agent-request.bin` or raw `~/.opensub` files to a pull
request. Describe protocol observations using redacted field shapes.

## Pull request checklist

- No real tokens, API keys, tunnel credentials, CA keys, logs, protocol
  captures, or local `~/.opensub` data are committed.
- OAuth identity constants and inference headers remain synchronized with
  `src/config.rs` and the architecture document.
- API-key authentication remains enabled for every HTTP API route.
- Custom upstream support remains allowlisted and opt-in.
- Native Cursor traffic remains a streaming passthrough and is routed before
  OpenSub-specific action parsing.
- Request and response streaming remain incremental; do not buffer Agent tool
  turns.
- Tests cover changed translation, routing, lifecycle, and security behavior.
- README, architecture, handoff, and CLI help are updated when public behavior
  changes.

## Engineering guidelines

- Preserve unknown protobuf fields by avoiding unnecessary decode/re-encode on
  Cursor passthrough traffic.
- Parse only the fields required to make a routing decision before selecting a
  destination.
- Do not log request bodies, response bodies, authorization headers, tool
  payloads, or fetched blob values.
- Avoid new dependencies when the standard library or an existing dependency
  is sufficient.
- Keep the OpenAI-compatible surface stable unless the public documentation and
  tests change with it.
