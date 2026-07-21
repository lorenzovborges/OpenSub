# OpenSub — Handoff / Continuation Notes

> **Read this first.** It's a context document for any model (or human)
> continuing work on OpenSub. It explains what the project is, how we got here,
> what's been verified, and what's left. Pair it with `README.md` (user-facing)
> and `docs/ARCHITECTURE.md` (deep technical reference).

---

## TL;DR for the next agent

OpenSub is a **Rust single-binary OpenAI-compatible proxy** that lets Cursor use
your ChatGPT (Plus/Pro) **subscription** as if it were an OpenAI API key. It
works by:

1. Logging you in with the same ChatGPT OAuth flow OpenCode uses (`opensub login`).
2. Transparently intercepting the official Cursor Agent stream with
   `opensub cursor proxy` and routing only OpenAI-family models to Codex.
3. **Translating** both Cursor Connect/protobuf and OpenAI Chat Completions to
   the Codex backend's Responses API.
4. Keeping `opensub serve [--tunnel]` as an OpenAI-compatible endpoint for
   other clients.

**Current status: text and native workspace tools are end-to-end verified in
the official Cursor application.** See "State" below.

---

## The full story (what we did and why)

### The problem
The user wanted to use their ChatGPT subscription inside Cursor (instead of
paying OpenAI API per-token). Cursor lets you point at a custom OpenAI-compatible
endpoint ("Override OpenAI Base URL"). So we built a tiny local server that
*impersonates* the OpenAI API and forwards to OpenAI's Codex backend, billed to
the ChatGPT subscription.

### Identity choice: "be OpenCode"
The user explicitly asked OpenSub to **present itself as OpenCode**
(`sst/opencode`) — same OAuth client id, same User-Agent — because OpenCode is a
permitted/known client, which lowers the risk of the account being flagged. We
reverse-engineered opencode's exact auth flow (PKCE params, scopes, client id
`app_EMoamEEZ73f0CkXaXp7hrann`, token/refresh shapes) from its source and the
Codex CLI source. Details: `docs/ARCHITECTURE.md` §2.

### The de-risk probe (key decision point)
Before building the translation layer, we ran `opensub probe` to learn which
upstream accepts the subscription token:

- `api.openai.com/v1/responses` → **401 `Missing scopes: api.responses.write`**
  (subscription tokens don't have API-key scopes).
- `chatgpt.com/backend-api/codex/responses` → **200 ✅** (works with Bearer +
  `chatgpt-account-id` + `originator: codex_cli_rs` headers).

**Decision:** the ChatGPT/Codex backend is the *only* working upstream, not a
fallback. The default in `config.rs` is `https://chatgpt.com/backend-api/codex`.
The public API endpoint is dead for this use case.

Two constraints fell out of this:
- The backend **requires `stream: true`** (`400 "Stream must be set to true"`).
  The handler forces it and buffers for non-streaming clients.
- It needs the extra identity headers; `is_chatgpt_upstream()` gates them.

### The "Cursor blocks private networks" discovery
The first real Cursor test failed: `Access to private networks is forbidden`.
Cursor runs chat on **its own cloud**, so it can't reach `localhost`. The fix:
bundle a Cloudflare quick tunnel (`opensub serve --tunnel`). Reference repo the
user found: `ephraimduncan/codex-cursor`. This also forced us to add **API-key
auth** (middleware) so the now-public endpoint can't be abused.

### Three bugs we fixed in sequence (the "live Cursor testing" arc)
1. **`broken pipe` / `Unable to reach the origin service`.** Root cause: the
   original `translate_stream` buffered the *entire* response into a `Vec<u8>`
   before replying, so the tunnel timed out. Fix: rewrote to stream frames
   incrementally through an `mpsc` channel + `Body::from_stream`.
2. **`/chat/completions` (no `/v1`).** Cursor sometimes calls without the
   prefix. Fix: added path aliases.
3. **`tools[7]: missing field function`.** Cursor sends non-function tools
   (`web_search`, etc.). Our strict `ChatTool` type rejected them. Fix: made
   `ChatTool` a newtype over raw JSON; only `function`-type tools are forwarded.

### Transparent Agent bridge bugs fixed during live validation
1. **HTTP/1 local hop dropped the bidirectional request body.** The bridge now
   terminates TLS with HTTP/2 ALPN and receives Cursor's Connect stream intact.
2. **Certificate present but not trusted.** The startup check used to accept any
   matching Keychain certificate. It now verifies the exact SHA-256 fingerprint
   plus user trust settings and installs the CA in the user trust domain.
3. **Tool execution targeted a nonexistent executor.** OpenSub populated
   `ExecServerMessage.exec_id` with the model call ID. Cursor's local executor
   expects the same shape as its mock Agent: numeric `id` plus the args oneof,
   without a synthetic `exec_id`.
4. **mitmproxy buffered Agent responses.** This deadlocked tools: OpenSub waited
   for `ExecClientMessage` while Cursor waited for `ExecServerMessage`. The addon
   now streams both request and response halves of `AgentService/Run`.

---

## State

### ✅ Done & verified
- Rust project scaffolded, compiles cleanly (release profile: strip/lto/abort).
- OAuth login (`opensub login`) — works, tokens persisted at `~/.opensub/auth.json`.
- Lazy token refresh (`ensure_valid_token`, 5-min window).
- `opensub probe` — confirmed **200** from the ChatGPT/Codex backend with a real
  `account_id` extraction verified (value intentionally redacted).
- API server with `/v1/models`, `/v1/chat/completions` (+ `/v1`-less aliases).
- API-key middleware (auto-generated key, `opensub key` to view).
- Chat Completions → Responses request translation (messages, tool_calls, tools).
- Responses-shaped Cursor request passthrough on `/v1/chat/completions`,
  preserving custom/freeform tools.
- Responses SSE → Chat Completions SSE translation (text, `function_call`, and
  `custom_tool_call` deltas).
- **Incremental streaming** via `mpsc` + `Body::from_stream` (no more broken pipe).
- Cloudflare tunnel integration (`--tunnel`).
- mitmproxy Local Capture verified against the official Cursor process tree.
- Real `AgentService/Run` capture decoded: Connect framing, gzip protobuf,
  requested model, reasoning parameter, 75 MCP tools, KV blobs, and Exec flow.
- Transparent selective bridge implemented: OpenAI model IDs route to Codex;
  Composer, Grok, Claude, Gemini, and unknown models pass through to Cursor.
- Agent text stream, prefetched conversation-blob ingestion, MCP/core tool
  execution loop, token usage, and Connect end-stream encoding implemented in
  Rust.
- Live official-Cursor text turns route to OpenSub and complete.
- Live workspace-tool turn verified with `read_file`, `shell`, `list_dir`, and
  `grep`; every request received a matching result and the generation completed.
- Local CA trust, HTTP/2 transport, bidirectional response streaming, and native
  Exec protobuf shapes are covered by startup checks and focused tests.
- The legacy managed Cursor copy and its hidden CLI commands were removed after
  the transparent bridge passed validation.
- README + ARCHITECTURE docs.

### 🟡 Known limitation
- Transparent mode currently uses the current prompt plus blobs prefetched by
  Cursor. Active fetching of every referenced historical KV blob is not yet
  implemented, so some older conversation context may be absent.

### ❌ Not done (future work)
- Broader unit tests with recorded SSE fixtures.
- Stable/named Cloudflare tunnel (so the URL doesn't rotate on restart).
- Broader error mapping (429 pass-through, nicer 401 "please re-login" message).
- Device-code (headless) login flow — currently browser-only.

---

## Immediate next steps (do these first)

1. **Quit Cursor completely and start the transparent proxy:**
   ```bash
   cd ~/CursorOpenSub
   cargo install --path . --force
   opensub cursor proxy
   ```
   Leave Cursor's OpenAI API key and base URL overrides disabled.
2. Use Cursor normally. For diagnosis, inspect the metadata-only
   `~/.opensub/cursor-proxy/events.jsonl`; a healthy tool turn includes
   `route_opensub`, `tool_requested`, `tool_completed`, and
   `generation_completed`.
3. Select Composer or Grok for a passthrough check. It should produce
   `route_cursor` and continue using the Cursor subscription.

---

## How to run / reproduce

```bash
# build & install
cd ~/CursorOpenSub
cargo install --path .
brew install cloudflared   # for the tunnel

# one-time login
opensub login

# debug the upstream anytime
opensub probe

# recommended: transparent official Cursor routing
# Cursor must be fully closed before this command
opensub cursor proxy

# optional OpenAI-compatible endpoint for other clients
opensub serve --tunnel
```

Sandbox note: this project was developed with a tool harness whose shell/filesystem
occasionally went degraded mid-session (`spawn /bin/zsh ENOENT`). If a command
mysteriously fails, retry — it's environmental, not the code.

---

## Where things live (map)

| Concern | File |
|---|---|
| Identity constants, env vars, model list | `src/config.rs` |
| CLI entry, tunnel spawn | `src/main.rs` |
| OAuth (PKCE, exchange, refresh) | `src/auth/oauth.rs` |
| Token storage + JWT parsing | `src/auth/store.rs` |
| Login orchestration, lazy refresh | `src/auth/mod.rs` |
| OAuth callback server (:1455) | `src/auth/callback.rs` |
| Router, API-key middleware, chat handler | `src/api/mod.rs` |
| Upstream HTTP client + probe | `src/codex/client.rs` |
| Transparent Cursor Connect/protobuf bridge | `src/cursor_agent.rs` |
| macOS process capture, TLS, CA trust, routing addon | `src/cursor_proxy.rs` |
| Chat→Responses request translation | `src/translate/request.rs` |
| Responses→Chat SSE translation + incremental stream | `src/translate/stream.rs` |
| Type definitions | `src/types/{chat,responses}.rs` |

User-facing docs: `README.md`. Deep technical: `docs/ARCHITECTURE.md`.

---

## One-line summary for the next agent

> OpenSub (Rust, `~/CursorOpenSub`) transparently routes OpenAI-family models
> from the official Cursor app to the ChatGPT Codex backend while native models
> stay on Cursor. OAuth, HTTP/2 Connect transport, incremental bidirectional
> streaming, text generation, and native workspace tools are live-verified;
> read `docs/ARCHITECTURE.md` before changing protocol or translation code.
