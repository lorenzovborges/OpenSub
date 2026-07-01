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
2. Serving an OpenAI-shaped API (`/v1/models`, `/v1/chat/completions`) on
   localhost (`opensub serve`).
3. **Translating** Chat Completions ↔ the Codex backend's Responses API.
4. Exposing itself over a public Cloudflare tunnel (`--tunnel`) because Cursor's
   cloud blocks private network addresses.

**Current status: functionally complete, end-to-end verified up to the point
where the request reaches Cursor's tool-format expectations.** See "State" below.

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

---

## State

### ✅ Done & verified
- Rust project scaffolded, compiles cleanly (release profile: strip/lto/abort).
- OAuth login (`opensub login`) — works, tokens persisted at `~/.opensub/auth.json`.
- Lazy token refresh (`ensure_valid_token`, 5-min window).
- `opensub probe` — confirmed **200** from the ChatGPT/Codex backend with a real
  `account_id` extracted (`fe874ce3-...`).
- API server with `/v1/models`, `/v1/chat/completions` (+ `/v1`-less aliases).
- API-key middleware (auto-generated key, `opensub key` to view).
- Chat Completions → Responses request translation (messages, tool_calls, tools).
- Responses-shaped Cursor request passthrough on `/v1/chat/completions`,
  preserving custom/freeform tools.
- Responses SSE → Chat Completions SSE translation (text, `function_call`, and
  `custom_tool_call` deltas).
- **Incremental streaming** via `mpsc` + `Body::from_stream` (no more broken pipe).
- Cloudflare tunnel integration (`--tunnel`).
- README + ARCHITECTURE docs.

### 🟡 In progress / not yet confirmed
- **End-to-end Cursor agent/tools test after the custom-tool fix.** The proxy now
  accepts Responses-shaped Cursor bodies, preserves custom tools, sends Codex
  session headers, and translates `custom_tool_call` events. `cargo test` and
  `opensub probe` pass, but Cursor still needs a live retest. The next step is
  `cargo install --path . --force`, restart `opensub serve --tunnel`, and
  confirm Cursor can actually execute an edit/tool turn.
- The broken-pipe fix similarly needs a live streaming confirmation through the
  tunnel (text should now arrive progressively).

### ❌ Not done (future work)
- Broader unit tests with recorded SSE fixtures.
- Stable/named Cloudflare tunnel (so the URL doesn't rotate on restart).
- `cargo fix` to clear the 8 dead-code warnings.
- Broader error mapping (429 pass-through, nicer 401 "please re-login" message).
- Device-code (headless) login flow — currently browser-only.

---

## Immediate next steps (do these first)

1. **Rebuild and retest in Cursor** (this is the real validation):
   ```bash
   cd ~/CursorOpenSub
   cargo install --path . --force
   opensub serve --tunnel
   ```
   Copy the new `https://*.trycloudflare.com/v1` URL and the API key into
   Cursor, send a test message. If it streams text → 🎉 the core works.
2. If Cursor's agent mode is the goal, test a tool-calling turn and watch the
   logs (`RUST_LOG=opensub=debug`) to confirm `function_call` deltas flow back.
3. If a new error appears, the two most likely culprits are:
   - the SSE event names (`response.function_call_arguments.delta` etc.) not
     matching what the backend actually emits — cross-check against
     `docs/ARCHITECTURE.md` §5 and add any missing events to the translator.
   - `tool_calls[].index` correlation — Cursor is picky about per-call indexing;
     `StreamTranslator::call_indices` must stay consistent.

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

# run for Cursor
opensub serve --tunnel
# → note the trycloudflare URL + API key, put both in Cursor
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
| Chat→Responses request translation | `src/translate/request.rs` |
| Responses→Chat SSE translation + incremental stream | `src/translate/stream.rs` |
| Type definitions | `src/types/{chat,responses}.rs` |

User-facing docs: `README.md`. Deep technical: `docs/ARCHITECTURE.md`.

---

## One-line summary for the next agent

> OpenSub (Rust, `~/CursorOpenSub`) is a working OpenAI-compatible proxy that
> routes Cursor to a ChatGPT subscription via the Codex backend, presenting as
> OpenCode. OAuth, translation, incremental streaming, tunnel, and API-key auth
> are all implemented and verified up to a `tools[7]: missing field function`
> bug that was just fixed — **the next step is `cargo install --path . --force`
> and a live Cursor retest.** Read `docs/ARCHITECTURE.md` for the translation
> internals before touching `translate/`.
