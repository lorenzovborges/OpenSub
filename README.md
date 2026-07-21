# OpenSub

A lightweight **selective Cursor proxy** and OpenAI-compatible API server that
routes OpenAI models to the Codex backend using your **ChatGPT (Plus/Pro)
subscription** — no OpenAI API key and no per-token API billing.

It mirrors the OpenAI API (`/v1/models`, `/v1/chat/completions`) so that tools
like **Cursor** can use it as a drop-in OpenAI provider. Internally it accepts
both legacy Chat Completions-shaped bodies and the Responses-shaped bodies
Cursor sends on `/v1/chat/completions`, forwards them to the Codex backend, and
translates the streaming response back to Chat Completions SSE. Authentication
uses the same OAuth "Sign in with ChatGPT" flow the Codex CLI and OpenCode use.

The recommended `cursor proxy` mode works with the official Cursor application
without changing its API-key or base-URL settings. It translates Cursor's
Connect/protobuf Agent stream, asks Cursor to execute tools locally, and sends
only OpenAI-family model inference to Codex. Composer, Grok, Claude, Gemini, and
other native models continue to use the Cursor subscription.

---

## How it works

```
 Official Cursor ──AgentService/Run──► OpenSub local process capture
                                           │
                     ┌─────────────────────┴─────────────────────┐
                     │ requested model                           │
                  gpt-*/o*/codex                         Composer/Grok/etc.
                     │                                           │
             Codex Responses API                         Cursor backend
                     │                                           │
                     └──────────── Agent stream ──────────────────┘
```

On macOS this uses mitmproxy Local Capture restricted to Cursor processes. It
does not change the system proxy and does not route other applications through
OpenSub. The separate `serve` mode remains available for OpenAI-compatible
clients and supports an optional Cloudflare tunnel.

---

## Quick start

### 1. Build & install

```bash
cargo install --path .
brew install --cask mitmproxy
```

### 2. Log in with ChatGPT (once)

```bash
opensub login
```

Opens a browser for the ChatGPT OAuth flow. Tokens are stored at
`~/.opensub/auth.json` (mode `0600`).

### 3. Quit Cursor and start selective routing

```bash
opensub cursor proxy
```

OpenSub launches the official Cursor and prints only route metadata:

```
→ Cursor traffic capture: active
→ Official Cursor launched; only Cursor processes are captured.
→ Non-Cursor applications are not routed through OpenSub.
```

The first run may ask macOS to approve mitmproxy's network extension and trust
OpenSub's local certificate. Press `Ctrl-C` to stop routing.

### 4. Use Cursor normally

Do not enable a custom OpenAI API key and do not override the OpenAI base URL.
Select an OpenAI model to use the ChatGPT subscription through OpenSub, or
select Composer/Grok/etc. to use the Cursor subscription unchanged.

Then send a message in chat / agent mode.

---

## Commands

```
opensub                 # login if not logged in, otherwise serve (no tunnel)
opensub login           # sign in with ChatGPT (browser OAuth)
opensub logout          # delete stored tokens
opensub key             # print your API key
opensub key rotate      # generate and persist a new API key
opensub cursor proxy    # launch official Cursor with selective local routing
opensub cursor proxy --capture-protocol # diagnostic: capture and block one Agent request
opensub probe           # debug: send a minimal request to the upstream
opensub serve           # start the API server (localhost only)
opensub serve --tunnel  # start server + Cloudflare quick tunnel (for Cursor)
opensub serve --port 9000 --host 127.0.0.1
```

---

## Keep Cursor models while routing GPT to OpenSub (macOS)

Cursor currently applies an enabled OpenAI BYOK configuration to models that
are not Claude or Gemini. That means explicitly selected Cursor models such as
Composer and Grok can incorrectly receive the OpenSub credentials and fail.

Run the process-level proxy with Cursor fully closed:

| Model family | Route |
|---|---|
| `gpt-*`, `o*`, `*codex*` | OpenSub / ChatGPT Codex backend |
| `claude-*`, `gemini-*` | Cursor subscription |
| Composer, Grok, Kimi, GLM, other models | Cursor subscription |

```bash
opensub cursor proxy
```

The official `/Applications/Cursor.app` is launched without modification and
keeps its normal updater. OpenSub does not create a second Cursor app or patch
the installed application bundle.

---

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `OPENSUB_HOST` | `127.0.0.1` | Bind address |
| `OPENSUB_PORT` | `8788` | Bind port |
| `OPENSUB_API_KEY` | *(auto-generated)* | The key clients must present. If unset, one is generated and persisted to `~/.opensub/api_key` |
| `OPENSUB_UPSTREAM` | `https://chatgpt.com/backend-api/codex` | Inference upstream base URL |
| `OPENSUB_ALLOW_CUSTOM_UPSTREAM` | *(unset)* | Set to `1` only when you intentionally want to send your OAuth token to a custom `OPENSUB_UPSTREAM` |
| `OPENSUB_HOME` | `~/.opensub` | Data directory (tokens, api key) |
| `OPENSUB_USER_AGENT_VERSION` | `local` | Version in the `opencode/<v>` User-Agent |
| `OPENSUB_CURSOR_MODEL` | *(automatic)* | Override the Codex model used for intercepted Cursor OpenAI model IDs |
| `RUST_LOG` | `opensub=info` | Log level |

---

## Authentication & identity

OpenSub presents itself as **OpenCode** to OpenAI's auth server — the same
OAuth flow and client id that the [`sst/opencode`](https://github.com/sst/opencode)
project uses:

- **OAuth flow:** PKCE (S256), scopes `openid profile email offline_access`
- **Client ID:** `app_EMoamEEZ73f0CkXaXp7hrann` *(OpenCode's public client id)*
- **Callback:** `http://localhost:1455/auth/callback`
- **User-Agent on auth requests:** `opencode/<version>`

The resulting access token works against the **ChatGPT/Codex backend**
(`chatgpt.com/backend-api/codex/responses`), not the public
`api.openai.com/v1/responses` (which requires an API-key scope that the
subscription token lacks — the public endpoint returns 401 with
`Missing scopes: api.responses.write`).

### Server-side access control

Because the server is exposed via a public tunnel, **OpenSub enforces an API
key** on every request. The key is auto-generated on first run (or set via
`OPENSUB_API_KEY`). Without a valid key, requests get `401`. This prevents
anyone with the tunnel URL from draining your subscription.

Rotate the persisted key anytime with:

```bash
opensub key rotate
```

Then update Cursor's OpenAI API Key field and restart any running OpenSub
server. If `OPENSUB_API_KEY` is set, that environment value takes precedence and
must be changed directly.

---

## API reference

OpenSub exposes an OpenAI-compatible API:

### `GET /v1/models`
Returns the static list of models (configurable in `src/config.rs`).

### `POST /v1/chat/completions`
OpenSub accepts both standard OpenAI Chat Completions bodies and
Responses-shaped bodies that Cursor may send on this path. Both `stream: true`
and `stream: false` are supported (non-streaming is internally buffered — the
Codex backend mandates `stream: true` upstream).

#### Request handling details

- `input[]` present: sanitize and pass through as a Responses request,
  preserving Cursor custom/freeform tools such as `ApplyPatch`.
- `messages[]` present: translate legacy Chat Completions messages into a
  Responses request.

Both paths force `stream:true`, `store:false`, include
`reasoning.encrypted_content`, default `parallel_tool_calls:true`, and keep
`prompt_cache_key` aligned with the `session_id` header.

#### Legacy translation details (Chat Completions → Responses)

| Chat Completions | Responses |
|---|---|
| `messages[role=system]` | `instructions` (concatenated) |
| `messages[role=user]` | `input[] message / input_text` |
| `messages[role=assistant]` | `input[] message / output_text` |
| `messages[role=assistant].tool_calls` | `input[] function_call` |
| `messages[role=tool]` | `input[] function_call_output` |
| `tools[].function` | `tools[] {type:"function", name, description, parameters}` |
| — | `store:false`, `tool_choice:"auto"` (defaults) |

For legacy `messages[]` requests, non-`function` tools are dropped. For
Responses-shaped Cursor requests, tool definitions are preserved so
custom/freeform tools can round-trip through the Codex backend.

### Path aliases
Routes are also served **without** the `/v1` prefix (`/models`,
`/chat/completions`) for client compatibility.

---

## Troubleshooting

### `Access to private networks is forbidden`
Cursor blocks private addresses. Start with `opensub serve --tunnel` and use the
`https://*.trycloudflare.com` URL (with `/v1`) as the base URL.

### Tools don't execute / Cursor talks about edits instead of editing
For `opensub cursor proxy`, reinstall the current source and restart Cursor
through the proxy. The transparent bridge streams both sides of the bidirectional
Agent request and uses Cursor's native `ExecServerMessage` shapes for workspace
tools.

```bash
cargo install --path . --force
opensub cursor proxy
```

Metadata-only lifecycle events are written to
`~/.opensub/cursor-proxy/events.jsonl`. A healthy tool turn contains
`route_opensub`, `tool_requested`, `tool_completed`, and `generation_completed`.

For the OpenAI-compatible `serve` mode, Responses-shaped custom tools and
`custom_tool_call` stream events are preserved, but the client remains
responsible for executing returned tools.

### Cursor reports `Network disconnected` or `ERR_CERT_AUTHORITY_INVALID`
Quit Cursor and restart `opensub cursor proxy`. OpenSub now verifies that its
exact local CA is present in the login Keychain and has user trust settings;
certificate presence alone is not treated as sufficient.

### `tools[7]: missing field function`
Fixed — OpenSub accepts any tool shape. In Responses-shaped Cursor requests, it
preserves custom tools; in legacy Chat-shaped requests, it forwards only
`function` tools.

### `broken pipe` / cloudflared `Unable to reach the origin service`
Was caused by buffering the entire upstream response before sending. Fixed —
OpenSub now streams frames incrementally.

### `401 Unauthorized` from upstream with `Missing scopes`
Means the upstream is set to `api.openai.com/v1` (public Responses endpoint),
which the subscription token can't access. Use the default
`chatgpt.com/backend-api/codex` upstream instead.

### `refusing to send OAuth token to unsupported OPENSUB_UPSTREAM host`
OpenSub only sends your ChatGPT OAuth token to `chatgpt.com` or
`api.openai.com` by default. If you are intentionally testing a trusted custom
proxy, set `OPENSUB_ALLOW_CUSTOM_UPSTREAM=1`.

### `400 Stream must be set to true`
The Codex backend mandates streaming. OpenSub always streams upstream now and
buffers for non-streaming clients — you shouldn't see this from Cursor.

---

## Project layout

```
src/
├── main.rs             # CLI (login/logout/key/probe/serve), tunnel spawn
├── config.rs           # constants (client_id, URLs), env vars, model list
├── auth/
│   ├── mod.rs          # login(), ensure_valid_token() (lazy refresh), logout()
│   ├── oauth.rs        # PKCE, authorize URL, code exchange, refresh
│   ├── callback.rs     # ephemeral axum server on :1455 for OAuth redirect
│   └── store.rs        # ~/.opensub/auth.json (0600), JWT parsing for exp/account_id
├── api/
│   ├── mod.rs          # router, API-key middleware, chat_completions handler
│   └── models.rs       # GET /v1/models
├── codex/
│   └── client.rs       # POST {upstream}/responses → ByteStream, probe()
├── cursor_agent.rs     # Cursor Connect/protobuf bridge, tools, blobs, routing
├── cursor_proxy.rs     # macOS process capture and native-model passthrough
├── translate/
│   ├── request.rs      # ChatCompletions → Responses
│   └── stream.rs       # Responses SSE → ChatCompletions SSE (incremental streaming)
└── types/
    ├── chat.rs         # serde: Chat Completions request/chunk types
    └── responses.rs    # serde: Responses request + SSE event struct
```

---

## Notes & caveats

- **Terms of Service:** Using a ChatGPT subscription outside the official
  ChatGPT/Codex clients is a gray area. OpenSub is for **personal use**. The
  risk of account action is the same as any third-party client reusing these
  OAuth flows.
- **Cursor Tab (autocomplete)** does not work with custom endpoints — that's a
  Cursor limitation, not an OpenSub one. Chat and Agent modes work.
- **Quick tunnels are ephemeral:** the `trycloudflare.com` URL changes on every
  `opensub serve --tunnel` restart. For a stable URL, set up a named Cloudflare
  tunnel (not yet bundled).
- **Model availability** depends on your subscription tier; the list in
  `config.rs` is just what's advertised to Cursor.
- **Transparent Cursor routing is experimental and macOS-only.** Cursor protocol
  updates may require a compatible OpenSub update.

---

## Build

```bash
cargo build --release
# binary: target/release/opensub
```

Release profile is configured with `strip`, `lto`, `panic = "abort"`, and
`codegen-units = 1` for a small, optimized binary.

---

## License

OpenSub is released under the [MIT License](LICENSE).
