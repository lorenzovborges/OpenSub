# OpenSub — Architecture & Technical Reference

This document is the deep technical reference: data flow, protocol translation
internals, the exact identity constants, and the key engineering decisions. Read
this when modifying the translation logic, the auth flow, or the streaming layer.

## Table of contents
1. [High-level data flow](#1-high-level-data-flow)
2. [Identity & OAuth constants (verbatim)](#2-identity--oauth-constants-verbatim)
3. [The two upstreams problem](#3-the-two-upstreams-problem)
4. [Protocol translation: Chat Completions → Responses](#4-protocol-translation-chat-completions--responses)
5. [Protocol translation: Responses SSE → Chat Completions SSE](#5-protocol-translation-responses-sse--chat-completions-sse)
6. [Streaming architecture (why incremental)](#6-streaming-architecture-why-incremental)
7. [Access control & the public tunnel](#7-access-control--the-public-tunnel)
8. [Token lifecycle & refresh](#8-token-lifecycle--refresh)
9. [Known limitations / gotchas](#9-known-limitations--gotchas)
10. [Transparent Cursor Agent bridge](#10-transparent-cursor-agent-bridge)

---

## 1. High-level data flow

```
┌────────┐ POST /v1/chat/completions            ┌──────────────────────┐
│ Cursor │ ───────────────────────────────────► │  (Cloudflare tunnel) │
│ (cloud)│  Authorization: Bearer <api key>      │  *.trycloudflare.com │
└────────┘                                       └─────────┬────────────┘
                                                           │ http → localhost:8788
                                                           ▼
                                                ┌──────────────────────┐
                                                │  OpenSub (axum)      │
                                                │                      │
                          ┌─────────────────────┤  1. API-key check     │
                          │                     │  2. lazy token refresh│
                          │                     │  3. request translate │
                          │                     │  4. POST /responses   │
                          ▼                     └─────────┬────────────┘
                ┌─────────────────────┐                    │
                │ translate::request  │  builds Responses  │
                │ (ChatCompl→Respons) │ ◄──────────────────┘
                └─────────────────────┘
                                                           │
                                                           ▼
                                          ┌─────────────────────────────┐
                                          │ chatgpt.com/backend-api/    │
                                          │ codex/responses             │
                                          │ Auth: Bearer <ChatGPT token>│
                                          │ + chatgpt-account-id        │
                                          │ + originator: codex_cli_rs  │
                                          └──────────────┬──────────────┘
                                                         │ SSE stream
                                                         ▼
                                          ┌─────────────────────────────┐
                                          │ translate::stream           │
                                          │ (Responses SSE → ChatCompl  │
                                          │  SSE, incremental)          │
                                          └──────────────┬──────────────┘
                                                         │
 Cursor ◄──text/event-stream── tunnel ◄──────────────────┘
```

---

## 2. Identity & OAuth constants (verbatim)

OpenSub presents itself as **OpenCode** (`sst/opencode`) to the OAuth server.
These constants match opencode's source exactly — see `src/config.rs`.

| Constant | Value |
|---|---|
| `CLIENT_ID` | `app_EMoamEEZ73f0CkXaXp7hrann` |
| `ISSUER` / authorize / token | `https://auth.openai.com`, `/oauth/authorize`, `/oauth/token` |
| `REDIRECT_URI` | `http://localhost:1455/auth/callback` |
| `SCOPES` | `openid profile email offline_access` |
| PKCE | S256; verifier = 43 bytes mapped `byte % 64` into `A-Za-z0-9-._~`; challenge = base64url(sha256(verifier)) |
| Authorize extra params | `id_token_add_organizations=true`, `codex_cli_simplified_flow=true`, `originator=opencode` |
| Token exchange | form-encoded, `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier` |
| Token refresh | form-encoded, `grant_type=refresh_token`, `refresh_token`, `client_id` |
| User-Agent (auth) | `opencode/<OPENSUB_USER_AGENT_VERSION>` (default `opencode/local`) |

### Inference headers (on `POST {upstream}/responses`)
| Header | Value |
|---|---|
| `Authorization` | `Bearer <access_token>` |
| `Accept` | `text/event-stream` |
| `Content-Type` | `application/json` |
| `User-Agent` | `codex_cli_rs/0.120.0 (opensub)` |
| `openai-beta` | `responses=experimental` |
| `session_id` | `<prompt_cache_key>` |
| `x-codex-installation-id` | `<per-process session id>` |
| `chatgpt-account-id` | `<account_id from JWT>` *(only when upstream is chatgpt.com)* |
| `originator` | `codex_cli_rs` *(only when upstream is chatgpt.com)* |

`account_id` is extracted from the access-token JWT claim
`https://api.openai.com/auth.chatgpt_account_id` (fallback
`chatgpt_account_id`). See `auth/store.rs::enrich_from_jwt`.

---

## 3. The two upstreams problem

There are two candidate inference endpoints. **Only one works with a
subscription token.**

| Upstream | Auth it accepts | Verdict |
|---|---|---|
| `https://api.openai.com/v1/responses` | API key (scopes `api.responses.write`) | **401** for subscription tokens |
| `https://chatgpt.com/backend-api/codex/responses` | ChatGPT OAuth Bearer + identity headers | **200** ✅ |

We empirically confirmed this: the public endpoint returns
`401 Missing scopes: api.responses.write`; the ChatGPT backend accepts the token
when `chatgpt-account-id` and `originator: codex_cli_rs` are sent.

**Default upstream** is therefore `https://chatgpt.com/backend-api/codex`.
`config::is_chatgpt_upstream_url()` detects this and adds the extra identity headers
automatically in `codex/client.rs`. If you ever want to test the public
endpoint, `OPENSUB_UPSTREAM=https://api.openai.com/v1 opensub probe` reproduces
the 401.

Because the upstream receives the ChatGPT OAuth bearer token, `config::validated_upstream()`
only allows `https://chatgpt.com/...` and `https://api.openai.com/...` by
default. Custom upstreams require `OPENSUB_ALLOW_CUSTOM_UPSTREAM=1` and should
only be used with a trusted proxy.

**The ChatGPT backend mandates `stream: true`** (returns
`400 "Stream must be set to true"` otherwise). So `api/mod.rs` always sets
the prepared body has `stream = true` and buffers for non-streaming clients.

---

## 4. Request normalization: Chat/Responses → Responses

Implemented in `api/mod.rs::prepare_upstream_body()` plus the legacy
`translate/request.rs::translate()` path.

Cursor may call `/v1/chat/completions` with a Responses-shaped body (`input`,
`instructions`, `reasoning`, `tools`, etc.) rather than a classic Chat
Completions `messages[]` body. OpenSub supports both:

- `input[]` present: sanitize allowed Responses fields and pass through,
  preserving Cursor custom/freeform tools.
- `messages[]` present: translate legacy Chat Completions messages into a
  `ResponsesRequest`.

Both paths normalize the upstream request:

```rust
store: false,
stream: true,
service_tier: "priority",
prompt_cache_key: <per-process session id unless Cursor supplied one>,
reasoning.effort: "xhigh" unless Cursor supplied one,
parallel_tool_calls: true,
include: ["reasoning.encrypted_content"],
```

### Legacy message mapping
| Chat `messages[]` | Responses `input[]` |
|---|---|
| `role: system` | concatenated into top-level `instructions` |
| `role: user` | `{type:"message", role:"user", content:[{type:"input_text", text}]}` |
| `role: assistant` (text) | `{type:"message", role:"assistant", content:[{type:"output_text", text}]}` |
| `role: assistant` (`tool_calls`) | one `{type:"function_call", call_id, name, arguments}` per call |
| `role: tool` | `{type:"function_call_output", call_id: tool_call_id, output}` |

`content` may be a string OR an array of content parts; `content_to_string()`
normalizes both to a single string.

### Legacy tool mapping
`ChatTool` is a newtype over raw `serde_json::Value` so **any** tool shape
deserializes (Cursor sends `web_search`, `code_interpreter`, etc. that lack a
`function` field — a strict type caused `missing field function` errors).
`ChatTool::as_function()` parses only `function`-type tools; non-function tools
are dropped on this legacy path. Each function tool is reshaped to the flat
Responses form: `{type:"function", name, description, parameters}`. Responses-
shaped Cursor requests bypass this mapping and preserve tools as-is, including
`type:"custom"` tools such as `ApplyPatch`.

---

## 5. Protocol translation: Responses SSE → Chat Completions SSE

Implemented in `translate/stream.rs`. The `StreamTranslator` state machine
consumes `ResponsesStreamEvent`s and emits `ChatCompletionChunk`s.

### Event handling
| Responses event | Action |
|---|---|
| first text/tool delta | emit leading `{delta:{role:"assistant"}}` chunk (once) |
| `response.output_text.delta` | `{delta:{content:<delta>}}` |
| `response.output_item.added` (`function_call` / `custom_tool_call`) | `{delta:{tool_calls:[{index,id,type:"function",function:{name}}]}}` |
| `response.function_call_arguments.delta` / `response.custom_tool_call_input.delta` | `{delta:{tool_calls:[{index,function:{arguments:<delta>}}]}}` |
| `response.output_item.done` | emits full `arguments` / `input` as fallback if no argument deltas arrived |
| `response.completed` / `response.done` | `{delta:{}, finish_reason:"stop"\|"tool_calls"}` + usage, then `data: [DONE]` |
| `response.failed` / `response.incomplete` | finish with `stop` |
| others (reasoning/metadata) | ignored |

### State
- `sent_role` — ensures the leading role chunk fires once.
- `tool_calls: HashMap<item_id, ToolCallState>` — assigns a stable per-call
  index for `tool_calls[].index` and tracks whether arguments were streamed.
- `next_call_index` — monotonic counter.
- `finished` — guards against double-finish; also lets `translate_stream` emit
  a synthetic finish if the upstream closed without one.

`finish_reason` is `"tool_calls"` if any function call was emitted, else `stop`.

Usage is extracted from `response.usage.{input_tokens,output_tokens}`.

---

## 6. Streaming architecture (why incremental)

**Critical:** OpenSub must emit SSE frames **as they arrive**, not buffer the
whole response. Two reasons:

1. **Broken pipe.** Cloudflare's quick tunnel closes the connection if OpenSub
   doesn't send the first byte quickly. An earlier buffered version
   (`translate_stream → Vec<u8>`) caused `write: broken pipe` /
   `Unable to reach the origin service` because the tunnel timed out waiting.
2. **UX.** Cursor shows tokens as they stream; buffering defeats streaming.

### Implementation
`translate::stream::translate_stream()` returns a
`Stream<Item = Result<Bytes>>`:

- Spawns a tokio task that reads the upstream `BufReader` line-by-line, parses
  each SSE `data:` event, runs the translator, and **sends each produced frame
  through an `mpsc` channel** immediately (`tx.send(...).await`).
- The handler wraps this in `Body::from_stream(out)` (axum streams it back to
  the client). If the client disconnects, `tx.send` returns `Err` and the task
  stops — clean cancellation.
- Non-streaming clients: the handler does `.try_collect::<Vec<_>>().await` to
  buffer, then `non_streaming_response()` collapses all deltas into one
  `{choices:[{message:{content}}]}` object.

`codex/client.rs::post_responses_stream` returns a `ByteStream`
(`Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>`) from
`resp.bytes_stream()`. `translate_stream` converts that to an `AsyncRead` via
`tokio_util::io::StreamReader` for line reading.

---

## 7. Access control & the public tunnel

Because Cursor runs server-side and blocks private networks, OpenSub must be
publicly reachable. A public endpoint with no auth would let anyone drain your
subscription, so **every route passes through `require_api_key` middleware**.

- The key is `config::api_key()`: from `OPENSUB_API_KEY` env, or
  `~/.opensub/api_key` file (auto-generated `sk-opensub-<24 random bytes>` on
  first run, persisted mode `0600`).
- `opensub key rotate` replaces the persisted `~/.opensub/api_key` with a fresh
  key. If `OPENSUB_API_KEY` is set, the environment value takes precedence and
  the command refuses to rotate the ignored persisted key.
- Middleware accepts `Authorization: Bearer <key>` or `x-api-key: <key>`.
  Mismatch → `401`.
- `opensub key` prints it; `opensub serve` prints it at startup.

`opensub serve --tunnel` spawns `cloudflared tunnel --url http://localhost:<port>`
with stdout/stderr captured. OpenSub drains the noisy Cloudflare logs, extracts
the `https://*.trycloudflare.com` URL, and prints only the useful `Tunnel URL`
and `Cursor Base URL` lines. The URL is **ephemeral** — it changes every restart.
(A named, stable tunnel would require a Cloudflare account and isn't yet
bundled.)

---

## 8. Token lifecycle & refresh

`auth/store.rs::TokenData` is persisted to `~/.opensub/auth.json` (mode `0600`):
```json
{
  "access_token": "<JWT>",
  "refresh_token": "<opaque>",
  "id_token": "<JWT>",
  "expires_at": 1782870927,
  "account_id": "<redacted>"
}
```

- **`enrich_from_jwt()`** parses the access token's payload (base64url middle
  segment) to read `exp` (→ `expires_at`) and `chatgpt_account_id` (→
  `account_id`). No signature verification — local use only.
- **`ensure_valid_token()`** (called via `auth::require_token()` on each chat
  request) checks `expiring_within(300)` and refreshes proactively if the access
  token expires within 5 minutes. The refresh also re-persists the new tokens.
- The probe confirmed that a valid `account_id` can be extracted. Values are
  never written to repository documentation or request logs.

---

## 9. Known limitations / gotchas

- **Cursor Tab (autocomplete)** doesn't use custom endpoints — not fixable here.
- **Legacy Chat-shaped non-function tools dropped.** Responses-shaped Cursor
  requests preserve tools as-is, including custom/freeform tools. Only the
  legacy `messages[]` translation path drops non-`function` tools.
- **Quick tunnel ephemeral.** URL rotates each restart.
- **Conversation history is partial in transparent mode.** The bridge consumes
  the current prompt and blobs prefetched in the initial Run request. It does
  not actively fetch every referenced KV blob, so older turns omitted from the
  prefetch may be unavailable to Codex.
- **Tests are focused, not exhaustive.** Current unit tests cover Responses-shaped
  custom tools and tool-call SSE translation; broader recorded fixtures would
  still help.
- **ToS gray area** — same as any third-party ChatGPT-subscription client.

---

## 10. Transparent Cursor Agent bridge

`opensub cursor proxy` uses mitmproxy Local Capture on macOS with a process
filter limited to Cursor, Cursor Helper, and Cursor Helper (Plugin). The addon
rewrites only `/agent.v1.AgentService/Run` to an ephemeral localhost Axum
listener. A random per-process secret header prevents unrelated local callers
from using that listener. If Cursor is already running, OpenSub requests a
graceful quit, waits for the process to exit, activates capture, and relaunches
the official app. A startup failure after that quit also relaunches Cursor.

The local bridge uses TLS with HTTP/2 ALPN because Cursor's Agent transport is a
bidirectional Connect stream. OpenSub generates one private local CA, installs
that exact certificate in the user's login Keychain, verifies both its SHA-256
fingerprint and user trust settings, and passes it to Node-based Cursor helpers.
The private key and generated capture files stay under
`~/.opensub/cursor-proxy` with restrictive permissions.

The Rust bridge reads the first Connect envelope incrementally, decompresses
gzip when requested by the envelope flags, and parses only the protobuf fields
needed to select a route:

| Requested model | Destination |
|---|---|
| `gpt-*`, `o*`, `*codex*` | ChatGPT Codex Responses backend |
| Composer, Grok, Claude, Gemini, unknown/future models | Original Cursor backend |

Native requests and responses remain byte streams; they are not buffered. GPT
requests are translated into Responses input. The addon enables streaming for
both halves of `AgentService/Run`; response buffering would deadlock a tool turn
because OpenSub waits for an `ExecClientMessage` while Cursor waits to receive
the corresponding `ExecServerMessage`.

Prefetched conversation blobs are folded into the Responses input, MCP
definitions become Responses function tools, and core workspace operations
become native `ExecServerMessage` requests. Local execution messages match
Cursor's own mock Agent shape (`id` plus the selected args oneof, without a
synthetic `exec_id`). Tool results returned as `ExecClientMessage` are fed into
the next Responses round. Text deltas, tool lifecycle updates, token usage, and
the Connect end-stream envelope are encoded back as `AgentServerMessage` frames.

The bridge logs route metadata only. Prompt bodies, Cursor authorization
headers, OAuth tokens, blob values, tool arguments, and tool outputs are not
logged. The diagnostic `--capture-protocol` mode is explicit, stores its file
with mode `0600`, and blocks the captured request before the Cursor backend.
