# OpenSub

OpenSub routes OpenAI-family models selected in the official Cursor app to the
Codex backend using a ChatGPT Plus/Pro subscription. Composer, Grok, Claude,
Gemini, and unknown model families continue to use Cursor normally.

The recommended integration is a transparent, process-scoped proxy for macOS.
It does not require an OpenAI API key, a custom base URL, a modified Cursor
application, or a terminal that stays open.

OpenSub also provides an optional OpenAI-compatible HTTP server for other
clients. That server exposes `/v1/models` and `/v1/chat/completions`, supports
streaming, and can create a Cloudflare quick tunnel.

> [!WARNING]
> Transparent Cursor routing is experimental and depends on Cursor's internal
> Agent protocol. Cursor updates can require a matching OpenSub update. Using a
> ChatGPT subscription through a third-party client may also be restricted by
> provider terms. Use this project only with accounts and machines you control.

## Choose a mode

| Mode | Intended use | API key | Public tunnel | Persistent |
|---|---|---:|---:|---:|
| `opensub cursor proxy` | Official Cursor on macOS | No | No | Yes, LaunchAgent |
| `opensub serve` | Local OpenAI-compatible clients | Yes | No | No |
| `opensub serve --tunnel` | Remote/cloud clients | Yes | Cloudflare quick tunnel | No |

For Cursor, use `opensub cursor proxy` unless you specifically need the HTTP
API. Do not combine transparent mode with Cursor's OpenAI API-key or base-URL
overrides.

## How transparent routing works

```text
Official Cursor -> mitmproxy Local Capture -> OpenSub bridge
                                              |
                     +------------------------+-----------------------+
                     | requested model                                |
             gpt-*, chatgpt-*, o*, *codex*                   everything else
                     |                                                |
          ChatGPT Codex Responses backend                    Cursor backend
                     |                                                |
                     +--------------- Agent stream -------------------+
```

Local Capture is restricted to Cursor processes, and the addon rewrites only
`/agent.v1.AgentService/Run`. OpenSub does not configure a system-wide proxy and
does not route other applications. The local bridge uses TLS/HTTP/2 and a
random per-process secret.

For OpenAI-family requests, OpenSub translates Cursor's Connect/protobuf Agent
stream to the Codex Responses protocol. Cursor still executes workspace tools
and subagents in its own harness; OpenSub only relays their schemas, calls, and
results. Native model traffic is passed through as a byte stream to Cursor.

OpenSub reconstructs each intercepted request with Cursor's root prompts,
conversation summary, prior user messages, and prior assistant messages. This
uses prefetched Cursor blobs when available, Cursor's local per-conversation
transcript when the Agent request provides its trusted project path, and a
bounded in-memory cache for turns completed through OpenSub. OpenSub only reads
the transcript; Cursor owns and writes it. The local transcript lets GPT turns
retain text history across worker restarts and after native-model turns. Exact
historical tool-result payloads are still best-effort and may need to be
re-read by the model.

## Requirements

Transparent Cursor mode requires:

- macOS and the official `/Applications/Cursor.app` installation.
- A ChatGPT Plus/Pro account for Codex inference.
- Rust 1.85 or newer and Cargo.
- [Homebrew](https://brew.sh/) and mitmproxy.

The optional tunnel mode additionally requires `cloudflared`.

## Install

```bash
git clone https://github.com/lorenzovborges/OpenSub.git
cd OpenSub

brew install --cask mitmproxy
cargo install --path . --locked
```

Then authenticate once:

```bash
opensub login
```

The browser-based OAuth flow stores tokens in `~/.opensub/auth.json` with mode
`0600`.

## Start Cursor routing

```bash
opensub cursor proxy
```

On first use, macOS may ask you to approve mitmproxy's network extension and
trust the local `OpenSub Cursor Proxy` certificate. OpenSub then installs and
starts this per-user LaunchAgent:

```text
~/Library/LaunchAgents/com.opensub.cursor-proxy.plist
```

The command returns after the worker is ready. No terminal needs to remain
open. If Cursor is already running, OpenSub refreshes its network process; if
that is not possible, Cursor is relaunched.

Check the state:

```bash
opensub cursor status
```

In Cursor:

1. Leave the custom OpenAI API key disabled.
2. Leave the OpenAI base URL unchanged.
3. Select a model and use Chat or Agent normally.

### Model routing

| Cursor model ID | Destination |
|---|---|
| `gpt-*`, `chatgpt-*`, `o1`-`o9*`, `*codex*` | OpenSub / ChatGPT Codex backend |
| Composer, Grok, Claude, Gemini, Kimi, GLM, unknown models | Cursor backend |

Recognized Codex model IDs, including `gpt-5.6-sol`, `gpt-5.6-terra`, and
`gpt-5.6-luna`, are preserved. A reasoning suffix such as `-xhigh` is removed
from the upstream model ID and sent as `reasoning.effort`. Unknown OpenAI-family
IDs fall back to `gpt-5.5`. Set `OPENSUB_CURSOR_MODEL` before running
`opensub cursor proxy` to force a specific upstream model.

Cursor subagents always inherit the parent's Cursor model and reasoning
variant. For example, a parent using `gpt-5.6-sol` at Extra High creates the
child with `gpt-5.6-sol-xhigh`. Model aliases suggested inside a Task call,
including `fast` or `auto`, cannot override that selection. The OpenAI-family
child is intercepted by OpenSub like any other Agent run.

## Service lifecycle

| Action | Command | Result |
|---|---|---|
| Install, update, or start | `opensub cursor proxy` | Enables and starts the LaunchAgent |
| Observe native Cursor | `opensub cursor trace` | Forwards everything to Cursor cloud and records the Agent body |
| Inspect | `opensub cursor status` | Reports active, starting, stopped, or not installed |
| Stop | `opensub cursor stop` | Stops and disables it across future macOS logins |
| Start again | `opensub cursor proxy` or `opensub cursor trace` | Re-enables the selected mode |
| Uninstall service | `opensub cursor uninstall` | Removes plist, service logs, and traces; keeps OAuth and local CA |

While enabled, the LaunchAgent starts automatically when the user logs in and
restarts the worker if it exits. `cursor stop` is persistent: the service stays
disabled until another explicit `cursor proxy` or `cursor trace` command.

## Update

From the cloned repository:

```bash
git pull --ff-only
cargo install --path . --locked --force
opensub cursor proxy
```

The last command updates the LaunchAgent configuration and restarts the worker
with the new binary. To update while keeping routing stopped:

```bash
opensub cursor stop
cargo install --path . --locked --force
```

## Optional OpenAI-compatible API

Start a local server:

```bash
opensub serve
```

Default endpoint: `http://127.0.0.1:8788/v1`.

For a client that cannot reach localhost:

```bash
brew install cloudflared
opensub serve --tunnel
```

OpenSub prints a temporary `https://*.trycloudflare.com/v1` base URL and an API
key. Quick-tunnel URLs change whenever the command restarts. A stable named
Cloudflare tunnel is not managed by OpenSub.

Every HTTP API route requires either:

```http
Authorization: Bearer <opensub-api-key>
```

or:

```http
x-api-key: <opensub-api-key>
```

Inspect or rotate the persisted key:

```bash
opensub key
opensub key rotate
```

API-key rotation affects only `serve` mode. Transparent Cursor routing uses its
own random loopback secret and does not use this API key.

## Commands

```text
opensub                         Login when unauthenticated; otherwise serve locally
opensub login                   Sign in with ChatGPT in a browser
opensub logout                  Delete stored OAuth tokens
opensub probe                   Send a minimal Codex request for diagnosis

opensub cursor proxy            Install/update/start transparent routing
opensub cursor proxy --trace    Start routing with a full local protocol trace
opensub cursor trace            Observe the untouched official Cursor flow
opensub cursor status           Show LaunchAgent health and policy
opensub cursor stop             Stop and disable transparent routing
opensub cursor uninstall        Remove the LaunchAgent and service logs

opensub key                     Show the HTTP API key
opensub key rotate              Rotate the persisted HTTP API key
opensub serve                   Start the local OpenAI-compatible server
opensub serve --tunnel          Start the server and a Cloudflare quick tunnel
```

`opensub cursor proxy --capture-protocol` is a developer diagnostic. It stores
the next Agent request locally, blocks that request from reaching Cursor, and
may capture prompt context. Do not use it during normal operation or share the
result.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `OPENSUB_HOME` | `~/.opensub` | Token, key, CA, state, and log directory |
| `OPENSUB_UPSTREAM` | `https://chatgpt.com/backend-api/codex` | Inference upstream base URL |
| `OPENSUB_ALLOW_CUSTOM_UPSTREAM` | unset | Explicitly allow a custom upstream to receive the OAuth token |
| `OPENSUB_USER_AGENT_VERSION` | `local` | Version in the OAuth `opencode/<version>` User-Agent |
| `OPENSUB_CURSOR_MODEL` | automatic | Force intercepted Cursor requests to one Codex model |
| `OPENSUB_MITMDUMP` | auto-detected | Override the `mitmdump` executable path |
| `OPENSUB_HOST` | `127.0.0.1` | HTTP API bind address |
| `OPENSUB_PORT` | `8788` | HTTP API bind port |
| `OPENSUB_API_KEY` | generated file | Override the HTTP API key; takes precedence over the persisted key |
| `RUST_LOG` | `info` | Global level or `opensub=<level>`: `off`, `error`, `warn`, `info`, `debug`, `trace` |

Environment values used by the LaunchAgent are captured when
`opensub cursor proxy` installs or updates its plist. Run that command again
after changing a proxy-related variable.

## HTTP API

### `GET /v1/models`

Returns the static model list from `src/config.rs`. `/models` is an alias.

### `POST /v1/chat/completions`

`/chat/completions` is an alias. The endpoint accepts:

- Standard Chat Completions requests containing `messages[]`.
- Responses-shaped requests containing `input[]`, as sent by some clients on
  the Chat Completions path.

Both `stream: true` and `stream: false` are accepted. OpenSub always uses
streaming upstream because the Codex backend requires it; non-streaming client
responses are assembled locally.

Responses-shaped requests preserve custom/freeform tools. Legacy
Chat Completions requests translate `function` tools and ignore unsupported
non-function tool shapes.

See [Architecture](docs/ARCHITECTURE.md) for the complete request, tool, and SSE
event mappings.

## Authentication and local data

OpenSub uses browser OAuth with PKCE and the public OpenCode client identity.
The resulting ChatGPT OAuth token is sent to the ChatGPT Codex backend, not to
the public `api.openai.com/v1/responses` endpoint.

| Path | Contents | Mode |
|---|---|---:|
| `~/.opensub/auth.json` | OAuth access, refresh, and ID tokens | `0600` |
| `~/.opensub/api_key` | HTTP API key for `serve` mode | `0600` |
| `~/.opensub/cursor-proxy/` | Local CA key, addon, state, metadata logs | directory `0700`; files `0600` |
| `~/Library/LaunchAgents/com.opensub.cursor-proxy.plist` | Worker command and non-secret environment | `0600` |

The transparent proxy installs a trusted local CA in the user's login
Keychain. Capture is process/path scoped, but possession of any trusted CA
private key is security-sensitive. Do not copy or share files from
`~/.opensub/cursor-proxy`.

OpenSub logs routing and lifecycle metadata only. It does not intentionally log
prompts, OAuth tokens, Cursor authorization headers, tool arguments, tool
outputs, or fetched blob contents. Diagnostic protocol captures are the
exception and can contain prompt data.

There are two distinct full-trace modes:

```bash
# OpenSub still routes GPT requests to Codex and records the translated flow.
opensub cursor proxy --trace

# OpenSub does not route or translate anything; Cursor uses its own cloud.
opensub cursor trace
```

`proxy --trace` writes `protocol-trace.jsonl` and includes Cursor protobuf,
normalized routing metadata, complete Codex Responses request bodies, SSE,
tool/subagent results, and frames returned to Cursor. `cursor trace` writes
`cursor-native-trace.jsonl` and records the raw bidirectional Agent request and
response body chunks while forwarding them unchanged to Cursor's cloud. It is
the reference capture for studying Cursor's official harness behavior.

Both files live under `~/.opensub/cursor-proxy/`, use mode `0600`, exclude
authentication headers and OAuth tokens, are capped at 512 MiB, and are
replaced when their respective mode starts again. Stop collection with
`opensub cursor stop`. Treat either trace as sensitive: it can contain prompts,
source code, terminal output, third-party tool data, and credentials embedded
inside protobuf bodies (for example a custom provider key passed to a
subagent), even though HTTP authentication headers are excluded.

Generate a content-free structural report from a native trace with:

```bash
python3 scripts/analyze_cursor_trace.py \
  ~/.opensub/cursor-proxy/cursor-native-trace.jsonl
```

Raw frame extraction is available through `--dump-frames`, but those files are
sensitive. The analyzer creates reports and dumps with mode `0600` and dump
directories with mode `0700`.

Read [SECURITY.md](SECURITY.md) before exposing the HTTP API or reporting a
vulnerability.

## Troubleshooting

### Verify routing

```bash
opensub cursor status
tail -f ~/.opensub/cursor-proxy/events.jsonl
```

An intercepted OpenAI turn records `route_opensub`; a native-model turn records
`route_cursor`. Tool turns additionally record `tool_requested`,
`tool_completed`, and `generation_completed`.

### Cursor uses its own quota for a GPT model

Confirm that transparent routing is active and that Cursor's custom OpenAI API
key/base URL are disabled. Then update and restart OpenSub:

```bash
cargo install --path . --locked --force
opensub cursor proxy
```

### Composer or Grok fails with `Agent action is not a user message`

Update OpenSub. Older builds fully decoded every Agent action before selecting
the route. Current builds inspect the model first and pass native actions
through without requiring a user-message shape.

### Tools are described but not executed

Inspect `events.jsonl`. A healthy tool turn has both `tool_requested` and
`tool_completed`. Reinstall and restart if the installed binary is stale:

```bash
cargo install --path . --locked --force
opensub cursor proxy
```

Current builds expose MCP to the model through `GetMcpTools` and `CallMcpTool`,
matching Cursor's discovery-first flow. The actual MCP call still runs in
Cursor's harness; OpenSub only translates its request and result.

### Shell fails with `Parsing result is required`

Install the current build. Cursor's current Agent protocol uses shell execution
field `14` and streams start/output/completion events; older OpenSub builds used
the obsolete field `2` shape and treated the first stream event as the result.

```bash
cargo install --path . --locked --force
opensub cursor proxy
```

### A tool turn keeps running without finishing

OpenSub does not impose a fixed tool-round limit. A turn continues while the
model requests tools and ends when the model returns a final response, an
upstream error occurs, or Cursor closes the stream. Cancel the request in
Cursor if the model enters a repetitive tool loop.

### `Network disconnected` or `ERR_CERT_AUTHORITY_INVALID`

Run `opensub cursor proxy` again. OpenSub verifies the exact local CA
fingerprint and its user trust settings. If startup still fails, inspect:

```bash
tail -n 100 ~/.opensub/cursor-proxy/service-error.log
tail -n 100 ~/.opensub/cursor-proxy/service.log
```

### `Access to private networks is forbidden`

This applies to `serve` mode when the client runs remotely. Use
`opensub serve --tunnel` and configure the printed HTTPS `/v1` URL. Transparent
`cursor proxy` mode does not need a public URL.

### `401 Missing scopes: api.responses.write`

The OAuth subscription token was sent to the public OpenAI API. Remove the
`OPENSUB_UPSTREAM` override or use the default ChatGPT Codex backend.

### `refusing to send OAuth token to unsupported OPENSUB_UPSTREAM host`

OpenSub only allows HTTPS `chatgpt.com` and `api.openai.com` upstreams by
default. Set `OPENSUB_ALLOW_CUSTOM_UPSTREAM=1` only for an upstream you fully
trust, because it receives your OAuth bearer token.

### Historical warnings remain in the logs

Service logs persist across updates. Stop routing before clearing them:

```bash
opensub cursor stop
: > ~/.opensub/cursor-proxy/service.log
: > ~/.opensub/cursor-proxy/service-error.log
```

## Remove OpenSub

Remove the service and OAuth tokens:

```bash
opensub cursor uninstall
opensub logout
```

To also remove the trusted CA, local state, API key, and binary:

```bash
security delete-certificate -c "OpenSub Cursor Proxy" \
  ~/Library/Keychains/login.keychain-db
rm -rf ~/.opensub
cargo uninstall opensub
```

`cursor uninstall` intentionally keeps the OAuth login and local CA so that a
later reinstall does not require authorization and certificate setup again.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo audit
cargo build --release
```

The release profile enables stripping, LTO, abort-on-panic, and one codegen unit.
See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request and read
[Architecture](docs/ARCHITECTURE.md) before changing routing, streaming, or
protobuf translation.

## Project layout

```text
src/
|-- main.rs              CLI, API server, and Cloudflare process
|-- config.rs            Identity constants, paths, environment, model list
|-- auth/                 OAuth, callback server, token refresh and storage
|-- api/                  OpenAI-compatible routes and API-key middleware
|-- codex/client.rs       Shared Codex HTTP client and streaming request
|-- cursor_agent.rs       Connect/protobuf routing and tool execution bridge
|-- cursor_proxy.rs       LaunchAgent, Local Capture, TLS, CA, and lifecycle
|-- translate/            Chat/Responses request and SSE translation
`-- types/                API wire types
```

## License

OpenSub is available under the [MIT License](LICENSE).
