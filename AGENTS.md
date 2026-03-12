# AGENTS.md

## Project

KeyFence is a credential tokenization proxy for AI agents, written in Go.
Single binary. It MITM-proxies HTTPS traffic and runs an SSH bastion,
swapping opaque `kf_` tokens for real credentials so agents never possess
raw secrets.

## Tech stack

- Go 1.22+
- Dependencies: `golang.org/x/crypto` (SSH bastion), OpenTelemetry (optional tracing), `gopher-lua` (response rule scripting)
- Container runtime: podman or docker

## Repository layout

```
cmd/keyfence/main.go          Entry point, CLI flags, HTTP API handlers
internal/proxy/proxy.go        MITM forward proxy (CONNECT tunneling, token swap)
internal/proxy/ca.go           Local ECDSA P-256 CA, on-the-fly cert generation
internal/tokenstore/store.go   In-memory token store (issue, resolve, revoke)
internal/credstore/credstore.go Credential backend (API keys, client certs, SSH keys)
internal/policy/policy.go      Policy engine (methods, paths, rate limits, budgets)
internal/sshproxy/sshproxy.go  SSH bastion (TCP forwarding, SSH key injection)
internal/luaengine/engine.go   Sandboxed Lua VM pool for response rule evaluation
internal/luaengine/convert.go  Go/Lua bidirectional type conversion
internal/telemetry/telemetry.go OpenTelemetry tracing initialization
internal/audit/audit.go        Structured JSON audit logging + sink fan-out
internal/audit/webhook.go      Webhook sink (async delivery, HMAC signing)
internal/audit/sse.go          Server-Sent Events sink
demo/                          Interactive demo (compose + scripts)
examples/claude-github/        Worked example: Claude Code + GitHub PAT
```

## Commands

```bash
# Build
go build -o ./bin/keyfence ./cmd/keyfence

# Run all integration tests (builds automatically)
./scripts/test.sh

# Or use make
make build
make test
make clean
```

## Testing

There are no unit tests yet. All testing is via `scripts/test.sh`, which:

1. Builds the binary
2. Starts keyfence on `:10210` (proxy), `:10211` (SSH), and `:10212` (API)
3. Runs integration tests against the live process
4. Cleans up on exit

Tests require `curl` and `python3` on PATH. Set `ANTHROPIC_API_KEY` for
a full round-trip test against the real API; otherwise a dummy key is used
and 401s from Anthropic are expected and accepted.

## Code style

- All source files have SPDX license headers
- Minimal dependencies (`golang.org/x/crypto`, OpenTelemetry, `gopher-lua`)
- Packages are small and focused: one file per package is fine
- Error messages are lowercase, no trailing punctuation
- Use `log.Printf` for operational logging, not structured logging

## Architecture notes

- The proxy is completely service-agnostic. It does not know about
  Anthropic, OpenAI, or any specific API.
- Tokens hold a `CredentialID` reference, never raw credential bytes.
  The credential backend fetches the real value on each request.
- Token prefix is `kf_` followed by 32 hex chars.
- The local CA generates per-hostname TLS certs on the fly.
- Client certificates for mTLS upstreams are held by KeyFence; agents never possess private keys.
- SSH bastion authenticates agents with kf_ tokens. Two modes:
  - TCP forwarding (direct-tcpip): any protocol, destination-enforced, bytes untouched.
  - SSH key injection (session exec): KeyFence holds real SSH key, bridges session upstream.
- Destinations support host-only (`api.example.com`) or host+path (`api.example.com/v1/*`)
  with glob matching. Fully backward compatible.
- Credentials can be rotated via `PUT /credentials/{id}` without invalidating tokens.
  All tokens referencing that credential get the new value on their next request.
- Tokens can carry Lua response rules evaluated against each upstream JSON response.
  Scripts run in a sandboxed VM (no os/io/require, 500ms timeout, 100k instruction cap).
  Scripts access `response` (parsed JSON), `state` (persists across requests),
  `response_headers`, and `response_status`. Return `{action="revoke"}` or `{action="alert"}`.
  SSE streaming responses are handled by capturing the last `data:` line.
- Audit events fan out to multiple sinks: stdout (default), SSE (`GET /events`),
  and registered webhooks (`POST /webhooks`) with optional HMAC-SHA256 signing.
- All proxy and SSH actions emit structured JSON audit logs with token_id, agent_id, and task_id.
- OpenTelemetry distributed tracing on all proxy and SSH operations. Configured via
  standard `OTEL_*` env vars. Silently disabled when no collector is reachable.

## Git conventions

- Conventional-ish commit messages: start with a verb ("Add", "Fix", "Update")
- One logical change per commit
- No force-pushing to main

## Do not modify

- `go.sum` — managed by `go mod tidy`
- `LICENSE` — MIT, do not change
