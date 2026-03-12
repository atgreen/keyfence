# AGENTS.md

## Project

KeyFence is a credential tokenization proxy for AI agents, written in Go.
Single binary, no external dependencies. It MITM-proxies HTTPS traffic,
swapping opaque `kf_` tokens for real credentials so agents never possess
raw secrets.

## Tech stack

- Go 1.22+
- No third-party dependencies (stdlib only)
- Container runtime: podman or docker

## Repository layout

```
cmd/keyfence/main.go          Entry point, CLI flags, HTTP API handlers
internal/proxy/proxy.go        MITM forward proxy (CONNECT tunneling, token swap)
internal/proxy/ca.go           Local ECDSA P-256 CA, on-the-fly cert generation
internal/tokenstore/store.go   In-memory token store (issue, resolve, revoke)
internal/credstore/credstore.go Credential backend + cert store (header creds, client certs)
internal/policy/policy.go      Policy engine (methods, paths, rate limits, budgets)
internal/audit/audit.go        Structured JSON audit logging
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
2. Starts keyfence on `:10210` (proxy) and `:10212` (API)
3. Runs integration tests against the live process
4. Cleans up on exit

Tests require `curl` and `python3` on PATH. Set `ANTHROPIC_API_KEY` for
a full round-trip test against the real API; otherwise a dummy key is used
and 401s from Anthropic are expected and accepted.

## Code style

- All source files have SPDX license headers
- No third-party dependencies — stdlib only
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
- All proxy actions emit structured JSON audit logs with token_id, agent_id, and task_id.

## Git conventions

- Conventional-ish commit messages: start with a verb ("Add", "Fix", "Update")
- One logical change per commit
- No force-pushing to main

## Do not modify

- `go.sum` — managed by `go mod tidy`
- `LICENSE` — MIT, do not change
