# AGENTS.md

## Project

KeyFence is a credential tokenization proxy for AI agents, written in Go.
Single binary. It MITM-proxies HTTPS traffic and runs an SSH bastion,
swapping opaque `kf_` tokens for real credentials so agents never possess
raw secrets.

## Tech stack

- Go 1.25+
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
internal/sshproxy/sshproxy.go  SSH bastion (SSH key injection)
internal/luaengine/engine.go   Sandboxed Lua VM pool for response rule evaluation
internal/luaengine/convert.go  Go/Lua bidirectional type conversion
internal/telemetry/telemetry.go OpenTelemetry tracing initialization
internal/audit/audit.go        Structured JSON audit logging + sink fan-out
internal/audit/webhook.go      Webhook sink (async delivery, HMAC signing)
internal/audit/sse.go          Server-Sent Events sink
demo/                          Interactive demo (podman pod + scripts)
examples/claude-github/        Worked example: Claude Code + GitHub PAT
examples/claude-code/          Worked example: Claude Code + Anthropic API sidecar
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
- SSH bastion authenticates agents with kf_ tokens. KeyFence holds the real SSH
  private key and bridges exec sessions to the upstream host. The agent never
  has the key.
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

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:970c3bf2 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   bd dolt push
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->

<!-- BEGIN BEADS CODEX SETUP: generated by bd setup codex -->
## Beads Issue Tracker

Use Beads (`bd`) for durable task tracking in repositories that include it. Use the `beads` skill at `.agents/skills/beads/SKILL.md` (project install) or `~/.agents/skills/beads/SKILL.md` (global install) for Beads workflow guidance, then use the `bd` CLI for issue operations.

### Quick Reference

```bash
bd ready                # Find available work
bd show <id>            # View issue details
bd update <id> --claim  # Claim work
bd close <id>           # Complete work
bd prime                # Refresh Beads context
```

### Rules

- Use `bd` for all task tracking; do not create markdown TODO lists.
- Run `bd prime` when Beads context is missing or stale. Codex 0.129.0+ can load Beads context automatically through native hooks; use `/hooks` to inspect or toggle them.
- Keep persistent project memory in Beads via `bd remember`; do not create ad hoc memory files.

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.
<!-- END BEADS CODEX SETUP -->
