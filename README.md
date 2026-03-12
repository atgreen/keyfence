# KeyFence

**Credential containment for AI agents.**

KeyFence is a single-binary proxy that sits between AI agents and the services they use. Agents never hold real credentials — only short-lived, scoped tokens that KeyFence resolves on each request. With KeyFence you can:

- **Protect any credential type** — API keys, Bearer tokens, Basic auth, mTLS client certificates, and SSH private keys. Agents use opaque `kf_` tokens; real secrets never enter the agent's address space.
- **Lock tokens to specific hosts and paths** — a token for `api.anthropic.com/v1/messages` cannot be used against any other host or endpoint.
- **Enforce policies** — restrict HTTP methods, content types, body sizes, and rate limits per token.
- **Set usage budgets with Lua scripting** — attach Lua scripts that inspect upstream JSON responses, accumulate metrics like LLM token usage across requests, and automatically revoke a token when a budget is exceeded.
- **Rotate credentials without disruption** — swap the underlying secret and all tokens pick up the new value on their next request. No reissuance needed.
- **Inject SSH keys** — agents authenticate to the SSH bastion with a `kf_` token; KeyFence holds the real private key and bridges the session upstream.
- **Monitor everything in real-time** — structured audit logs, Server-Sent Events stream, webhook delivery, and OpenTelemetry distributed tracing on every request.
- **Deploy as a sidecar** — run KeyFence alongside your agent in a podman pod or Kubernetes sidecar. Agents reach the proxy at localhost.

## The Problem

AI agents need API keys, bot tokens, SSH keys, and other credentials to do useful work. As agents gain autonomy — spawning subprocesses, running arbitrary tools, executing code from untrusted inputs — every credential in their environment becomes an exfiltration target.

The attack surface is broad:

- **Prompt injection** tricks the agent into including credentials in outbound messages, tool calls, or generated code
- **Tool-mediated leakage** — the agent runs a tool that reads environment variables, config files, or process memory and sends them to an attacker-controlled endpoint
- **Subprocess escape** — the agent spawns a shell, a Python script, or a compiled binary that has full access to every secret in the environment
- **Accidental exposure** — the agent logs, caches, or returns credentials in its responses

Traditional secret management (Vault, 1Password, environment variables) solves the *storage* problem but not the *runtime* problem. Once a secret is loaded into the agent's process, it can be read and exfiltrated by anything the agent executes.

**If an AI agent can read a credential, that credential can be exfiltrated. KeyFence makes sure it never can.**

## How KeyFence Works

KeyFence is a credential containment proxy for bearer tokens, Basic auth, mTLS client certificates, and SSH keys. It sits between the agent and the internet as an HTTPS proxy and SSH bastion. The agent never possesses real credentials — only short-lived, destination-locked opaque tokens (`kf_...`) that are worthless outside KeyFence.

### Supported credential types

| Type | How it works |
|------|-------------|
| **Bearer / API keys** | Token found in any header value, swapped for real credential |
| **Basic auth** | Token found inside Base64-decoded `Authorization: Basic` header |
| **Client certificates** | KeyFence presents the cert+key on the upstream TLS handshake; agent never has the private key |
| **SSH keys** | Agent authenticates to KeyFence's SSH bastion with a `kf_` token; KeyFence connects upstream with the real SSH key |

> **Scope today:** KeyFence protects credentials carried in HTTP headers, client certificates presented at the TLS layer, and SSH private keys. Credentials that require local cryptographic operations (AWS SigV4 signing, JWT minting) are out of scope for v1 — see [What KeyFence Does Not Defend Against](#what-keyfence-does-not-defend-against).

```
┌──────────────────────────────────────┐
│  Agent Container                     │
│                                      │
│  ANTHROPIC_API_KEY=kf_a3f8b2c1...    │
│  HTTPS_PROXY=http://127.0.0.1:10210  │
│                                      │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│  KeyFence                            │
│                                      │
│  1. Intercept TLS (MITM with CA)     │
│  2. Find kf_ token in headers        │
│  3. Validate: TTL, destination,      │
│     method, path, rate limit         │
│  4. Fetch credential / client cert    │
│  5. Inject credential in header,     │
│     present client cert on upstream  │
│     TLS                              │
│  6. Forward to upstream              │
└──────────────┬───────────────────────┘
               │
               ▼
          api.anthropic.com
```

In the recommended deployment, KeyFence runs as a sidecar in a podman pod or Kubernetes pod. The agent reaches the proxy at `127.0.0.1:10210`. The agent never has real credentials — even if it bypasses the proxy, it has nothing valuable to exfiltrate.

## Quick Start

### Local (no containers)

```bash
# Build
make build

# Start KeyFence
./bin/keyfence

# In another terminal — issue a token
TOKEN=$(curl -sf -X POST http://localhost:10212/tokens \
  -d '{"credential":"sk-ant-your-real-key","destinations":["api.anthropic.com"],"ttl_seconds":300}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Use it
export HTTPS_PROXY=http://127.0.0.1:10210
export SSL_CERT_FILE=~/.keyfence/ca/ca.pem
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $TOKEN" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":64,"messages":[{"role":"user","content":"say hi"}]}'
```

### Podman pod (sidecar)

This is the recommended deployment. KeyFence runs as a sidecar in a podman pod, sharing localhost with the agent.

```bash
# Create pod and shared volume
podman pod create --name kf -p 10212:10212
podman volume create kf-certs

# Start KeyFence
podman run -d --pod kf --name kf-keyfence \
    -v kf-certs:/certs \
    keyfence --certs-dir /certs

# Issue a token
TOKEN=$(curl -sf -X POST http://localhost:10212/tokens \
  -d '{"credential":"sk-ant-your-real-key","destinations":["api.anthropic.com"],"ttl_seconds":300}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Run the agent
podman run -it --rm --pod kf \
    -e "HTTPS_PROXY=http://127.0.0.1:10210" \
    -e "SSL_CERT_FILE=/certs/ca.pem" \
    -e "ANTHROPIC_API_KEY=$TOKEN" \
    -v kf-certs:/certs:ro \
    your-agent-image
```

Containers in the pod share a network namespace, so the agent reaches KeyFence at `127.0.0.1`.

### Worked examples

| Example | Description |
|---------|-------------|
| [`examples/claude-code/`](examples/claude-code/) | Claude Code calling the Anthropic API through KeyFence |
| [`examples/claude-github/`](examples/claude-github/) | Claude Code using a GitHub PAT through KeyFence |
| [`demo/`](demo/) | Interactive demo with guided walkthrough |

## Control API Authentication

In a container deployment, the agent can reach KeyFence on the shared network. To prevent the agent from issuing or revoking tokens directly, set `--api-key`:

```bash
keyfence --api-key "$KEYFENCE_API_KEY" --data-dir /data --certs-dir /certs
```

All control API endpoints (except `/health`) require the key as a Bearer token:

```bash
curl -H "Authorization: Bearer $KEYFENCE_API_KEY" \
  -X POST http://localhost:10212/tokens -d '...'
```

The agent does not have this key. Without `--api-key`, KeyFence logs a warning at startup.

## Token API

### Issue a token

```bash
curl -H "Authorization: Bearer $KEYFENCE_API_KEY" \
  -X POST http://localhost:10212/tokens \
  -d '{
    "credential": "sk-ant-real-key",
    "destinations": ["api.anthropic.com"],
    "ttl_seconds": 300,
    "label": "my-agent",
    "policy": "strict"
  }'
```

Response:
```json
{
  "token": "kf_a3f8b2c1e4d5f6...",
  "expires_at": "2026-03-12T10:05:00Z",
  "destinations": ["api.anthropic.com"],
  "label": "my-agent",
  "policy": "strict"
}
```

### List tokens

```bash
curl http://localhost:10212/tokens
```

### Revoke a token

```bash
curl -X DELETE http://localhost:10212/tokens/kf_a3f8b2c1e4d5f6...
```

### List policies

```bash
curl http://localhost:10212/policies
```

## Token Properties

| Property | Description |
|----------|-------------|
| **Short-lived** | Configurable TTL (default 5 minutes). Expired tokens are rejected. |
| **Destination-locked** | Only resolved when the request targets an allowed host and path. A token for `api.anthropic.com/v1/*` cannot be used against other hosts or paths. |
| **Policy-bound** | Optional policy restricts HTTP methods, paths, rate limits, body size, and content types. |
| **Revocable** | Instant invalidation without rotating the underlying credential. |
| **Opaque** | The agent never sees the real credential. Even if the token leaks, it's expired and destination-locked. |

## Policies

Tokens can be issued with a named policy that restricts what the token is allowed to do.

| Policy | Description |
|--------|-------------|
| `open` | No restrictions beyond token validation and destination check. |
| `standard` | Common HTTP methods, 1000 req/hour rate limit. |
| `strict` | GET/POST only, JSON content type, 10 MiB body limit, 1000 req/hour. |
| `readonly` | GET/HEAD only. Blocks all write operations. |

```bash
# Issue a readonly token — agent can list models but not create completions
curl -X POST http://localhost:10212/tokens \
  -d '{"credential":"sk-ant-key","destinations":["api.anthropic.com"],"policy":"readonly"}'
```

## Destination Path Scoping

Destinations can include URL path restrictions, not just hostnames. This lets you lock a token to specific API endpoints.

```bash
# Host only — matches all paths (existing behavior)
"destinations": ["api.anthropic.com"]

# Exact path
"destinations": ["api.anthropic.com/v1/messages"]

# Path glob — matches /v1/messages, /v1/models, etc.
"destinations": ["api.anthropic.com/v1/*"]
```

The first `/` in a destination entry separates the host from the path pattern. Host-only entries match all paths (fully backward compatible). Path patterns support glob matching with `/*` for subtree wildcards.

```bash
# Token that can only call Anthropic's messages endpoint
curl -X POST http://localhost:10212/tokens \
  -d '{"credential":"sk-ant-key","destinations":["api.anthropic.com/v1/messages"]}'
```

SSH bastion (TCP forwarding) destinations are host-only — path scoping applies to HTTPS proxy requests.

## Credential Rotation

Credentials can be rotated without invalidating tokens. All tokens referencing a credential pick up the new value on their next request.

```bash
# Rotate a header credential (the credential_id comes from token issuance)
curl -H "Authorization: Bearer $KEYFENCE_API_KEY" \
  -X PUT http://localhost:10212/credentials/cred_1 \
  -d '{"credential":"sk-ant-new-rotated-key"}'
```

Response:
```json
{"status": "rotated", "credential_id": "cred_1", "affected_tokens": 3}
```

Client certificates and SSH keys can also be rotated:

```bash
# Rotate a client certificate
curl -H "Authorization: Bearer $KEYFENCE_API_KEY" \
  -X PUT http://localhost:10212/credentials/cert_1/cert \
  -d '{"client_cert":"-----BEGIN CERTIFICATE-----\n...", "client_key":"-----BEGIN EC PRIVATE KEY-----\n..."}'

# Rotate an SSH key
curl -H "Authorization: Bearer $KEYFENCE_API_KEY" \
  -X PUT http://localhost:10212/credentials/sshkey_1/sshkey \
  -d '{"ssh_private_key":"...", "ssh_username":"git"}'
```

This works because tokens hold credential references (IDs), not raw values. The credential backend resolves the ID to the current value on each request. Rotation is atomic and takes effect immediately.

## Webhooks and Event Stream

KeyFence can push audit events to webhook URLs and stream them in real-time via Server-Sent Events.

### SSE event stream

Connect to the `/events` endpoint for a real-time stream of all audit events:

```bash
curl -N -H "Authorization: Bearer $KEYFENCE_API_KEY" \
  http://localhost:10212/events
```

Events arrive as `data: {...}\n\n` in standard SSE format. Each event is a JSON audit entry with fields like `event`, `token_id`, `agent_id`, `destination`, etc.

### Webhooks

Register a webhook to receive audit events via HTTP POST:

```bash
curl -H "Authorization: Bearer $KEYFENCE_API_KEY" \
  -X POST http://localhost:10212/webhooks \
  -d '{
    "url": "https://ops.example.com/keyfence-events",
    "secret": "my-signing-key",
    "events": ["deny", "revoke", "response_rule"]
  }'
```

If `secret` is set, each delivery includes an `X-KeyFence-Signature` header (HMAC-SHA256 of the body). The `events` filter is optional — omit it to receive all events. Delivery is async with retry (3 attempts, exponential backoff).

## Response Rules (Lua scripting)

Tokens can carry Lua scripts that are evaluated against each upstream JSON response. This enables automatic token revocation based on API response data — for example, revoking a token when cumulative LLM token usage exceeds a budget.

```bash
# Issue a token with a usage budget
curl -H "Authorization: Bearer $KEYFENCE_API_KEY" \
  -X POST http://localhost:10212/tokens \
  -d '{
    "credential": "sk-ant-key",
    "destinations": ["api.anthropic.com/v1/*"],
    "ttl_seconds": 3600,
    "response_rules": [{
      "script": "state.total = (state.total or 0) + (response.usage and response.usage.output_tokens or 0)\nif state.total > 50000 then return {action=\"revoke\", reason=\"budget exceeded: \" .. state.total} end"
    }]
  }'
```

### How it works

1. The proxy forwards the request to upstream and tees the response — the client receives it immediately with no added latency
2. After the response completes, if `Content-Type` is `application/json`, the buffered copy is parsed and injected into a sandboxed Lua VM as the `response` table
3. Each Lua script runs with access to:
   - `response` — the parsed JSON response body
   - `response_headers` — HTTP response headers
   - `response_status` — HTTP status code
   - `state` — a mutable table persisted across requests for this token
4. Scripts return `nil` (no action) or a table like `{action="revoke", reason="..."}`

### Actions

| Action | Effect |
|--------|--------|
| `revoke` | Immediately revokes the token. The current response is delivered, but the next request will fail. |
| `alert` | Fires an audit event (propagated to webhooks and SSE stream). Token remains valid. |

### SSE streaming support

For LLM streaming responses (`text/event-stream`), KeyFence captures the last SSE `data:` line — which is where Anthropic, OpenAI, and other APIs report usage — and evaluates Lua scripts against it. The stream is forwarded to the client in real-time with zero added latency.

### Sandbox

Lua scripts run in a sandboxed VM with no filesystem, network, or OS access. Dangerous functions (`os`, `io`, `require`, `load`, `debug`) are removed. Scripts are terminated after 500ms or 100,000 instructions to prevent infinite loops. Script errors never affect response delivery.

### Examples

```lua
-- Revoke when cumulative output tokens exceed 50k
state.total = (state.total or 0) + (response.usage and response.usage.output_tokens or 0)
if state.total > 50000 then
  return {action = "revoke", reason = "budget exceeded: " .. state.total}
end
```

```lua
-- Alert on errors from upstream
if response.error then
  return {action = "alert", reason = "upstream error: " .. (response.error.message or "unknown")}
end
```

```lua
-- Revoke if upstream says the key is invalid (don't keep hammering a dead key)
if response.error and response.error.type == "authentication_error" then
  return {action = "revoke", reason = "upstream auth failed"}
end
```

## Client Certificates (mTLS)

KeyFence can present client certificates to upstream services that require mutual TLS. The agent never has the private key — KeyFence holds it and presents it during the upstream TLS handshake.

```bash
# Issue a token with a client certificate
curl -H "Authorization: Bearer $KEYFENCE_API_KEY" \
  -X POST http://localhost:10212/tokens \
  -d '{
    "client_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "client_key": "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----",
    "destinations": ["internal-api.example.com"],
    "ttl_seconds": 300
  }'
```

This works because KeyFence terminates the agent-side TLS and initiates a separate upstream TLS connection. For mTLS upstreams, KeyFence presents the client certificate on that upstream connection. The private key never leaves the KeyFence process.

Optionally, the certificate PEM can also be injected into a request header for services that expect it (e.g., behind a TLS-terminating load balancer):

```bash
curl -X POST http://localhost:10212/tokens \
  -d '{
    "client_cert": "...",
    "client_key": "...",
    "client_cert_header": "X-Client-Cert",
    "destinations": ["internal-api.example.com"]
  }'
```

A token can carry both a header credential and a client certificate, or either one alone.

## SSH Key Injection

KeyFence includes an SSH bastion on `:10211` for git-over-SSH and other SSH-based upstreams. The agent authenticates with a `kf_` token as the SSH password. KeyFence holds the real SSH private key and authenticates upstream on the agent's behalf — the agent never has the key.

```bash
# Issue a token with an SSH key
curl -H "Authorization: Bearer $KEYFENCE_API_KEY" \
  -X POST http://localhost:10212/tokens \
  -d '{
    "ssh_private_key": "'"$(cat ~/.ssh/deploy_key)"'",
    "ssh_username": "git",
    "destinations": ["github.com"],
    "ttl_seconds": 3600
  }'

# Agent git configuration
export GIT_SSH_COMMAND="sshpass -p $KEYFENCE_TOKEN ssh -p 10211 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password \
  keyfence"

git clone git@github.com:owner/repo.git
```

KeyFence resolves the token, fetches the real SSH key, and bridges the session. The private key never enters the agent's address space. Only `exec` requests are supported (no interactive shell or PTY).

## Architecture

KeyFence is a single Go binary with minimal dependencies (`golang.org/x/crypto` for the SSH bastion, OpenTelemetry for optional tracing, `gopher-lua` for response rule scripting).

| Component | Description |
|-----------|-------------|
| **MITM Proxy** (`:10210`) | TLS-intercepting forward proxy. Handles CONNECT tunneling, token resolution, credential injection, upstream mTLS presentation, policy evaluation. |
| **SSH Bastion** (`:10211`) | SSH server that authenticates agents with `kf_` tokens. Holds real SSH private keys and bridges sessions to upstream hosts (git, etc.). |
| **Control API** (`:10212`) | Token issuance, listing, revocation, health checks. Orchestrator-facing. Protected by `--api-key` to prevent agent access (see below). |
| **Credential Backend** | Tokens hold references, not raw secrets. The backend fetches the real credential on each request. Stores API keys, client certs, and SSH keys. Supports credential rotation without token invalidation. |
| **Local CA** | ECDSA P-256 CA generated at startup. Issues per-hostname certificates on the fly for TLS interception. |
| **Policy Engine** | Per-request evaluation of method, path, rate limits, request budgets, body size, content type. |
| **Lua Rule Engine** | Sandboxed Lua VM evaluates response rules against upstream JSON. Supports stateful accumulation (e.g., token usage budgets) and automatic revocation. |
| **Webhooks / SSE** | Real-time audit event delivery via Server-Sent Events (`GET /events`) and registered webhook URLs. |
| **Telemetry** | Optional OpenTelemetry distributed tracing. Configured via standard `OTEL_*` env vars. Silently disabled when no collector is reachable. |

## Telemetry (OpenTelemetry)

KeyFence emits distributed traces via OpenTelemetry. Every proxy request and SSH session gets a trace span with token ID, agent ID, task ID, destination, and outcome.

Configuration uses standard OTel environment variables:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318   # OTLP/HTTP endpoint
OTEL_SERVICE_NAME=keyfence                           # default
OTEL_TRACES_EXPORTER=none                            # set to disable tracing
```

If no OTLP endpoint is reachable, tracing is silently disabled. KeyFence continues to operate normally.

Trace spans include:
- `proxy.connect` / `proxy.request` — HTTPS proxy operations
- `ssh.forward` / `ssh.session` — SSH bastion operations
- Attributes: `keyfence.token_id`, `keyfence.agent_id`, `keyfence.task_id`, `keyfence.policy`, `http.method`, `http.url`, `net.peer.name`, `http.status_code`

## What KeyFence Does Not Defend Against

- Side-channel exfiltration (timing, DNS tunneling, URL path encoding)
- Compromise of the KeyFence process itself
- Credentials consumed locally for cryptographic operations (AWS SigV4 signing, JWT minting) — these require Tier 2/3 features not yet implemented
- Tools that pin certificates and reject the MITM CA (these fail closed, which is correct)

## Development

```bash
make build       # build ./bin/keyfence
make test        # run integration tests
make clean       # remove build artifacts
```

Requires Go 1.22+.

## Author

Anthony Green (<green@redhat.com>)

## License

MIT — see [LICENSE](LICENSE).
