# KeyFence

**Credential containment for AI agents.**

## The Problem

AI agents need API keys, bot tokens, and signing credentials to do useful work. As agents gain autonomy — spawning subprocesses, running arbitrary tools, executing code from untrusted inputs — every credential in their environment becomes an exfiltration target.

The attack surface is broad:

- **Prompt injection** tricks the agent into including credentials in outbound messages, tool calls, or generated code
- **Tool-mediated leakage** — the agent runs a tool that reads environment variables, config files, or process memory and sends them to an attacker-controlled endpoint
- **Subprocess escape** — the agent spawns a shell, a Python script, or a compiled binary that has full access to every secret in the environment
- **Accidental exposure** — the agent logs, caches, or returns credentials in its responses

Traditional secret management (Vault, 1Password, environment variables) solves the *storage* problem but not the *runtime* problem. Once a secret is loaded into the agent's process, it can be read and exfiltrated by anything the agent executes.

**If the agent can read a secret value at all, you have already lost the exfiltration property.**

## How KeyFence Works

KeyFence is an egress-controlled credential broker. It sits between the agent and the internet. The agent never possesses real credentials — only short-lived, destination-locked opaque tokens (`kf_...`) that are worthless outside the proxy.

```
┌──────────────────────────────────────┐
│  Agent Container                     │
│                                      │
│  ANTHROPIC_API_KEY=kf_a3f8b2c1...    │
│  HTTPS_PROXY=http://keyfence:10210   │
│                                      │
│  (no internet access)                │
└──────────────┬───────────────────────┘
               │ only allowed connection
               ▼
┌──────────────────────────────────────┐
│  KeyFence                            │
│                                      │
│  1. Intercept TLS (MITM with CA)     │
│  2. Find kf_ token in headers        │
│  3. Validate: TTL, destination,      │
│     method, path, rate limit, DLP    │
│  4. Fetch real credential from       │
│     backend                          │
│  5. Swap token → real credential     │
│  6. Forward to upstream              │
└──────────────┬───────────────────────┘
               │
               ▼
          api.anthropic.com
```

The agent container runs on an isolated network with no default gateway. It can only reach KeyFence. All outbound HTTPS transits the proxy. Non-HTTP traffic is dropped at the network level.

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

### Containerized (with egress enforcement)

This is the recommended deployment. The agent container has no internet access — it can only reach KeyFence.

```bash
# Start KeyFence
podman-compose up -d keyfence

# Issue a token
TOKEN=$(curl -sf -X POST http://localhost:10212/tokens \
  -d '{"credential":"sk-ant-your-real-key","destinations":["api.anthropic.com"],"ttl_seconds":300}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Run the agent (isolated network, no direct internet)
KEYFENCE_TOKEN=$TOKEN podman-compose run --rm agent
```

The `docker-compose.yaml` puts the agent on an `internal: true` network with no default gateway. Replace the example agent service with your actual agent image.

## Token API

### Issue a token

```bash
curl -X POST http://localhost:10212/tokens \
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
| **Destination-locked** | Only resolved when the request targets an allowed host. A token for `api.anthropic.com` cannot be used against `api.openai.com`. |
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

## DLP (Data Loss Prevention)

KeyFence scans outbound request bodies for credential patterns before forwarding. If an agent tries to exfiltrate a real API key in a message body, the request is blocked.

Detected patterns:
- Anthropic API keys (`sk-ant-...`)
- OpenAI API keys (`sk-proj-...`)
- Slack bot tokens (`xoxb-...`)
- GitHub PATs (`ghp_...`)

DLP is defense-in-depth. The primary defense is that the agent never possesses real credentials in the first place.

## Architecture

KeyFence is a single Go binary with no external dependencies.

| Component | Description |
|-----------|-------------|
| **MITM Proxy** (`:10210`) | TLS-intercepting forward proxy. Handles CONNECT tunneling, token resolution, credential injection, policy evaluation, DLP scanning. |
| **Control API** (`:10212`) | Token issuance, listing, revocation, health checks. Orchestrator-facing — not exposed to the agent. |
| **Credential Backend** | Tokens hold references, not raw secrets. The backend fetches the real credential on each request. |
| **Local CA** | ECDSA P-256 CA generated at startup. Issues per-hostname certificates on the fly for TLS interception. |
| **Policy Engine** | Per-request evaluation of method, path, rate limits, request budgets, body size, content type. |

## Egress Enforcement

Without egress enforcement, KeyFence is convenience, not containment. The agent could bypass the proxy and send credentials anywhere.

The containerized deployment enforces egress at the network level:

```yaml
networks:
  agent-isolated:
    internal: true   # no default gateway — no internet access
```

The agent container can only reach KeyFence. All other outbound traffic — HTTP, DNS, raw TCP, UDP — is dropped. This is enforced by the container runtime, not by KeyFence, making it harder to bypass.

For Kubernetes, use a NetworkPolicy:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-egress
spec:
  podSelector:
    matchLabels:
      role: agent
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: keyfence
      ports:
        - port: 10210
```

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

## License

MIT — see [LICENSE](LICENSE).
