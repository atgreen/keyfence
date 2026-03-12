# Example: Claude Code with KeyFence Sidecar

Run Claude Code in a podman pod where it can call the Anthropic API, but
never possesses the real API key. KeyFence sits as an HTTPS proxy sidecar,
swapping the opaque `kf_` token for the real `sk-ant-` key on each request.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  podman pod (shared network namespace)              │
│                                                     │
│  ┌───────────────┐         ┌──────────────────┐    │
│  │ Claude Code   │─127.0.0.1──▶  KeyFence     │    │
│  │               │  :10210 │   (proxy + swap)  │    │
│  │ ANTHROPIC_    │         │                   │    │
│  │ API_KEY       │         │ kf_abc → sk-ant-… │    │
│  │ = kf_abc...   │         │                   │    │
│  └───────────────┘         └────────┬─────────┘    │
│                                     │               │
└─────────────────────────────────────┼───────────────┘
                                      │
                                      ▼
                               api.anthropic.com
```

- Both containers share **localhost** via the pod's network namespace.
- Claude Code reaches the proxy at `127.0.0.1:10210`.
- The `kf_` token is swapped for the real API key inside KeyFence at proxy time.

## Quick start

```bash
export ANTHROPIC_API_KEY=sk-ant-...
./setup.sh
```

This will:

1. Build the KeyFence and Claude Code container images.
2. Create a podman pod with KeyFence as a sidecar.
3. Issue a `kf_` token locked to `api.anthropic.com` (1-hour TTL).
4. Launch Claude Code with the proxied token.

## Manual setup

```bash
# 1. Build images
podman build -t keyfence -f ../../Containerfile ../..
podman build -t keyfence-claude-code -f Containerfile.claude .

# 2. Create pod and start KeyFence
KEYFENCE_API_KEY=$(openssl rand -hex 16)
podman pod create --name kf -p 10212:10212
podman volume create kf-certs
podman run -d --pod kf --name kf-keyfence \
    -v kf-certs:/certs \
    keyfence --certs-dir /certs --api-key "$KEYFENCE_API_KEY"

# 3. Issue a token
KEYFENCE_TOKEN=$(curl -sf -X POST http://localhost:10212/tokens \
  -H "Authorization: Bearer $KEYFENCE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "credential": "'"$ANTHROPIC_API_KEY"'",
    "destinations": ["api.anthropic.com"],
    "ttl_seconds": 3600
  }' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# 4. Launch Claude Code
podman run -it --rm --pod kf \
    -e "HTTPS_PROXY=http://127.0.0.1:10210" \
    -e "SSL_CERT_FILE=/certs/ca.pem" \
    -e "NODE_EXTRA_CA_CERTS=/certs/ca.pem" \
    -e "ANTHROPIC_API_KEY=$KEYFENCE_TOKEN" \
    -v kf-certs:/certs:ro \
    keyfence-claude-code \
    claude --dangerously-skip-permissions
```

## Non-interactive mode

Pass a prompt directly instead of starting an interactive session:

```bash
podman run -it --rm --pod kf \
    -e "HTTPS_PROXY=http://127.0.0.1:10210" \
    -e "SSL_CERT_FILE=/certs/ca.pem" \
    -e "NODE_EXTRA_CA_CERTS=/certs/ca.pem" \
    -e "ANTHROPIC_API_KEY=$KEYFENCE_TOKEN" \
    -v kf-certs:/certs:ro \
    keyfence-claude-code \
    claude -p "explain the architecture of this project"
```

## What the agent sees

Inside the container:

| Variable            | Value                           |
|---------------------|---------------------------------|
| `ANTHROPIC_API_KEY` | `kf_abc123...` (opaque)         |
| `HTTPS_PROXY`       | `http://127.0.0.1:10210`       |
| `SSL_CERT_FILE`     | `/certs/ca.pem` (KeyFence CA)  |

Claude Code uses `ANTHROPIC_API_KEY` normally. It has no idea the key is
a proxy token — the Anthropic SDK sends it as a Bearer token, KeyFence
intercepts and swaps it, and api.anthropic.com sees the real key.

## Security properties

- **No raw secret in agent environment**: The container never has `sk-ant-`.
- **Destination locking**: Even through the proxy, the token only works for
  `api.anthropic.com`. Requests to any other host return 403.
- **TTL expiry**: The token expires after 1 hour. A leaked token is useless
  after that.
- **CA key isolation**: The agent volume mounts only `ca.pem` (the public
  cert), not the CA private key.

## Cleanup

```bash
podman pod rm -f keyfence-claude
podman volume rm keyfence-claude-certs
```

## Files

| File                  | Purpose                                          |
|-----------------------|--------------------------------------------------|
| `Containerfile.claude` | Claude Code agent image (node:20-slim)           |
| `setup.sh`            | Automated setup: build, pod, token, run Claude   |
| `README.md`           | This file                                        |
