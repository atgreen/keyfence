# Example: Claude Code with GitHub Token

This example shows how to give Claude Code access to a GitHub repository
without ever putting the real GitHub PAT in Claude's environment.

## The problem

You want Claude Code to `git push`, `gh pr create`, and interact with your
GitHub repos. But handing your PAT directly to an AI agent means:

- The token could leak through logs, tool output, or prompt injection.
- There is no way to limit which hosts the token can reach.
- If the token escapes the container, it works everywhere, forever.

## The solution

KeyFence sits between Claude and the internet as an HTTPS proxy. You give
KeyFence your real GitHub PAT, and it gives you back a `kf_` token that:

1. Only works through the KeyFence proxy.
2. Only reaches the destinations you specify (github.com, api.github.com).
3. Expires after a short TTL.

Claude never sees the real PAT. If the `kf_` token leaks, it is useless
outside the proxy and expires quickly.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  agent-isolated network (internal, no internet)     │
│                                                     │
│  ┌───────────────┐         ┌──────────────────┐    │
│  │ Claude Code   │──HTTPS──▶   KeyFence        │    │
│  │               │  proxy  │   (proxy + swap)  │    │
│  │ GITHUB_TOKEN  │         │                   │    │
│  │  = kf_abc...  │         │  kf_abc → ghp_... │    │
│  └───────────────┘         └────────┬─────────┘    │
│                                     │               │
└─────────────────────────────────────┼───────────────┘
                                      │ default network
                                      ▼
                               github.com
                               api.github.com
```

- Claude is on the `agent-isolated` network only (no default gateway).
- KeyFence is on both networks: it can reach GitHub, and Claude can reach it.
- The `kf_` token is swapped for the real PAT inside KeyFence at proxy time.

## Step-by-step walkthrough

### 1. Start KeyFence

```bash
docker compose up -d keyfence
```

Wait for the health check to pass:

```bash
docker compose exec keyfence wget -q --spider http://localhost:10212/health
```

### 2. Issue a token locked to GitHub

```bash
KEYFENCE_TOKEN=$(curl -sf -X POST http://localhost:10212/tokens \
  -H 'Content-Type: application/json' \
  -d '{
    "credential": "'"$GITHUB_TOKEN"'",
    "destinations": ["github.com", "api.github.com"],
    "ttl_seconds": 3600
  }' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "$KEYFENCE_TOKEN"
# kf_abc123...
```

The real `$GITHUB_TOKEN` (your PAT) is stored inside KeyFence's encrypted
data volume. The returned `kf_` token is a reference that only works
through the proxy.

### 3. Launch the Claude container

```bash
KEYFENCE_TOKEN=$KEYFENCE_TOKEN docker compose run --rm claude
```

Inside the container:

- `GITHUB_TOKEN` is set to the `kf_` token.
- `HTTPS_PROXY` points to KeyFence.
- `SSL_CERT_FILE` points to the KeyFence CA cert (for MITM TLS).
- The container has **no direct internet access**.

### 4. Claude uses GitHub normally

Inside the container, standard tools work transparently:

```bash
gh auth status          # authenticated via kf_ token
gh pr create            # works — proxied through KeyFence
git push origin main    # works — proxied through KeyFence
```

KeyFence intercepts each HTTPS request, swaps `kf_abc...` for `ghp_real...`,
and forwards it to GitHub.

## What happens if the token leaks?

If an attacker extracts the `kf_` token from Claude's environment:

- **Outside the proxy**: The token is meaningless. GitHub does not recognize
  `kf_` tokens. There is no way to use it without going through KeyFence.
- **After TTL expiry**: Even through the proxy, the token is rejected.
  Default TTL in this example is 1 hour.
- **Wrong destination**: If someone tries to use the token to reach
  `evil.com` through the proxy, KeyFence blocks it because the token is
  locked to `github.com` and `api.github.com`.

## What happens if Claude tries to reach a non-GitHub host?

The request is blocked at two levels:

1. **Network level**: The `agent-isolated` network has no default gateway.
   Claude cannot reach anything except KeyFence.
2. **Token policy level**: Even through the proxy, KeyFence checks the
   destination against the token's allowed list. A request to
   `api.openai.com` would be rejected with a 403.

## Quick start

The easiest way to run this example:

```bash
export GITHUB_TOKEN=ghp_your_real_pat_here
./setup.sh
```

Or manually with docker compose:

```bash
export GITHUB_TOKEN=ghp_your_real_pat_here
docker compose up -d keyfence
# ... issue token as shown above ...
KEYFENCE_TOKEN=$KEYFENCE_TOKEN docker compose run --rm claude
```

## Files

| File                  | Purpose                                        |
|-----------------------|------------------------------------------------|
| `docker-compose.yaml` | Service definitions for KeyFence and Claude    |
| `setup.sh`            | Automated setup: start, issue token, run Claude |
| `README.md`           | This file                                      |
