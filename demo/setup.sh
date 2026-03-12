#!/usr/bin/env bash
#
# setup.sh -- Start KeyFence, issue a token, drop into the agent shell.
#
# Prerequisites:
#   export GITHUB_TOKEN=ghp_your_real_pat
#
# What this does:
#   1. Generates a random API key for the control plane
#   2. Starts KeyFence and the agent container
#   3. Issues a kf_ token locked to github.com + api.github.com (1 hour TTL)
#   4. Drops you into a bash shell inside the isolated agent container
#
# Once inside the agent, run:
#   /demo.sh            # guided walkthrough
#   gh api /user        # try it yourself
#
set -euo pipefail
cd "$(dirname "$0")"

# ── 1. Check GITHUB_TOKEN ──────────────────────────────────────────────
if [ -z "${GITHUB_TOKEN:-}" ]; then
    echo "Error: GITHUB_TOKEN is not set."
    echo ""
    echo "  export GITHUB_TOKEN=ghp_your_real_pat"
    echo "  ./setup.sh"
    exit 1
fi
echo "==> Real GITHUB_TOKEN detected (${GITHUB_TOKEN:0:8}...)"

# ── 2. Generate control API key ────────────────────────────────────────
export KEYFENCE_API_KEY="${KEYFENCE_API_KEY:-$(openssl rand -hex 16)}"
echo "==> Control API key: ${KEYFENCE_API_KEY:0:8}..."

# ── 3. Start everything ───────────────────────────────────────────────
# Use a placeholder token for the initial start — we'll inject the real
# one after keyfence is up and we've issued it.
export KEYFENCE_TOKEN="kf_placeholder"
echo "==> Starting KeyFence and agent..."
podman-compose up -d

echo "==> Waiting for KeyFence health check..."
RETRIES=0
until curl -sf http://localhost:10212/health >/dev/null 2>&1; do
    RETRIES=$((RETRIES + 1))
    if [ "$RETRIES" -ge 30 ]; then
        echo "Error: KeyFence did not become healthy."
        echo "Check logs: podman-compose logs keyfence"
        exit 1
    fi
    sleep 1
done
echo "==> KeyFence is healthy."

# ── 4. Issue a token ───────────────────────────────────────────────────
echo "==> Issuing token locked to github.com + api.github.com (1 hour TTL)..."
TOKEN_RESPONSE=$(curl -sf -X POST http://localhost:10212/tokens \
    -H "Authorization: Bearer ${KEYFENCE_API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "credential": "'"${GITHUB_TOKEN}"'",
        "destinations": ["github.com", "api.github.com"],
        "ttl_seconds": 3600,
        "label": "demo-agent",
        "policy": "standard"
    }')

KEYFENCE_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

if [ -z "$KEYFENCE_TOKEN" ]; then
    echo "Error: failed to issue token."
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi

echo "==> Token issued: ${KEYFENCE_TOKEN:0:20}..."
echo "    Destinations: github.com, api.github.com"
echo "    Policy: standard"
echo "    TTL: 1 hour"
echo ""
echo "==> Dropping you into the agent container."
echo "    Run /demo.sh for a guided walkthrough."
echo ""

# ── 5. Shell into the agent ────────────────────────────────────────────
# Use exec to attach to the already-running agent container, injecting
# the real token. This avoids recreating keyfence via depends_on.
podman-compose exec -e "GITHUB_TOKEN=${KEYFENCE_TOKEN}" agent /bin/bash
