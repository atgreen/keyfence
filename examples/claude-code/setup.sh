#!/usr/bin/env bash
#
# setup.sh — Start KeyFence + Claude Code in a podman pod, issue a token,
#             launch Claude Code.
#
# Prerequisites:
#   export ANTHROPIC_API_KEY=sk-ant-...
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

POD_NAME="keyfence-claude"
KEYFENCE_IMAGE="keyfence"
CLAUDE_IMAGE="keyfence-claude-code"

# ── 1. Check ANTHROPIC_API_KEY ───────────────────────────────────────
if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo "Error: ANTHROPIC_API_KEY is not set."
    echo ""
    echo "  export ANTHROPIC_API_KEY=sk-ant-..."
    echo "  ./setup.sh"
    exit 1
fi
echo "==> Real ANTHROPIC_API_KEY detected (${ANTHROPIC_API_KEY:0:10}...)"

# ── 2. Generate control API key ──────────────────────────────────────
KEYFENCE_API_KEY="${KEYFENCE_API_KEY:-$(openssl rand -hex 16)}"
echo "==> Control API key: ${KEYFENCE_API_KEY:0:8}..."

# ── 3. Build images ──────────────────────────────────────────────────
echo "==> Building KeyFence image..."
podman build -t "$KEYFENCE_IMAGE" -f ../../Containerfile ../..

echo "==> Building Claude Code image..."
podman build -t "$CLAUDE_IMAGE" -f Containerfile.claude .

# ── 4. Create pod ────────────────────────────────────────────────────
podman pod rm -f "$POD_NAME" 2>/dev/null || true

echo "==> Creating pod $POD_NAME..."
podman pod create --name "$POD_NAME" -p 10212:10212

# Shared volume for CA cert (public cert only)
podman volume rm "${POD_NAME}-certs" 2>/dev/null || true
podman volume create "${POD_NAME}-certs"

# ── 5. Start KeyFence ────────────────────────────────────────────────
echo "==> Starting KeyFence..."
podman run -d --pod "$POD_NAME" --name "${POD_NAME}-keyfence" \
    -v "${POD_NAME}-certs:/certs" \
    "$KEYFENCE_IMAGE" \
    --certs-dir /certs \
    --api-key "$KEYFENCE_API_KEY"

echo "==> Waiting for KeyFence health check..."
RETRIES=0
MAX_RETRIES=30
until curl -sf http://localhost:10212/health >/dev/null 2>&1; do
    RETRIES=$((RETRIES + 1))
    if [ "$RETRIES" -ge "$MAX_RETRIES" ]; then
        echo "Error: KeyFence did not become healthy after ${MAX_RETRIES} attempts."
        echo "Check logs: podman logs ${POD_NAME}-keyfence"
        exit 1
    fi
    sleep 1
done
echo "==> KeyFence is healthy."

# ── 6. Issue a token ─────────────────────────────────────────────────
echo "==> Issuing token locked to api.anthropic.com (1 hour TTL)..."
TOKEN_RESPONSE=$(curl -sf -X POST http://localhost:10212/tokens \
    -H "Authorization: Bearer ${KEYFENCE_API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "credential": "'"${ANTHROPIC_API_KEY}"'",
        "destinations": ["api.anthropic.com"],
        "ttl_seconds": 3600,
        "label": "claude-code-agent"
    }')

KEYFENCE_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

if [ -z "$KEYFENCE_TOKEN" ]; then
    echo "Error: failed to issue token."
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi

echo "==> Token issued: ${KEYFENCE_TOKEN:0:20}..."
echo "    Destination: api.anthropic.com"
echo "    TTL: 1 hour"
echo ""

# ── 7. Launch Claude Code ────────────────────────────────────────────
echo "==> Launching Claude Code..."
echo "    The real Anthropic API key stays inside KeyFence."
echo "    Claude Code only sees the kf_ token."
echo ""

podman run -it --rm --pod "$POD_NAME" --name "${POD_NAME}-claude" \
    -e "HTTPS_PROXY=http://127.0.0.1:10210" \
    -e "HTTP_PROXY=http://127.0.0.1:10210" \
    -e "SSL_CERT_FILE=/certs/ca.pem" \
    -e "NODE_EXTRA_CA_CERTS=/certs/ca.pem" \
    -e "ANTHROPIC_API_KEY=${KEYFENCE_TOKEN}" \
    -v "${POD_NAME}-certs:/certs:ro" \
    "$CLAUDE_IMAGE" \
    claude --dangerously-skip-permissions
