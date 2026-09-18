#!/usr/bin/env bash
#
# setup.sh — Start KeyFence + agent in a podman pod, issue a token,
#             run the GitHub demo.
#
# Prerequisites:
#   export GITHUB_TOKEN=ghp_your_real_pat_here
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

POD_NAME="keyfence-github"
KEYFENCE_IMAGE="keyfence"
AGENT_IMAGE="keyfence-github-agent"

# ── 1. Check GITHUB_TOKEN ───────────────────────────────────────────
if [ -z "${GITHUB_TOKEN:-}" ]; then
    echo "Error: GITHUB_TOKEN is not set."
    echo ""
    echo "Export your GitHub Personal Access Token before running this script:"
    echo "  export GITHUB_TOKEN=ghp_your_real_pat_here"
    echo "  ./setup.sh"
    exit 1
fi
echo "==> Real GITHUB_TOKEN detected (${GITHUB_TOKEN:0:8}...)"

# ── 2. Generate control API key ──────────────────────────────────────
KEYFENCE_API_KEY="${KEYFENCE_API_KEY:-$(openssl rand -hex 16)}"
echo "==> Control API key: ${KEYFENCE_API_KEY:0:8}..."

# ── 3. Build images ──────────────────────────────────────────────────
echo "==> Building KeyFence image..."
podman build -t "$KEYFENCE_IMAGE" -f ../../Containerfile ../..

echo "==> Building agent image..."
podman build -t "$AGENT_IMAGE" -f Containerfile.agent .

# ── 4. Create pod ────────────────────────────────────────────────────
podman pod rm -f "$POD_NAME" 2>/dev/null || true

echo "==> Creating pod $POD_NAME..."
podman pod create --name "$POD_NAME" -p 10212:10212

podman volume rm "${POD_NAME}-certs" 2>/dev/null || true
podman volume create "${POD_NAME}-certs"

# ── 5. Start KeyFence ────────────────────────────────────────────────
echo "==> Starting KeyFence..."
# The key goes in as a podman secret rather than on the command line, where
# every process of this user could read it out of /proc.
podman secret rm "${POD_NAME}-api-key" 2>/dev/null || true
printf '%s' "$KEYFENCE_API_KEY" | podman secret create "${POD_NAME}-api-key" -

podman run -d --pod "$POD_NAME" --name "${POD_NAME}-keyfence" \
    -v "${POD_NAME}-certs:/certs" \
    --secret "${POD_NAME}-api-key,target=/run/secrets/api-key" \
    "$KEYFENCE_IMAGE" \
    --certs-dir /certs \
    --api-key-file /run/secrets/api-key

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
echo "==> Issuing token locked to github.com + api.github.com (1 hour TTL)..."
TOKEN_RESPONSE=$(curl -sf -X POST http://localhost:10212/tokens \
    -H "Authorization: Bearer ${KEYFENCE_API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{
        "credential": "'"${GITHUB_TOKEN}"'",
        "destinations": ["github.com", "api.github.com"],
        "ttl_seconds": 3600
    }')

KEYFENCE_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

if [ -z "$KEYFENCE_TOKEN" ]; then
    echo "Error: failed to issue token."
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi

echo "==> Token issued: ${KEYFENCE_TOKEN:0:20}..."
echo "    Locked to: github.com, api.github.com"
echo "    TTL: 1 hour"
echo ""

# ── 7. Run the agent ─────────────────────────────────────────────────
echo "==> Launching agent container..."
echo "    The real GitHub PAT stays inside KeyFence."
echo "    The agent only sees the kf_ token."
echo ""

podman run -it --rm --pod "$POD_NAME" --name "${POD_NAME}-agent" \
    -e "HTTPS_PROXY=http://127.0.0.1:10210" \
    -e "SSL_CERT_FILE=/certs/ca.pem" \
    -e "GIT_SSL_CAINFO=/certs/ca.pem" \
    -e "GITHUB_TOKEN=${KEYFENCE_TOKEN}" \
    -e "GH_HOST=github.com" \
    -v "${POD_NAME}-certs:/certs:ro" \
    "$AGENT_IMAGE"
