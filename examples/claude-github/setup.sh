#!/usr/bin/env bash
#
# setup.sh — Automated setup for Claude Code + GitHub via KeyFence
#
# This script:
#   1. Reads your real GITHUB_TOKEN from the environment
#   2. Starts KeyFence
#   3. Waits for it to become healthy
#   4. Issues a kf_ token locked to github.com + api.github.com
#   5. Runs the Claude container with the proxied token
#
# Usage:
#   export GITHUB_TOKEN=ghp_your_real_pat_here
#   ./setup.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# 1. Check that GITHUB_TOKEN is set (the real PAT)
# ---------------------------------------------------------------------------
if [ -z "${GITHUB_TOKEN:-}" ]; then
  echo "Error: GITHUB_TOKEN is not set."
  echo ""
  echo "Export your GitHub Personal Access Token before running this script:"
  echo "  export GITHUB_TOKEN=ghp_your_real_pat_here"
  echo "  ./setup.sh"
  exit 1
fi

echo "==> Real GITHUB_TOKEN detected (${GITHUB_TOKEN:0:8}...)"
echo ""

# ---------------------------------------------------------------------------
# 2. Start KeyFence
# ---------------------------------------------------------------------------
echo "==> Starting KeyFence..."
docker compose up -d keyfence

# ---------------------------------------------------------------------------
# 3. Wait for KeyFence to become healthy
# ---------------------------------------------------------------------------
echo "==> Waiting for KeyFence health check..."
RETRIES=0
MAX_RETRIES=30
until curl -sf http://localhost:10212/health >/dev/null 2>&1; do
  RETRIES=$((RETRIES + 1))
  if [ "$RETRIES" -ge "$MAX_RETRIES" ]; then
    echo "Error: KeyFence did not become healthy after ${MAX_RETRIES} attempts."
    echo "Check logs with: docker compose logs keyfence"
    exit 1
  fi
  sleep 1
done
echo "==> KeyFence is healthy."
echo ""

# ---------------------------------------------------------------------------
# 4. Issue a token locked to github.com + api.github.com
# ---------------------------------------------------------------------------
echo "==> Issuing KeyFence token locked to github.com and api.github.com..."

TOKEN_RESPONSE=$(curl -sf -X POST http://localhost:10212/tokens \
  -H 'Content-Type: application/json' \
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
echo "    TTL: 3600 seconds (1 hour)"
echo ""

# ---------------------------------------------------------------------------
# 5. Run the Claude container with the proxied token
# ---------------------------------------------------------------------------
echo "==> Launching Claude container..."
echo "    The real GitHub PAT stays inside KeyFence."
echo "    Claude only sees the kf_ token."
echo ""

KEYFENCE_TOKEN="$KEYFENCE_TOKEN" docker compose run --rm claude
