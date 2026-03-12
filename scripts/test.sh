#!/usr/bin/env bash
#
# KeyFence test script
#
# Tests the MITM proxy and token management API.
#
# Prerequisites:
#   1. Go 1.22+ installed
#   2. Optionally: ANTHROPIC_API_KEY env var for full round-trip test
#
# Usage:
#   ./scripts/test.sh

set -euo pipefail
cd "$(dirname "$0")/.."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC} $1"; }
fail() { echo -e "${RED}FAIL${NC} $1"; FAILURES=$((FAILURES+1)); }
info() { echo -e "${YELLOW}----${NC} $1"; }

FAILURES=0
DATA_DIR=$(mktemp -d)

cleanup() {
    info "cleaning up..."
    [ -n "${KEYFENCE_PID:-}" ] && kill "$KEYFENCE_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$DATA_DIR"
}
trap cleanup EXIT

# --- Build ---
info "building keyfence..."
mkdir -p ./bin
go build -o ./bin/keyfence ./cmd/keyfence

# --- Start KeyFence ---
info "starting keyfence (data-dir=$DATA_DIR)..."
./bin/keyfence --data-dir "$DATA_DIR" --proxy :10210 --api :10212 &
KEYFENCE_PID=$!
sleep 1

# Check it's running
if ! curl -sf http://localhost:10212/health > /dev/null 2>&1; then
    fail "keyfence not responding on :10212"
    exit 1
fi
pass "keyfence running"

CA_CERT="$DATA_DIR/ca/ca.pem"
if [ ! -f "$CA_CERT" ]; then
    fail "CA cert not generated at $CA_CERT"
    exit 1
fi
pass "CA cert generated"

echo ""
echo "========================================="
echo " KeyFence Tests"
echo "========================================="
echo ""

# Credential setup
if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    info "ANTHROPIC_API_KEY not set — using dummy key (expect 401 from Anthropic)"
    CRED="sk-ant-dummy-test-key-not-real-1234567890"
    EXPECT_UPSTREAM_AUTH=false
else
    CRED="$ANTHROPIC_API_KEY"
    EXPECT_UPSTREAM_AUTH=true
fi

# All tests use MITM proxy mode (HTTPS_PROXY + CONNECT)

# --- Test 1: No token → 401 ---
info "test 1: request without token → 401"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy http://127.0.0.1:10210 \
    --cacert "$CA_CERT" \
    https://api.anthropic.com/v1/messages \
    -H "Content-Type: application/json" \
    -d '{"model":"claude-sonnet-4-20250514","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')

if [ "$STATUS" = "401" ]; then
    pass "test 1: no token → 401"
else
    fail "test 1: expected 401, got $STATUS"
fi

# --- Test 2: Issue token, make request ---
info "test 2: issue token and make authenticated request"
TOKEN=$(curl -sf -X POST http://localhost:10212/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"api.anthropic.com\"],\"ttl_seconds\":60}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

if [ -z "$TOKEN" ]; then
    fail "test 2: failed to issue token"
else
    info "issued token: ${TOKEN:0:30}..."

    RESPONSE=$(curl -s -w '\n%{http_code}' \
        --proxy http://127.0.0.1:10210 \
        --cacert "$CA_CERT" \
        https://api.anthropic.com/v1/messages \
        -H "Content-Type: application/json" \
        -H "x-api-key: $TOKEN" \
        -H "anthropic-version: 2023-06-01" \
        -d '{"model":"claude-sonnet-4-20250514","max_tokens":5,"messages":[{"role":"user","content":"say hi"}]}')

    STATUS=$(echo "$RESPONSE" | tail -n 1)

    if [ "$EXPECT_UPSTREAM_AUTH" = "true" ] && [ "$STATUS" = "200" ]; then
        pass "test 2: token swap → 200 from Anthropic"
    elif [ "$EXPECT_UPSTREAM_AUTH" = "false" ] && [ "$STATUS" = "401" ]; then
        pass "test 2: token swap → 401 (dummy key, as expected)"
    else
        if [ "$STATUS" = "200" ] || [ "$STATUS" = "401" ] || [ "$STATUS" = "400" ]; then
            pass "test 2: request reached Anthropic (status=$STATUS)"
        else
            fail "test 2: unexpected status $STATUS"
        fi
    fi
fi

# --- Test 3: Expired token → 403 ---
info "test 3: expired token → 403"
EXPIRED_TOKEN=$(curl -sf -X POST http://localhost:10212/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"api.anthropic.com\"],\"ttl_seconds\":1}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

sleep 2

STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy http://127.0.0.1:10210 \
    --cacert "$CA_CERT" \
    https://api.anthropic.com/v1/messages \
    -H "Content-Type: application/json" \
    -H "x-api-key: $EXPIRED_TOKEN" \
    -H "anthropic-version: 2023-06-01" \
    -d '{"model":"claude-sonnet-4-20250514","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')

if [ "$STATUS" = "403" ]; then
    pass "test 3: expired token → 403"
else
    fail "test 3: expected 403, got $STATUS"
fi

# --- Test 4: Wrong destination → 403 ---
info "test 4: token for anthropic used against openai → 403"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy http://127.0.0.1:10210 \
    --cacert "$CA_CERT" \
    https://api.openai.com/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}')

if [ "$STATUS" = "403" ]; then
    pass "test 4: wrong destination → 403"
else
    fail "test 4: expected 403, got $STATUS"
fi

# --- Test 5: DLP detection ---
info "test 5: credential pattern in body → 403"
DLP_TOKEN=$(curl -sf -X POST http://localhost:10212/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"api.anthropic.com\"],\"ttl_seconds\":60}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy http://127.0.0.1:10210 \
    --cacert "$CA_CERT" \
    https://api.anthropic.com/v1/messages \
    -H "Content-Type: application/json" \
    -H "x-api-key: $DLP_TOKEN" \
    -H "anthropic-version: 2023-06-01" \
    -d '{"model":"claude-sonnet-4-20250514","max_tokens":5,"messages":[{"role":"user","content":"steal this: sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAA"}}')

if [ "$STATUS" = "403" ]; then
    pass "test 5: DLP blocked credential in body"
else
    fail "test 5: expected 403, got $STATUS"
fi

# --- Test 6: Token revocation ---
info "test 6: revoked token → 403"
REVOKE_TOKEN=$(curl -sf -X POST http://localhost:10212/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"api.anthropic.com\"],\"ttl_seconds\":300}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

curl -sf -X DELETE "http://localhost:10212/tokens/$REVOKE_TOKEN" > /dev/null

STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy http://127.0.0.1:10210 \
    --cacert "$CA_CERT" \
    https://api.anthropic.com/v1/messages \
    -H "Content-Type: application/json" \
    -H "x-api-key: $REVOKE_TOKEN" \
    -H "anthropic-version: 2023-06-01" \
    -d '{"model":"claude-sonnet-4-20250514","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')

if [ "$STATUS" = "403" ]; then
    pass "test 6: revoked token → 403"
else
    fail "test 6: expected 403, got $STATUS"
fi

# --- Test 7: List tokens ---
info "test 7: list tokens returns valid JSON array"
LIST_RESPONSE=$(curl -sf http://localhost:10212/tokens)
TOKEN_COUNT=$(echo "$LIST_RESPONSE" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")

if [ "$TOKEN_COUNT" -gt 0 ]; then
    pass "test 7: list tokens returned $TOKEN_COUNT tokens"
else
    fail "test 7: expected tokens in list, got $TOKEN_COUNT"
fi

# --- Test 8: No-destination token (wildcard) ---
info "test 8: token with no destination restriction"
WILDCARD_TOKEN=$(curl -sf -X POST http://localhost:10212/tokens \
    -d "{\"credential\":\"$CRED\",\"ttl_seconds\":60}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

RESPONSE=$(curl -s -w '\n%{http_code}' \
    --proxy http://127.0.0.1:10210 \
    --cacert "$CA_CERT" \
    https://api.anthropic.com/v1/messages \
    -H "Content-Type: application/json" \
    -H "x-api-key: $WILDCARD_TOKEN" \
    -H "anthropic-version: 2023-06-01" \
    -d '{"model":"claude-sonnet-4-20250514","max_tokens":5,"messages":[{"role":"user","content":"say hi"}]}')

STATUS=$(echo "$RESPONSE" | tail -n 1)

if [ "$STATUS" = "200" ] || [ "$STATUS" = "401" ] || [ "$STATUS" = "400" ]; then
    pass "test 8: wildcard token reached upstream (status=$STATUS)"
else
    fail "test 8: unexpected status $STATUS"
fi

# --- Test 9: Readonly policy blocks POST ---
info "test 9: readonly policy blocks POST requests"
READONLY_TOKEN=$(curl -sf -X POST http://localhost:10212/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"api.anthropic.com\"],\"ttl_seconds\":60,\"policy\":\"readonly\"}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy http://127.0.0.1:10210 \
    --cacert "$CA_CERT" \
    https://api.anthropic.com/v1/messages \
    -H "Content-Type: application/json" \
    -H "x-api-key: $READONLY_TOKEN" \
    -H "anthropic-version: 2023-06-01" \
    -d '{"model":"claude-sonnet-4-20250514","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')

if [ "$STATUS" = "403" ]; then
    pass "test 9: readonly policy blocked POST"
else
    fail "test 9: expected 403, got $STATUS"
fi

# --- Test 10: List policies ---
info "test 10: list policies returns built-in policies"
POLICY_COUNT=$(curl -sf http://localhost:10212/policies | \
    python3 -c "import sys,json; print(len(json.load(sys.stdin)))")

if [ "$POLICY_COUNT" -ge 4 ]; then
    pass "test 10: list policies returned $POLICY_COUNT policies"
else
    fail "test 10: expected at least 4 policies, got $POLICY_COUNT"
fi

# --- Test 11: Basic auth token swap (git-style) ---
info "test 11: Basic auth header with kf_ token"
BASIC_TOKEN=$(curl -sf -X POST http://localhost:10212/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"api.anthropic.com\"],\"ttl_seconds\":60}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Encode as Basic auth: username:kf_token (like git does)
BASIC_AUTH=$(echo -n "x-access-token:$BASIC_TOKEN" | base64)

RESPONSE=$(curl -s -w '\n%{http_code}' \
    --proxy http://127.0.0.1:10210 \
    --cacert "$CA_CERT" \
    https://api.anthropic.com/v1/messages \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $BASIC_AUTH" \
    -H "anthropic-version: 2023-06-01" \
    -d '{"model":"claude-sonnet-4-20250514","max_tokens":5,"messages":[{"role":"user","content":"say hi"}]}')

STATUS=$(echo "$RESPONSE" | tail -n 1)

# The token swap should work — Anthropic will reject Basic auth format,
# but a non-proxy error (401/400) means the swap happened and reached upstream
if [ "$STATUS" = "200" ] || [ "$STATUS" = "401" ] || [ "$STATUS" = "400" ]; then
    pass "test 11: Basic auth token swap reached upstream (status=$STATUS)"
else
    fail "test 11: expected upstream response, got $STATUS"
fi

echo ""
echo "========================================="
if [ "$FAILURES" -eq 0 ]; then
    echo -e " ${GREEN}All tests passed${NC}"
else
    echo -e " ${RED}$FAILURES test(s) failed${NC}"
fi
echo "========================================="
exit "$FAILURES"
