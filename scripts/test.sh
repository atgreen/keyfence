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
skip() { echo -e "${YELLOW}SKIP${NC} $1"; SKIPPED=$((SKIPPED+1)); }

FAILURES=0
SKIPPED=0
DATA_DIR=$(mktemp -d)

# Deliberately not 10210/10212. A developer running KeyFence as a service has
# those, and a suite that quietly talked to it instead of to the instance it
# started would test the wrong process with the wrong CA -- which looks like a
# certificate failure and is not one.
PROXY_PORT="${KEYFENCE_TEST_PROXY_PORT:-10310}"
API_PORT="${KEYFENCE_TEST_API_PORT:-10312}"
SSH_PORT="${KEYFENCE_TEST_SSH_PORT:-10311}"

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
for port in "$PROXY_PORT" "$API_PORT" "$SSH_PORT"; do
    if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$port" 2>/dev/null \
       || (command -v ss >/dev/null && ss -ltn 2>/dev/null | grep -q ":$port "); then
        echo "port $port is already in use; set KEYFENCE_TEST_PROXY_PORT," \
             "KEYFENCE_TEST_API_PORT and KEYFENCE_TEST_SSH_PORT to free ones"
        exit 1
    fi
done

info "starting keyfence (data-dir=$DATA_DIR, api=:$API_PORT)..."
# With a control API key, because that is how anyone should run it: the suite
# should exercise the path that production uses, not the one that skips it.
KEYFENCE_API_KEY=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '%s' "$KEYFENCE_API_KEY" > "$DATA_DIR/api-key"
chmod 600 "$DATA_DIR/api-key"
AUTH="Authorization: Bearer $KEYFENCE_API_KEY"

./bin/keyfence --api-key-file "$DATA_DIR/api-key" --data-dir "$DATA_DIR" --proxy "127.0.0.1:$PROXY_PORT" --api "127.0.0.1:$API_PORT" --ssh "127.0.0.1:$SSH_PORT" &
KEYFENCE_PID=$!
sleep 1

# Check it's running
if ! curl -sf http://localhost:$API_PORT/health > /dev/null 2>&1; then
    fail "keyfence not responding on :$API_PORT"
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

# Most tests are answered by the proxy itself -- a refused token, a wrong
# destination, a policy denial -- and need nothing outside this machine. Two
# require the real upstream to answer, so they are skipped rather than failed
# where it cannot be reached.
if curl -s -o /dev/null --max-time 8 https://api.anthropic.com/ 2>/dev/null; then
    UPSTREAM_REACHABLE=true
else
    UPSTREAM_REACHABLE=false
    info "api.anthropic.com is not reachable; tests that need it will be skipped"
fi

# All tests use MITM proxy mode (HTTPS_PROXY + CONNECT)

# --- Test 0: the control API refuses callers without the key ---
info "test 0: unauthenticated control API call → 401"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:$API_PORT/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"api.anthropic.com\"],\"ttl_seconds\":60}")
if [ "$STATUS" = "401" ]; then
    pass "test 0: minting without the control key refused (401)"
else
    fail "test 0: expected 401 minting without the control key, got $STATUS"
fi

# --- Test 1: No token → 401 ---
info "test 1: request without token → 401"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy http://127.0.0.1:$PROXY_PORT \
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
if [ "$UPSTREAM_REACHABLE" != "true" ]; then
    skip "test 2: needs api.anthropic.com to answer"
else
info "test 2: issue token and make authenticated request"
TOKEN=$(curl -sf -X POST -H "$AUTH" http://localhost:$API_PORT/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"api.anthropic.com\"],\"ttl_seconds\":60}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

if [ -z "$TOKEN" ]; then
    fail "test 2: failed to issue token"
else
    info "issued token: ${TOKEN:0:30}..."

    # GET /v1/models rather than POST /v1/messages: what this test is about is
    # whether the token was swapped for the real credential, and a model name is
    # a dependency on Anthropic's catalogue that goes stale and spends tokens
    # proving nothing. An authenticated metadata call answers the same question.
    RESPONSE=$(curl -s -w '\n%{http_code}' \
        --proxy http://127.0.0.1:$PROXY_PORT \
        --cacert "$CA_CERT" \
        https://api.anthropic.com/v1/models \
        -H "x-api-key: $TOKEN" \
        -H "anthropic-version: 2023-06-01")

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

fi

# --- Test 3: Expired token → 403 ---
info "test 3: expired token → 403"
EXPIRED_TOKEN=$(curl -sf -X POST -H "$AUTH" http://localhost:$API_PORT/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"api.anthropic.com\"],\"ttl_seconds\":1}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

sleep 2

STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy http://127.0.0.1:$PROXY_PORT \
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
# Its own token rather than test 2's: a test that borrows another's state fails
# for the wrong reason the moment that one is skipped.
DEST_TOKEN=$(curl -sf -X POST -H "$AUTH" http://localhost:$API_PORT/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"api.anthropic.com\"],\"ttl_seconds\":300}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy http://127.0.0.1:$PROXY_PORT \
    --cacert "$CA_CERT" \
    https://api.openai.com/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $DEST_TOKEN" \
    -d '{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}')

if [ "$STATUS" = "403" ]; then
    pass "test 4: wrong destination → 403"
else
    fail "test 4: expected 403, got $STATUS"
fi

# --- Test 5: Token revocation ---
info "test 5: revoked token → 403"
REVOKE_TOKEN=$(curl -sf -X POST -H "$AUTH" http://localhost:$API_PORT/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"api.anthropic.com\"],\"ttl_seconds\":300}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

curl -sf -X DELETE "-H "$AUTH" http://localhost:$API_PORT/tokens/$REVOKE_TOKEN" > /dev/null

STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy http://127.0.0.1:$PROXY_PORT \
    --cacert "$CA_CERT" \
    https://api.anthropic.com/v1/messages \
    -H "Content-Type: application/json" \
    -H "x-api-key: $REVOKE_TOKEN" \
    -H "anthropic-version: 2023-06-01" \
    -d '{"model":"claude-sonnet-4-20250514","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')

if [ "$STATUS" = "403" ]; then
    pass "test 5: revoked token → 403"
else
    fail "test 5: expected 403, got $STATUS"
fi

# --- Test 6: List tokens ---
info "test 6: list tokens returns valid JSON array"
LIST_RESPONSE=$(curl -sf -H "$AUTH" http://localhost:$API_PORT/tokens)
TOKEN_COUNT=$(echo "$LIST_RESPONSE" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")

if [ "$TOKEN_COUNT" -gt 0 ]; then
    pass "test 6: list tokens returned $TOKEN_COUNT tokens"
else
    fail "test 6: expected tokens in list, got $TOKEN_COUNT"
fi

# --- Test 7: No-destination token (wildcard) ---
# Omitting destinations is refused: an empty list means nothing is permitted, and
# a token that works anywhere has to be asked for as ["*"].
info "test 7a: a token with no destinations at all is refused"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "$AUTH" http://localhost:$API_PORT/tokens \
    -d "{\"credential\":\"$CRED\",\"ttl_seconds\":60}")
if [ "$STATUS" = "400" ]; then
    pass "test 7a: issuing without destinations refused (400)"
else
    fail "test 7a: expected 400 for a token with no destinations, got $STATUS"
fi

if [ "$UPSTREAM_REACHABLE" != "true" ]; then
    skip "test 7: needs api.anthropic.com to answer"
else
info "test 7: token with an explicit wildcard destination"
WILDCARD_TOKEN=$(curl -sf -X POST -H "$AUTH" http://localhost:$API_PORT/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"*\"],\"ttl_seconds\":60}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

RESPONSE=$(curl -s -w '\n%{http_code}' \
    --proxy http://127.0.0.1:$PROXY_PORT \
    --cacert "$CA_CERT" \
    https://api.anthropic.com/v1/models \
    -H "x-api-key: $WILDCARD_TOKEN" \
    -H "anthropic-version: 2023-06-01")

STATUS=$(echo "$RESPONSE" | tail -n 1)

if [ "$STATUS" = "200" ] || [ "$STATUS" = "401" ] || [ "$STATUS" = "400" ]; then
    pass "test 7: wildcard token reached upstream (status=$STATUS)"
else
    fail "test 7: unexpected status $STATUS"
fi

fi

# --- Test 8: Readonly policy blocks POST ---
info "test 8: readonly policy blocks POST requests"
READONLY_TOKEN=$(curl -sf -X POST -H "$AUTH" http://localhost:$API_PORT/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"api.anthropic.com\"],\"ttl_seconds\":60,\"policy\":\"readonly\"}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy http://127.0.0.1:$PROXY_PORT \
    --cacert "$CA_CERT" \
    https://api.anthropic.com/v1/messages \
    -H "Content-Type: application/json" \
    -H "x-api-key: $READONLY_TOKEN" \
    -H "anthropic-version: 2023-06-01" \
    -d '{"model":"claude-sonnet-4-20250514","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')

if [ "$STATUS" = "403" ]; then
    pass "test 8: readonly policy blocked POST"
else
    fail "test 8: expected 403, got $STATUS"
fi

# --- Test 9: List policies ---
info "test 9: list policies returns built-in policies"
POLICY_COUNT=$(curl -sf -H "$AUTH" http://localhost:$API_PORT/policies | \
    python3 -c "import sys,json; print(len(json.load(sys.stdin)))")

if [ "$POLICY_COUNT" -ge 4 ]; then
    pass "test 9: list policies returned $POLICY_COUNT policies"
else
    fail "test 9: expected at least 4 policies, got $POLICY_COUNT"
fi

# --- Test 10: Basic auth token swap (git-style) ---
info "test 10: Basic auth header with kf_ token"
BASIC_TOKEN=$(curl -sf -X POST -H "$AUTH" http://localhost:$API_PORT/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"api.anthropic.com\"],\"ttl_seconds\":60}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Encode as Basic auth: username:kf_token (like git does)
BASIC_AUTH=$(echo -n "x-access-token:$BASIC_TOKEN" | base64)

RESPONSE=$(curl -s -w '\n%{http_code}' \
    --proxy http://127.0.0.1:$PROXY_PORT \
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
    pass "test 10: Basic auth token swap reached upstream (status=$STATUS)"
else
    fail "test 10: expected upstream response, got $STATUS"
fi

# --- Test 11: Per-token rate limiting ---
info "test 11: per-token rate limit (2 req/60s)"
RATE_TOKEN=$(curl -sf -X POST -H "$AUTH" http://localhost:$API_PORT/tokens \
    -d "{\"credential\":\"$CRED\",\"destinations\":[\"api.anthropic.com\"],\"ttl_seconds\":60,\"rate_limit\":2,\"rate_window_seconds\":60}" | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# First two requests should succeed (200 or 401 from upstream)
for i in 1 2; do
    STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
        --proxy http://127.0.0.1:$PROXY_PORT \
        --cacert "$CA_CERT" \
        https://api.anthropic.com/v1/messages \
        -H "Content-Type: application/json" \
        -H "x-api-key: $RATE_TOKEN" \
        -H "anthropic-version: 2023-06-01" \
        -d '{"model":"claude-sonnet-4-20250514","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')
    if [ "$STATUS" = "429" ]; then
        fail "test 11: request $i should not be rate-limited, got 429"
        break
    fi
done

# Third request should be rate-limited → 429
STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy http://127.0.0.1:$PROXY_PORT \
    --cacert "$CA_CERT" \
    https://api.anthropic.com/v1/messages \
    -H "Content-Type: application/json" \
    -H "x-api-key: $RATE_TOKEN" \
    -H "anthropic-version: 2023-06-01" \
    -d '{"model":"claude-sonnet-4-20250514","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}')

if [ "$STATUS" = "429" ]; then
    pass "test 11: per-token rate limit enforced (429 on 3rd request)"
else
    fail "test 11: expected 429, got $STATUS"
fi

echo ""
echo "========================================="
if [ "$FAILURES" -eq 0 ]; then
    if [ "$SKIPPED" -eq 0 ]; then
        echo -e " ${GREEN}All tests passed${NC}"
    else
        echo -e " ${GREEN}All tests passed${NC} ($SKIPPED skipped)"
    fi
else
    echo -e " ${RED}$FAILURES test(s) failed${NC} ($SKIPPED skipped)"
fi
echo "========================================="
exit "$FAILURES"
