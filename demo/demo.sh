#!/usr/bin/env bash
#
# demo.sh -- Run inside the agent container to demonstrate KeyFence.
#
# This script shows:
#   1. The agent only has a kf_ token, not the real PAT
#   2. Direct internet access is blocked
#   3. HTTPS through the proxy works (curl)
#   4. gh CLI works through the proxy
#   5. Non-allowed destinations are blocked
#   6. Rate limiting enforcement
#
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

section() { echo -e "\n${BOLD}── $1 ──${NC}\n"; }
pass()    { echo -e "   ${GREEN}PASS${NC} $1"; }
fail()    { echo -e "   ${RED}FAIL${NC} $1"; }
info()    { echo -e "   ${YELLOW}INFO${NC} $1"; }

echo -e "${BOLD}"
echo "============================================"
echo "  KeyFence Demo"
echo "============================================"
echo -e "${NC}"

# ── 1. Show the token ──────────────────────────────────────────────────
section "1. Agent's credential is an opaque kf_ token"

echo "   GITHUB_TOKEN=$GITHUB_TOKEN"
if echo "$GITHUB_TOKEN" | grep -q '^kf_'; then
    pass "token starts with kf_ (not a real PAT)"
else
    fail "expected kf_ prefix"
fi

# ── 2. Direct internet is blocked ─────────────────────────────────────
section "2. Direct internet access is blocked"

info "trying: curl --noproxy '*' https://github.com"
if curl -sf --max-time 3 --noproxy '*' https://github.com >/dev/null 2>&1; then
    fail "direct internet access succeeded (should be blocked)"
else
    pass "direct internet blocked (agent-isolated network has no gateway)"
fi

# ── 3. curl through the proxy works ───────────────────────────────────
section "3. HTTPS through the KeyFence proxy works"

info "trying: curl https://api.github.com/user"
USER_JSON=$(curl -sf https://api.github.com/user \
    -H "Authorization: Bearer $GITHUB_TOKEN" 2>&1) || true

if echo "$USER_JSON" | jq -e '.login' >/dev/null 2>&1; then
    LOGIN=$(echo "$USER_JSON" | jq -r '.login')
    pass "authenticated as $LOGIN via curl through proxy"
else
    fail "could not authenticate (check your GitHub PAT)"
    echo "   Response: $USER_JSON"
fi

# ── 4. gh CLI works through the proxy ─────────────────────────────────
section "4. gh CLI works through the proxy"

info "trying: gh api /user"
GH_JSON=$(gh api /user 2>&1) || true

if echo "$GH_JSON" | jq -e '.login' >/dev/null 2>&1; then
    LOGIN=$(echo "$GH_JSON" | jq -r '.login')
    pass "gh authenticated as $LOGIN"
else
    fail "gh could not authenticate"
    echo "   Response: $GH_JSON"
fi

info "trying: gh repo list --limit 3"
REPOS=$(gh repo list --limit 3 2>&1) || true
if [ -n "$REPOS" ]; then
    pass "gh repo list returned results:"
    echo "$REPOS" | sed 's/^/        /'
else
    info "no repos returned (PAT may lack repo scope)"
fi

# ── 5. Non-allowed destinations are blocked ────────────────────────────
section "5. Non-allowed destinations are blocked by token policy"

info "trying: curl https://api.openai.com/ (not in allowed destinations)"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    https://api.openai.com/ 2>&1) || true

if [ "$HTTP_CODE" = "403" ]; then
    pass "request to api.openai.com blocked (HTTP 403)"
else
    fail "expected 403, got $HTTP_CODE"
fi

# ── 6. Rate limiting ──────────────────────────────────────────────────
section "6. Rate limiting"

info "the standard policy allows 1000 req/hour"
info "to see rate limiting in action, you can issue a tighter token from the host:"
echo ""
echo "   # From the host (not inside this container):"
echo '   curl -H "Authorization: Bearer $KEYFENCE_API_KEY" \'
echo "     -X POST http://localhost:10212/tokens \\"
echo '     -d '"'"'{"credential":"'"'"'"$GITHUB_TOKEN"'"'"'","destinations":["api.github.com"],"ttl_seconds":300,"rate_limit":3,"rate_window_seconds":60}'"'"
echo ""
info "then inside this container, set the new token and fire requests:"
echo ""
echo '   export GITHUB_TOKEN=kf_<new_token>'
echo '   for i in 1 2 3 4; do'
echo '     echo "Request $i: $(curl -s -o /dev/null -w "%{http_code}" \'
echo '       https://api.github.com/user -H "Authorization: Bearer $GITHUB_TOKEN")"'
echo '   done'
echo ""
info "requests 1-3 succeed, request 4 returns 429 (rate limited)"

echo ""
echo -e "${BOLD}============================================${NC}"
echo -e "${BOLD}  Demo complete. You are in a bash shell.${NC}"
echo -e "${BOLD}  Try: gh api /user, gh repo list, curl...${NC}"
echo -e "${BOLD}============================================${NC}"
echo ""
