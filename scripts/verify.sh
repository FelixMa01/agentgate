#!/usr/bin/env bash
# Verifies AgentGate end-to-end from a clean checkout.
# Exits non-zero on first failure.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

step=0
fail() { echo "✗ step $1 failed"; exit 1; }
ok()   { echo "✓ $1"; }

# 1. Pytest
step=$((step+1))
uv run pytest tests/ -q | tail -1 | grep -qE 'passed' && ok "pytest (all passed)" || fail $step

# 2. Init + smoke eval
step=$((step+1))
rm -rf demo && mkdir demo
uv run agentgate init --preset balanced --force --output ./demo/policy.yaml >/dev/null
ALLOW=$(uv run agentgate eval -p ./demo/policy.yaml --db ./demo/audit.db \
  --event-json '{"tool":"Bash","command":"ls -la"}' --json 2>/dev/null || true)
DENY=$(uv run agentgate eval -p ./demo/policy.yaml --db ./demo/audit.db \
  --event-json '{"tool":"Bash","command":"rm -rf /etc"}' --json 2>/dev/null || true)
echo "$ALLOW" | grep -q '"allow"' && echo "$DENY" | grep -q '"deny"' && ok "cli eval (allow + deny)" || fail $step

# 3. Dashboard endpoints
step=$((step+1))
uv run agentgate dashboard --db ./demo/audit.db --port 18790 >/dev/null 2>&1 &
DPID=$!
sleep 2
HTML=$(curl -fs http://127.0.0.1:18790/)
STATS=$(curl -fs http://127.0.0.1:18790/api/stats)
kill $DPID 2>/dev/null || true
echo "$HTML" | grep -q "AgentGate" && echo "$STATS" | grep -q '"total"' \
  && ok "dashboard (HTML + /api/stats)" || fail $step

# 4. Approval server + cross-process resolve
step=$((step+1))
uv run python -c "
import os, threading, time
os.environ['AGENTGATE_DB'] = './demo/audit.db'
from agentgate.approval_server import serve
serve('127.0.0.1', 18791)
" >/dev/null 2>&1 &
APID=$!
sleep 2
TOKEN=$(uv run python -c "
import os; os.environ['AGENTGATE_DB']='./demo/audit.db'
from agentgate.approval import STORE
ask = STORE.request({'tool':'Bash','command':'verify'},'Bash','verify')
print(ask.token)
")
RESP=$(curl -fs "http://127.0.0.1:18791/approve/$TOKEN?d=allow" || true)
kill $APID 2>/dev/null || true
echo "$RESP" | grep -qi "allow" && ok "approval server (resolved allow)" || fail $step

# 5. Network proxy
step=$((step+1))
cat > /tmp/agentgate-verify-policy.yaml <<EOF
version: 1
default: allow
rules: []
network:
  allowed_domains: ["example.com"]
  require_https: false
EOF
AGENTGATE_POLICY=/tmp/agentgate-verify-policy.yaml \
AGENTGATE_DB=./demo/audit.db \
  uv run mitmdump --mode regular --listen-port 18792 --quiet --set block_global=false \
  --scripts src/agentgate/proxy_addon.py >/dev/null 2>&1 &
PROXY_PID=$!
sleep 3
ALLOW_HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 --proxy http://127.0.0.1:18792 http://example.com/ || true)
DENY_HTTP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 --proxy http://127.0.0.1:18792 http://other-domain.test/ || true)
kill $PROXY_PID 2>/dev/null || true
[ "$ALLOW_HTTP" = "200" ] && [ "$DENY_HTTP" = "403" ] && ok "network proxy (200 allow + 403 deny)" || { echo "got allow=$ALLOW_HTTP deny=$DENY_HTTP"; fail $step; }

# 6. Hook install + run + uninstall
step=$((step+1))
TMPHOOK=$(mktemp -d)
cat > "$TMPHOOK/policy.yaml" <<EOF
version: 1
default: allow
rules:
  - id: deny-rm
    match: {tool: Bash, command: "rm -rf /*"}
    action: deny
EOF
uv run agentgate install-hook -p "$TMPHOOK/policy.yaml" --db "$TMPHOOK/audit.db" --target "$TMPHOOK" >/dev/null 2>&1
cat > "$TMPHOOK/payload.json" <<EOF
{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /etc"}}
EOF
HOOK_OUT=$(AGENTGATE_POLICY="$TMPHOOK/policy.yaml" AGENTGATE_DB="$TMPHOOK/audit.db" \
  AGENTGATE_PAYLOAD_FILE="$TMPHOOK/payload.json" \
  .venv/bin/python bin/agentgate-hook.py 2>/dev/null)
uv run agentgate uninstall-hook --target "$TMPHOOK" >/dev/null 2>&1
rm -rf "$TMPHOOK"
echo "$HOOK_OUT" | grep -q '"deny"' && ok "hook install + deny (real Claude Code protocol output)" || { echo "got: $HOOK_OUT"; fail $step; }

# 7. Cursor hook — same deny path, different payload shape
step=$((step+1))
TMPCURSOR=$(mktemp -d)
cat > "$TMPCURSOR/policy.yaml" <<EOF
version: 1
default: allow
rules:
  - id: deny-rm
    match: {tool: Bash, command: "rm -rf /*"}
    action: deny
EOF
uv run agentgate install-cursor-hook -p "$TMPCURSOR/policy.yaml" --db "$TMPCURSOR/audit.db" --target "$TMPCURSOR" >/dev/null 2>&1
cat > "$TMPCURSOR/payload.json" <<EOF
{"hook_event_name":"beforeShellExecution","tool_name":"Shell","tool_input":{"command":"rm -rf /etc"}}
EOF
CURSOR_OUT=$(AGENTGATE_POLICY="$TMPCURSOR/policy.yaml" AGENTGATE_DB="$TMPCURSOR/audit.db" \
  AGENTGATE_PAYLOAD_FILE="$TMPCURSOR/payload.json" \
  .venv/bin/python -m agentgate.cursor_hook 2>/dev/null)
rm -rf "$TMPCURSOR"
echo "$CURSOR_OUT" | grep -q '"deny"' && ok "cursor hook install + deny" || { echo "got: $CURSOR_OUT"; fail $step; }

echo
# (overwritten below by PyPI step)
# 8. PyPI install — verify the published package is installable
step=$((step+1))
PYTESTMP=$(mktemp -d)
(cd "$PYTESTMP" && uv venv --quiet && uv pip install agentgate-firewall --quiet 2>&1 | tail -2)
PYAG=$(ls "$PYTESTMP/.venv/bin/agentgate" 2>/dev/null || true)
if [ -x "$PYAG" ]; then
  PYVER=$("$PYAG" --version 2>&1)
  rm -rf "$PYTESTMP"
  echo "$PYVER" | grep -qE "agentgate, version" && ok "PyPI install (agentgate-firewall latest)" || { echo "got: $PYVER"; fail $step; }
else
  rm -rf "$PYTESTMP"
  fail $step
fi

echo

# 9. Continue.dev hook — same format as Claude Code
step=$((step+1))
TMPCONT=$(mktemp -d)
cat > "$TMPCONT/policy.yaml" <<EOF
version: 1
default: allow
rules:
  - id: deny-rm
    match: {tool: Bash, command: "rm -rf /*"}
    action: deny
EOF
cat > "$TMPCONT/payload.json" <<EOF
{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /etc"}}
EOF
CONT_OUT=$(AGENTGATE_POLICY="$TMPCONT/policy.yaml" AGENTGATE_DB="$TMPCONT/audit.db" \
  AGENTGATE_PAYLOAD_FILE="$TMPCONT/payload.json" \
  .venv/bin/python -m agentgate.continue_hook 2>/dev/null)
rm -rf "$TMPCONT"
echo "$CONT_OUT" | grep -q '"deny"' && ok "continue hook install + deny" || { echo "got: $CONT_OUT"; fail $step; }

# 10. GitHub Actions adapter — annotate a fake diff
step=$((step+1))
TMPA=$(mktemp -d)
# Provide a real policy file so the actions adapter doesn't warn.
cat > "$TMPA/policy.yaml" <<'POL'
version: 1
default: allow
rules: []
POL
(
  cd "$TMPA"
  git init -q && git config user.email t@t && git config user.name T
  echo "ok" > a.py && git add a.py && git commit -q -m init
  echo "diff content" > b.py
  AGENTGATE_POLICY="$TMPA/policy.yaml" AGENTGATE_DB="$TMPA/audit.db" \
    AGENTGATE_WORKSPACE="$TMPA" \
    "$ROOT/.venv/bin/python" -m agentgate.actions_annotate > /tmp/actions.log 2>&1 || true
)
grep -q "AgentGate reviewed" /tmp/actions.log && ok "actions annotate (CI workflow commands)" || { echo "log: $(cat /tmp/actions.log)"; fail $step; }
rm -rf "$TMPA" /tmp/actions.log

echo
echo "All 10 steps verified ✓"