# Verifying AgentGate on a fresh clone

A short script that exercises every public surface from a clean checkout. Useful
as both a manual dogfood step and as a smoke test before reporting bugs.

## Run it

```bash
git clone https://github.com/FelixMa01/agentgate.git /tmp/agentgate-verify
cd /tmp/agentgate-verify
uv sync
./scripts/verify.sh
```

The script:

1. Runs the full pytest suite (48 tests, ~6s).
2. Initializes a fresh policy + audit DB in `./demo/`.
3. Runs the CLI smoke tests: `eval` with allow/deny/ask events, `stats`, `validate`.
4. Starts the dashboard in the background, hits every JSON endpoint, kills it.
5. Starts the approval server in the background, sends a fake ask via SQLite, hits `/approve`, kills it.
6. Starts the mitmproxy add-on in the background, curls through it twice (allowed + denied domains), kills it.
7. Installs the Claude Code PreToolUse hook into a temp project dir, runs the hook binary with a sample payload, confirms it returns `deny`, then uninstalls.

If any step fails, the script exits non-zero with the failing step number.

## What the script does NOT do

- It does not talk to a real Claude Code session — the hook is run as a standalone subprocess.
- It does not send real Slack messages (no `AGENTGATE_SLACK_WEBHOOK` set in CI).
- It does not require `sudo`; everything runs under the current user.

## CI

GitHub Actions runs `pytest` on every push and PR (Python 3.12 + 3.13). For a
real hook integration test, see `.github/workflows/test.yml`.