# Contributing to AgentGate

## Setup

```bash
git clone https://github.com/FelixMa01/agentgate.git
cd agentgate
uv sync
```

## Verify everything works

```bash
bash scripts/verify.sh
```

This runs the full 8-step end-to-end smoke test in under 30 seconds:

1. pytest (all unit tests pass)
2. CLI: `agentgate eval` (allow + deny)
3. Dashboard HTTP server (HTML + /api/stats)
4. Approval server (cross-process resolve)
5. Network proxy (200 allow + 403 deny)
6. Claude Code hook (real protocol output)
7. Cursor hook (cursor_to_event translation)
8. PyPI install (`agentgate-firewall` from real PyPI)

If any step fails, the script exits non-zero.

## Project layout

```
src/agentgate/
  __init__.py           version + docstring
  policy.py             YAML → Rule objects + Action enum
  audit.py              SQLite append-only audit log
  hook.py               Claude Code PreToolUse entrypoint
  cursor_hook.py        Cursor beforeShellExecution entrypoint
  network.py            URL/domain matching, NetDecision
  proxy_addon.py        mitmproxy add-on (DNS/HTTPS filtering)
  approval.py           SQLite-backed cross-process ApprovalStore
  approval_server.py    HTTP /approve/<token> server
  notify.py             Slack Block Kit + file fallback
  dashboard.py          HTTP server + single-page HTML viewer
  cli.py                Click CLI (init/eval/audit/stats/...)
bin/agentgate-hook.py   venv python shebang launcher
examples/policy.yaml    example policy
scripts/verify.sh       end-to-end smoke test
```

## Adding a new adapter

Want to support Codex, Aider, Continue.dev, or another agent?

1. Read the agent's hook docs.
2. Add a module like `src/agentgate/<agent>_hook.py`.
3. Translate the agent's payload into AgentGate event schema:
   - `tool` (string)
   - `command` or `file_path` (string)
   - `agent` (string)
   - `session_id`, `cwd` (optional)
4. Call `evaluate_event(event, source="<agent>")` from `agentgate.hook`.
5. Write the response JSON to stdout in the agent's format.
6. Add a CLI subcommand `<agent>-hook` that writes the config file.
7. Add a test in `tests/test_<agent>.py` that exercises the real subprocess.

The whole adapter is usually ~50 lines + tests.

## Adding a new policy action

1. Add the value to `Action` enum in `policy.py`.
2. Handle it in `hook.py:evaluate_event`.
3. Add a test in `tests/test_core.py`.

## Style

- Python 3.12+, no walrus on by default
- `from __future__ import annotations`
- Black + isort defaults; flake8 unused-imports only
- No external runtime deps beyond `click mitmproxy pyyaml rich`

## Releasing

1. **Bump version** in both `pyproject.toml` and `src/agentgate/__init__.py` (must match).
2. **Run all checks locally**:
   ```bash
   make verify    # 10-step e2e
   make test      # 83+ unit tests
   ```
3. **Build**:
   ```bash
   make build     # produces dist/agentgate_firewall-X.Y.Z-py3-none-any.whl + .tar.gz
   ```
4. **Upload to PyPI** (Test PyPI first if unsure):
   ```bash
   export UV_PUBLISH_TOKEN=pypi-***
   make publish   # or: uv publish dist/agentgate_firewall-X.Y.Z-*
   ```
   PyPI token: https://pypi.org/manage/account/token/ — scope it to the
   `agentgate-firewall` project. Revoke after publishing.
5. **Verify install** in a fresh venv:
   ```bash
   uv venv /tmp/check && /tmp/check/bin/pip install agentgate-firewall
   /tmp/check/bin/agentgate --version    # should print new version
   ```
6. **Tag + GitHub release**:
   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   gh release create vX.Y.Z --title "..." --notes-file CHANGELOG.md
   ```
7. **Update `CHANGELOG.md`** with the new version's section before step 3.

### Why a separate PyPI name (`agentgate-firewall`)

The plain `agentgate` PyPI package was already taken (a different multi-agent
framework). We use `agentgate-firewall` on PyPI but the CLI command stays
`agentgate`.

## License

Apache 2.0. By contributing you agree to license your work under the same.