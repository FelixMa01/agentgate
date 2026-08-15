# AgentGate Quickstart

Get from `pip install` to a working firewall in under five minutes.

## 1. Install

```bash
pip install agentgate-firewall
# or, with uv (recommended):
uv tool install agentgate-firewall
```

Verify the install:

```bash
agentgate --version
# → 0.11.0
```

## 2. Generate a starter policy

```bash
mkdir my-agent && cd my-agent
agentgate init --preset balanced --output ./policy.yaml
```

This produces a `policy.yaml` covering the most common risky operations
(`rm -rf /`, exfiltration to pastebin, prompt-injection patterns) while
leaving ordinary `ls`/`grep`/`Read` calls allowed.

Three presets ship out of the box:

| Preset      | Default action | Best for                                   |
|-------------|----------------|--------------------------------------------|
| `readonly`  | deny           | Reviewing an unfamiliar codebase           |
| `balanced`  | allow          | Day-to-day Claude Code / Cursor work       |
| `strict`    | ask            | Production CI / shared dev machines        |

## 3. Audit database

```bash
export AGENTGATE_DB="$PWD/audit.db"
touch "$AGENTGATE_DB"
```

Every evaluation AgentGate performs writes a row here.

## 4. Smoke-test your policy

```bash
agentgate eval -p ./policy.yaml --db ./audit.db \
  --event-json '{"tool":"Bash","command":"ls -la"}' --json
# → {"action":"allow", ...}

agentgate eval -p ./policy.yaml --db ./audit.db \
  --event-json '{"tool":"Bash","command":"rm -rf /"}' --json
# → {"action":"deny", ...}
```

## 5. Wire it into your coding agent

```bash
agentgate install-hook -p ./policy.yaml --db ./audit.db
```

This writes the hook config to `.claude/settings.local.json` (Claude Code),
`.cursor/hooks.json` (Cursor), `.continue/settings.json` (Continue.dev),
and `.gemini/settings.json` (Gemini CLI) — pick the one your agent reads.

## 6. Watch decisions in real time

```bash
agentgate dashboard --db ./audit.db
# → open http://localhost:8766
```

For Prometheus / Grafana:

```bash
curl http://localhost:8766/metrics
# → agentgate_events_total{action="deny"} 12
```

## Next steps

- [Tutorial](tutorial.md) — build a custom policy for your stack
- [CLI reference](cli-reference.md) — every command
- [Policy reference](policy-reference.md) — match patterns, network rules, mode
- [Security model](security.md) — what AgentGate does (and does not) protect
