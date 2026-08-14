---
layout: default
title: AgentGate — firewall for AI coding agents
---

# AgentGate

**Firewall for AI coding agents — intercept, log, approve every action.**

AgentGate sits between your AI coding agent and the rest of your system. One CLI, three small pieces:

1. **`agentgate install-hook`** — registers a PreToolUse hook with Claude Code (or any MCP-compatible agent) that intercepts Bash / Read / Write / Edit / WebFetch / Grep / Glob calls.
2. **`agentgate proxy`** — a mitmproxy add-on that intercepts every outbound HTTP(S) request and applies your domain allow/deny list.
3. **`agentgate dashboard`** — a single-page HTML viewer for the audit log, with live stats, time series, and per-rule breakdowns.

![dashboard](docs/dashboard.svg)

## Install

```bash
uv tool install agentgate-firewall
agentgate doctor    # verify your install
```

Or with pip:

```bash
pip install agentgate-firewall
```

## Quick start

```bash
# 1. Scaffold a policy
agentgate init --dir ~/.agentgate

# 2. Install the Claude Code hook
agentgate install-hook --policy ~/.agentgate/policy.yaml --db ~/.agentgate/audit.db

# 3. Watch the audit log live
agentgate dashboard --db ~/.agentgate/audit.db --port 8765
# open http://localhost:8765/

# 4. Try a request
agentgate eval -p ~/.agentgate/policy.yaml --db /tmp/x.db \
  --event-json '{"tool": "Bash", "command": "rm -rf /"}'
# → ✗ DENY  deny-destructive-bash
```

## Why AgentGate?

| Without AgentGate | With AgentGate |
| --- | --- |
| AI agent runs `rm -rf /` | Blocked by default-deny + destructive-command regex |
| AI agent exfiltrates secrets via curl | Blocked by network allowlist |
| AI agent merges a broken PR | Requires human click via Slack / Telegram |
| AI agent reads `.env` silently | Logged to audit DB with full context |
| 30 different agents, no central policy | One YAML, served by `pull-policy` to all hosts |

## Supported agents

- **Claude Code** (PreToolUse hook)
- **Cursor** (`~/.cursor/hooks.json`)
- **Continue.dev** (`.continue/hooks/`)
- **Aider** (`~/.aider.conf.yml`)
- **GitHub Actions** (workflow `::error` annotations)

## Supported notifications

- **Telegram** (`AGENTGATE_TELEGRAM_BOT_TOKEN`, `AGENTGATE_TELEGRAM_CHAT_ID`)
- **Slack** (incoming webhook URL)
- **File fallback** (writes to a JSONL on disk for testing)

## 17 CLI commands

```
init                  Scaffold a new policy + audit DB
eval                  Evaluate a single event against a policy
audit                 Query the audit log
stats                 Aggregate audit counts (--by-source, --by-rule)
validate              YAML schema check
install-hook          Register Claude Code PreToolUse hook
uninstall-hook        Remove the hook
install-cursor-hook   Register Cursor hook
install-continue-hook Register Continue.dev hook
proxy                 Run the mitmproxy addon
approval-server       HTTP server for /approve/<token>?d=allow|deny
ask-test              Generate a fake ask request (smoke-test)
dashboard             Single-page HTML viewer with SSE
replay                Replay an audit log through a new policy
doctor                Check Python version, deps, ports, channels
lint                  Lint a policy.yaml (duplicate IDs, empty matches)
docs                  Print README + architecture + policy-reference paths
```

## Links

- Source: <https://github.com/FelixMa01/agentgate>
- PyPI: <https://pypi.org/project/agentgate-firewall/>
- Issues: <https://github.com/FelixMa01/agentgate/issues>
- Releases: <https://github.com/FelixMa01/agentgate/releases>
- Architecture: [docs/architecture.md](docs/architecture.md)
- Policy reference: [docs/policy-reference.md](docs/policy-reference.md)
