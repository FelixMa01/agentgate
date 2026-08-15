# AgentGate CLI reference

Every command in the v0.11.0 CLI. Run `agentgate <cmd> --help` for the
full flag set.

## Policy commands

| Command | Purpose |
|---|---|
| `agentgate init` | Generate a starter policy.yaml from a preset (readonly/balanced/strict) or via interactive wizard |
| `agentgate validate` | Check a policy file for syntax + reference errors |
| `agentgate lint` | Style checks for policy.yaml (best-practice + dead-rule detection) |
| `agentgate diff` | Diff two policies and explain decision changes |
| `agentgate eval` | Evaluate a single event against a policy (one-shot, no daemon) |
| `agentgate test-policy` | Run a JSONL fixture of events against a policy |

## Hook installation

| Command | Target |
|---|---|
| `agentgate install-hook` | Claude Code (`.claude/settings.local.json`) |
| `agentgate install-cursor-hook` | Cursor (`.cursor/hooks.json`) |
| `agentgate install-continue-hook` | Continue.dev (`.continue/settings.json`) |
| `agentgate install-gemini-hook` | Gemini CLI (`.gemini/settings.json`) |
| `agentgate uninstall-hook` | Remove all AgentGate hooks |

## Daemons

| Command | Purpose |
|---|---|
| `agentgate dashboard` | Audit DB browser + SSE event stream + Prometheus `/metrics` |
| `agentgate approval-server` | HTTP server for resolving ASK events |
| `agentgate proxy` | mitmdump wrapper that enforces network policy on egress |

## Audit & observability

| Command | Purpose |
|---|---|
| `agentgate audit` | Inspect rows from the audit DB (filter by action/source/agent/rule) |
| `agentgate stats` | Aggregate counts (total/allow/deny/ask) |
| `agentgate alerts` | Subscribe to threshold alerts (e.g. "deny count > 10 in 5 min") |
| `agentgate replay` | Re-evaluate a historical event against the current policy |
| `agentgate detect-agents` | Scan the local machine for installed coding agents |

## Integrations

| Command | Purpose |
|---|---|
| `agentgate webhook add/list/remove/test` | Manage outbound webhooks (HMAC-signed, exp-backoff retries) |
| `agentgate mcp` | Expose AgentGate as a stdio MCP server (4 tools) |
| `agentgate hosted pull-policy` | Pull a policy from a hosted AgentGate instance |
| `agentgate hosted push-events` | Push audit events to a hosted AgentGate instance |

## Doctor & docs

| Command | Purpose |
|---|---|
| `agentgate doctor` | Health-check (Python version, mitmproxy installed, DB writable, policy valid) |
| `agentgate docs` | Open the README in a browser |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success / allowed |
| 1 | denied (action blocked) |
| 2 | invalid arguments / policy syntax |
| 3 | internal error (see stderr) |
