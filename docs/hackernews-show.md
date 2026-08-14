Title: Show HN: AgentGate – firewall for AI coding agents

---

I've spent the last 5 days building a small tool that sits between Claude Code (and friends) and the rest of your machine. It intercepts every tool call and network request the agent makes, applies a single YAML policy, and writes everything to a SQLite audit log you can browse in a single-page dashboard.

GitHub: https://github.com/FelixMa01/agentgate
Try it: `uv tool install agentgate` (or `pip install agentgate` once PyPI'd)

## What it does

The hook is a PreToolUse script that Claude Code (and any other agent that supports hooks) calls before each tool call. AgentGate evaluates the event against `policy.yaml`:

```yaml
rules:
  - id: deny-rm-rf
    match: { tool: Bash, command: "rm -rf /*" }
    action: deny
    reason: "Mass deletion outside repo"
  - id: ask-outbound
    match: { tool: Bash, command: "~\\bcurl\\b|\\bwget\\b" }
    action: ask
    reason: "Outbound network from agent"

network:
  allowed_domains: ["github.com", "*.pypi.org"]
  require_https: true
```

Actions:
- `allow` – tool runs, logged
- `deny` – tool blocked, user sees the reason
- `ask` – Slack message posted, the hook blocks until a human clicks Allow/Deny (or default 60s timeout → deny)

A separate mitmproxy add-on enforces the same YAML for outbound HTTP, returning 403 with an "AgentGate: DENY" body for blocked domains.

A 35-line single-page HTML dashboard reads the audit DB and shows live stats, top denied rules, and a 24-hour time-series.

## Why

I noticed three things while watching coding agents run:

1. **Per-agent permission systems don't see network egress.** Claude Code's settings.json blocks Bash commands but doesn't see what `curl` sends over the wire.
2. **Cross-tool audit is missing.** Hooks in Cursor, Claude Code, Codex etc. each log to their own format — no place to grep for "did this agent ever try to read .env?".
3. **Ask-the-human doesn't fit in a terminal.** A Slack approve/deny button reaches engineers where they already are.

I cloned 7 existing agent-firewall repos (agentjail, Armorer, ryk, sandshell, avakill, AgentFense, EctoLedger) and saw all of them miss at least one of the above. AgentGate tries to cover all three.

## What's NOT in it

- Only Claude Code has a tested adapter. Cursor's permission API and Codex's PreToolUse equivalent are both doable but not shipped yet.
- Slack is the only notification channel. A Telegram webhook would be ~20 lines.
- No hosted SaaS mode. Self-hosted only.

## Stack

Python 3.12+, ~1100 LOC, 48 unit tests, GitHub Actions on Py 3.12 + 3.13. mitmproxy for the network layer. SQLite for everything. No JS, no cloud deps.

## Feedback I'd love

- Which agent is the next most painful to plug into? (Cursor? Aider? Continue.dev?)
- Which notification channel do you actually read? (Slack, Telegram, Discord, email?)
- Is "centralized policy across a team" interesting, or is per-repo `policy.yaml` enough?

Happy to walk anyone through the hook install — it's one command and the policy file is one YAML.

— Felix