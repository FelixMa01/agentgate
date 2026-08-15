# AgentGate — Firewall for AI Coding Agents

[![PyPI version](https://badge.fury.io/py/agentgate-firewall.svg)](https://pypi.org/project/agentgate-firewall/)
[![CI](https://github.com/FelixMa01/agentgate/workflows/CI/badge.svg)](https://github.com/FelixMa01/agentgate/actions)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

AgentGate sits between AI coding agents (Claude Code, Cursor, Continue.dev,
Aider, Gemini CLI, OpenAI Codex) and your machine. It intercepts every
Bash / Read / Edit / Write call, applies a policy, scans outgoing HTTP
for data-exfiltration patterns, and asks a human via Telegram / Discord
/ Slack when the call is risky.

## Why

| Without AgentGate | With AgentGate |
|---|---|
| Agent can `rm -rf /` with no warning | Deny rules block destructive ops before they run |
| Agent can leak API keys to pastebin.com | DLP scanner rejects outgoing bodies containing `sk-ant-…` |
| Agent can fetch arbitrary URLs | Allowlist / blocklist of domains |
| No record of what the agent did | Tamper-evident SQLite audit chain, optionally Ed25519-signed |
| Prompt-injection payloads slip through | 28+ injection patterns scanned on every request |

## Install

```bash
pip install agentgate-firewall
agentgate doctor        # check pre-requisites
agentgate init          # write a starter policy.yaml
agentgate start         # launch the proxy on :18790
```

Then install the Claude Code / Cursor / Aider hook:

```bash
agentgate install-hook           # Claude Code
agentgate install-cursor-hook    # Cursor
agentgate install-continue-hook   # Continue.dev
agentgate install-aider-hook      # Aider
agentgate install-gemini-hook     # Gemini CLI
agentgate install-codex-hook      # OpenAI Codex CLI
```

## Policy example

```yaml
version: 1
default: deny

rules:
  # Read access to dotfiles is OK
  - id: allow-read-configs
    match: {tool: Read, file_glob: "~/.config/*"}
    action: allow

  # Block destructive Bash commands
  - id: deny-rm-rf
    match: {tool: Bash, command_regex: "rm\\s+-[rf]+.*"}
    action: deny
    reason: "Recursive delete blocked"

  # Allow `kubectl apply` but require human approval
  - id: ask-kubectl-apply
    match: {tool: Bash, command_regex: "kubectl apply.*"}
    action: ask

  # CEL-lite `when` conditions
  - id: deny-rm-elsewhere
    match: {tool: Bash, command_regex: "rm -rf.*"}
    action: deny
    when: 'event.cwd != "/srv"'

  # Rate-limit noisy rules
  - id: ask-deploy
    match: {tool: Bash, command_regex: "kubectl apply.*"}
    action: ask
    rate_limit: {capacity: 5, refill_per_sec: 0.1}

network:
  allowed_domains:
    - "*.github.com"
    - "*.anthropic.com"
    - "registry.npmjs.org"
  require_https: true
```

## Subcommands

| Command | Purpose |
|---|---|
| `agentgate start` | Run the mitmproxy-based intercept proxy |
| `agentgate scan` | Static security scanner for AI agent configs |
| `agentgate audit` | Read the audit log |
| `agentgate audit verify` | Verify the SHA-256 audit chain |
| `agentgate receipts verify` | Verify Ed25519-signed receipts |
| `agentgate coverage` | Dead-rule + uncovered-tool report |
| `agentgate env add|use|list` | Multi-environment policy manager |
| `agentgate policy test` | Replay events against a policy (dry-run) |
| `agentgate doctor` | Pre-flight health check |

## Security features

- **Bash/Read/Edit/Write intercept** — every tool call passes through `policy.evaluate()`.
- **CEL-lite `when`** — gate matches on event fields (`event.cwd != "/srv"`).
- **Token-bucket rate limiting** — per-rule throttling without bricking the agent.
- **DLP egress scan** — 50+ API-key patterns, JWTs, private keys, DB connection strings.
- **Prompt-injection scanner** — 28+ markers (`ignore previous instructions`, role overrides, etc.).
- **Network allow/block lists** — domain + HTTPS enforcement + per-rule exemptions.
- **Tamper-evident audit chain** — SHA-256 chained rows; integrity verifiable.
- **Ed25519-signed receipts** — optional cryptographic proof of audit entry provenance.
- **HMAC-signed webhooks** — verify callbacks actually came from AgentGate.
- **Multi-channel approval** — Telegram / Discord / Slack / approval server / file.
- **Multi-environment manager** — dev / staging / prod switching.

## Supported agents

| Agent | Hook | Install |
|---|---|---|
| Claude Code | PreToolUse → JSON | `agentgate install-hook` |
| Cursor | beforeShellExecution | `agentgate install-cursor-hook` |
| Continue.dev | `beforeCommand` etc. | `agentgate install-continue-hook` |
| Aider | `pre-commit` adapter | `agentgate install-aider-hook` |
| Gemini CLI | BeforeTool | `agentgate install-gemini-hook` |
| OpenAI Codex CLI | Before hook | `agentgate install-codex-hook` |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Run `agentgate doctor` first to
verify your environment.

## License

Apache 2.0 — see [LICENSE](LICENSE).