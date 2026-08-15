# Changelog

All notable changes to AgentGate are documented here. Dates are UTC.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.13.1] - 2026-08-15

### Added
- **`agentgate lint <policy.yaml>`** — static policy linter (`lint.py`). 12 rule classes:
  bad-action / bad-default / empty-match / unknown-tool / missing-id / duplicate-id /
  shadowed-rule / catchall-allow / cel-unknown-key / bad-rate-limit[-keys] /
  network-domain-contradiction / unknown-network-key. Exits 2 on error, 1 on
  warning under `--strict`. JSON output via `--json-output`.
- **5 named policy templates** (`templates.py`): `yolo`, `enterprise`, `airgapped`,
  `ci-cd`, `pair-programming`. Use via `agentgate init --template <name>`.
- **`agentgate replay <trace.jsonl> <policy.yaml>`** — replay a recorded session
  of policy events against a new policy; reports divergences. `--strict` exits
  non-zero on any divergence so it can gate a CI pipeline.
- **`benchmarks.py`** — 30-vector security benchmark spanning destructive bash,
  DLP exfil, prompt injection, safe ops, and provider self-calls. Reports
  accuracy + per-failure details. Run via `python -m agentgate.benchmarks`.
- **`action.yml`** — GitHub Action composite: installs AgentGate, runs doctor /
  lint / scan / DLP samples, uploads `agentgate-scan.json` artifact.
- **`agentgate init --template <name>`** wired in `cli_init.py` to write a
  ready-to-use policy file from any of the 5 templates.

### Fixed
- **`cli/__init__.py` `add_command` loop**: now defensive against plain helper
  functions slipping into the command tuple — pre-existing test-collection
  errors unblocked.
- **`agentgate lint`** accepts `-p` flag as alternative to positional arg.

### Tests
- 249 tests passing (was 228, +21).
- ruff clean, mypy clean.

## [0.13.0] - 2026-08-15

### Added
- **`agentgate scan` — static config security scanner** (`scanner.py`). 35+ rules across
  secrets / permissions / hooks / MCP-servers. Inspired by affaan-m/agentshield.
  - Detects `sk-ant-...`, `ghp_...`, `AKIA...`, private keys, JWTs, DB connection strings.
  - Detects `Bash(*)` / `Write(*)` / `--dangerously-skip-permissions`, `rm -rf /`.
  - Detects command injection (`$file` in hooks), reverse shells, log tampering.
  - Reports A–F grade + JSON output; exits 2 on critical so CI can gate.
- **DLP egress scanner** (`dlp.py`). 50+ provider API key patterns (Anthropic, OpenAI,
  OpenRouter, GitHub, AWS, GCP, Azure, Stripe, GitLab, Slack, Discord, Pinecone,
  Hugging Face, Mistral, etc.) + DB connection strings + JWTs + crypto wallets.
  Evidence redacted (`sk-an***12`). Host exemption for the provider itself so
  legitimate calls aren't tripped.
- **Prompt-injection scanner** in the same DLP engine. 28+ markers:
  `ignore previous instructions`, system/role override, DAN, tool invocation
  injection, hidden HTML instructions, Pliny divider, system prompt extraction.
- **Shannon entropy detection** (`dlp.shannon_entropy` /
  `looks_like_high_entropy_blob`). Threshold 4.5 bits/char catches base64
  secrets that don't match a known provider prefix.
- **Ed25519-signed audit receipts** (`receipts.py`). Optional per-event signing:
  `ReceiptKeyPair` auto-generates keys into `~/.agentgate/receipts/` (0600).
  `receipt_envelope()` signs `(prev_signature, chain_hash, action, event)`.
  `agentgate receipts verify <audit.db>` walks the chain and verifies every
  signature with the public key.
- **`agentgate doctor`** — pre-flight health check. 7 readiness probes:
  Claude Code on PATH, Node.js, Docker, GnuPG, AGENTGATE_POLICY, ~/.agentgate
  writable, ~/.claude present.
- **README rewrite** + **9 GitHub topics** (`ai-agents`, `security`, `firewall`,
  `llm-security`, `claude-code`, `mcp`, `prompt-injection`, `ai-security`,
  `agentic-ai`) for discoverability.
- **`cryptography>=45.0.0`** new dependency.

### Changed
- **Proxy addon** (`proxy_addon.py`) now runs DLP + prompt-injection + entropy
  scans on every request body, URL, and headers. Any CRITICAL finding auto-denies
  the request before forwarding. Audit record includes `dlp_findings`.
- **Audit chain** (`audit.py`) gains a `receipt_signature` column + an `_migrate()`
  that backfills the column on existing dbs so upgrades don't lose history.

### Tests
- 228 tests passing (up from 206). New file `tests/test_v013_features.py` (22 tests).
- ruff clean, mypy clean.

### Inspiration
- `agentshield` (static config scanner)
- `pipelock` (DLP + entropy + signed receipts)

### Added
- **`Codex CLI hook`** — `agentgate install-codex-hook` wires AgentGate into OpenAI's Codex CLI as a BeforeTool hook. Tool mapping (shell→Bash, apply_patch→Edit) keeps policies portable across agents.
- **CEL-lite `when` conditions** — rules can now carry a small expression that gates matching on event fields:
  ```yaml
  rules:
    - id: deny-rm-elsewhere
      match: {tool: Bash, command_regex: 'rm -rf.*'}
      action: deny
      when: 'event.cwd != "/srv"'
  ```
  Supports `== != in not-in > < >= <=`, `and or not`, parens, literals (`"str"`, numbers, `true/false`, `[...]`).
- **Per-rule token-bucket rate limiter** — `rate_limit: {capacity: 5, refill_per_sec: 0.1}` lets you throttle noisy rules without bricking the agent. When the bucket is empty, the rule falls through to the next match. DENY rules bypass the limiter (always fire).
- **Multi-environment policy manager** — `agentgate env add|list|show|use|remove|active` for dev/staging/prod switching. Writes `~/.agentgate/environments.yaml` and sources `~/.agentgate/active.env`.
- **`agentgate coverage`** — reports dead rules and uncovered tools by replaying your audit log (or a JSONL fixture file) through the current policy. `--fail-under 80` for CI gating.
- **Discord notify** — `AGENTGATE_DISCORD_WEBHOOK` triggers Discord incoming-webhook notifications; channel precedence is now Telegram > Discord > Slack > file.

### Changed
- `notify.py`: f-string backslash workarounds for Python 3.12+ (em-dash now constant).
- `policy.py`: imports cleaned up; CEL evaluator extracted as `evaluate_cel()` / `evaluate_when()`.

## [0.11.0] - 2026-08-15

### Added
- **`dry-run` mode** — `AGENTGATE_MODE=dry-run` records the verdict but never blocks, so you can preview a policy change before flipping the switch
- **`PolicyWatcher`** — mtime-based hot reload for long-lived processes (proxy + dashboard pick up edits to `policy.yaml` without a restart)
- **Prometheus `/metrics` endpoint** — `agentgate_events_total{action}`, `agentgate_db_size_bytes`, `agentgate_uptime_seconds`, `agentgate_info` for Grafana / scrape pipelines
- **Gemini CLI hook** — `agentgate install-gemini-hook` writes `.gemini/settings.json` and translates `BeforeTool` payloads to the AgentGate event schema
- **Webhook HMAC-SHA256 signing** — `Webhook.secret` field; receivers verify with `verify_signature(secret, body, header)`
- **Webhook exponential backoff** — 5 attempts at 1, 2, 4, 8, 16s (configurable via `max_attempts` / `base_backoff`)
- **`docs/quickstart.md`, `tutorial.md`, `cli-reference.md`, `security.md`** — full documentation set, mkdocs-ready
- **CI quality workflow** — `.github/workflows/quality.yml` adds ruff + mypy + coverage ≥70% on every PR

### Changed
- `webhook.deliver()` now signs and retries by default; backoff is `time.sleep(base * 2^(attempt-1))`
- `ProxyAddon` logs reload count on session done

## [0.10.0] - 2026-08-14

### Added
- `agentgate init` — interactive wizard generating a starter policy.yaml (3 presets: readonly/balanced/strict)
- MCP stdio server (`agentgate mcp`) — JSON-RPC 2.0 with `policy_lookup`, `audit_recent`, `audit_count`, `policy_test_tool`
- Ask queue dashboard (`/asks` + `/api/asks/pending` + `/api/asks/resolve`) — UI to approve/deny pending ASK events
- Webhook subscriptions (`agentgate webhook add/list/remove/test`) — fire external URLs on filtered audit events with retry/backoff
- `agentgate policy diff <a.yaml> <b.yaml>` — compare two policies: rule-level diff + decision-change detection across canary events
- Fail-closed on missing critical event fields (`Bash.command`, `Read.file`, `WebFetch.url`) — ASK synthetic rule with explicit reason

### Fixed
- Rule.matches() now dispatches `*_regex` keys to `re.search` and `*_glob` keys to `fnmatch.fnmatch` (previously used fnmatch for all keys, causing `command_regex` rules to silently never match)
- `load_policy()` now reads `default_action` from YAML (was reading nonexistent `default` key, silently always defaulting to allow)
- Dashboard SSE handler rewritten to drop timing-fragile `time.sleep(0.5)` schema-check loop and unskip the SSE integration test

### Tests
171/171 passing (+58 since v0.9.0): +init (9), +rule_matches regression (5), +mcp_server (10), +ask_queue (8), +webhooks (11), +policy_diff (8), +missing-fields (7)

## [0.9.0] - 2026-08-14

### Added
- **`agentgate policy test`** + **`policy explain`** — dry-run events against a policy without side effects. Returns decision + matched rule + raw vs effective action + all candidates considered. Useful for debugging why a rule denied something.
- **Enforcement modes** (`enforce` / `observe` / `ci`) — `AGENTGATE_MODE` env var selects. CI mode auto-promotes `ASK` to `DENY` for non-interactive runs. Observe mode records decisions but never blocks.
- **Unknown-tool fail-closed** — `unknown_tool_action` + `known_tools` in policy schema. Surfaces MCP tools that aren'''t referenced in any rule.
- **Approval provenance** — `event_provenance()` SHA-256 hashes the event at ASK time; replay detects payload tampering with `PROVENANCE MISMATCH`.
- **Hash-chain audit** — every event row stores `chain_hash = SHA256(prev_hash + own)`. `agentgate audit verify` walks the chain offline and returns exit 1 if any row was tampered.
- `agentgate audit` is now a group with `show` + `verify` subcommands.
- 22 new tests (91 → 113 total).

### Internal
- `Policy.evaluate_explain()` returns both `raw_action` and `effective_action` so dashboards can show what the policy said vs what the mode allowed.
- `Policy.is_known_tool(name)` checks all rules for tool references.

## [0.8.0] - 2026-08-14

### Added
- **Helm chart** at `deploy/helm/agentgate/` — full k8s deployment with Deployment, Service, PVC, Secret, ConfigMap, Ingress, HPA, ServiceAccount. Production-ready with securityContext (non-root, read-only rootfs, drop ALL caps), resource limits, health probes.
- **Dashboard time-series chart** — new `GET /api/stats/timeseries?hours=N` endpoint + chart.js stacked bar chart with 1h/6h/24h/3d/7d range selector. Replaces inline SVG.
- **`agentgate alerts`** — alert engine that evaluates YAML rules against the audit DB with time windows + thresholds + custom message templates (`{{count}}`, `{{window}}`).
- **`agentgate detect-agents`** — auto-detects which AI coding agents are installed on the host (Claude Code, Cursor, Continue.dev, Aider, GitHub CLI).
- **`Audit.counts_per_bucket()`** and **`Audit.since_within()`** — new aggregation primitives for dashboards and alerts.

### Fixed
- `counts_per_bucket` SQL was using `(ts / N) * N` which returned float in SQLite, splitting buckets per microsecond. Now uses `CAST(... AS INTEGER)`.
- `since_within` returned dict with column indices off-by-one (assumed old schema). Now correctly maps to actual schema (id, ts, source, agent, action, rule_id, rule_name, event_json, reason).

### Tests
- Added `tests/test_alerts.py` (4 tests covering bucket math + action filter + CLI).
- Added `tests/test_dashboard.py` (3 tests covering HTML, timeseries API, events filter).

## [0.7.0] - 2026-08-14

### Added
- `py.typed` marker — package ships type hints for downstream type checkers
- `docs/coverage.svg` badge (63% unit-test coverage)
- `.github/workflows/test-matrix.yml` — CI matrix runs unit tests on ubuntu + macOS + Windows
- `.github/workflows/publish.yml` — push `v*.*.*` tag auto-builds, publishes to PyPI via OIDC trusted publishing, and drafts a GitHub release
- `agentgate docs` — print README + architecture + policy-reference + CONTRIBUTING paths with one-liner usage
- `Dockerfile` — minimal `python:3.12-slim` based image, runs as non-root user `agent`
- `.pre-commit-config.yaml` + `ruff.toml` — ruff lint + format + isort + shellcheck + `agentgate lint --strict` hooks
- README badges: release workflow + coverage

### Changed
- Cleaned 166 ruff errors down to 0 (`F401` unused imports removed, `I001` import order normalized, `SIM112` uppercase env vars)
- `proxy_addon.py` now reads only `AGENTGATE_POLICY` / `AGENTGATE_DB` (lowercase fallback removed)
- `dns_sinkhole.py` `main()` lazily imports `load_policy` from `.policy` to avoid an unused import at module top

### Internal
- Bumped 24 dependency lockfiles
- `policy.py` imports `StrEnum` only (dropped unused `Enum`)

## [0.6.1] - 2026-08-14

### Changed
- **PyPI description rewritten** — now names the agents it supports (Claude Code, Cursor, Continue.dev, Aider, GitHub Actions) and what it intercepts (Bash/Read/Write/Edit, outbound HTTP, human approvals)
- **20 PyPI classifiers** (up from 12) — added `Microsoft Windows`, `Python 3 :: Only`, `Topic :: System :: Networking :: Firewalls`, `Topic :: System :: Monitoring`, `Topic :: Utilities`, `Intended Audience :: Information Technology`, `Intended Audience :: Financial and Insurance Industry`
- 14 GitHub repo topics (merged duplicates on first review)

## [0.6.0] - 2026-08-14

### Added
- `agentgate doctor` — print Python version, deps, optional tools, notification channel config, port availability, policy validation. First command a new user should run.
- `agentgate lint policy.yaml` — catches duplicate rule IDs, deny rules without a reason, empty match blocks, dead `_glob` / `_regex` keys. `--strict` turns warnings into errors.
- `agentgate stats --by-source / --by-rule` — break down the audit log by source (claude-code, proxy, manual) or rule name
- `GET /api/events?action=...&source=...&since=...&limit=...` — dashboard JSON API accepts filters
- `docs/architecture.md` — Mermaid-rendered component map + sequence diagrams for deny / ask round-trip flows
- `docs/dashboard.svg` — inline-rendered dashboard preview in README (works without JavaScript)
- `Makefile` with 14 targets: install / test / verify / lint / format / build / publish / release / clean / doctor / run-dashboard / run-proxy / run-approval
- `.devcontainer/devcontainer.json` — one-click dev environment (Codespaces / VS Code Remote)
- **Windows path support** — `notify_ask` file fallback and approval DB now use `tempfile.gettempdir()` instead of hard-coded `/tmp/`
- CONTRIBUTING.md with full release flow (bump, build, publish to PyPI, verify install, tag, GitHub release)

### Tests
- 90 unit tests (+7 for doctor + lint)
- All 90 pass; 10/10 e2e verify steps green; CI green on Py 3.12 + 3.13

## [0.5.0] - 2026-08-14

### Added
- **DNS sinkhole** (`agentgate dns policy.yaml`) — alternative to mitmproxy for intercepting outbound DNS at the network layer. Writes `/etc/resolver/agentgate` on macOS or a `systemd-resolved` drop-in on Linux
- **SSE live dashboard** — `/_events.js` + `EventSource("/api/events/stream")` + browser notification on deny / ask
- **Hosted team mode** — `agentgate pull-policy URL` downloads shared policy, `agentgate push-events URL --token TOKEN` streams audit events to a central backend. Bearer-token auth. Cursor sync via `Audit.since()`
- `tests/test_dashboard_sse.py` — 5 SSE tests (stream headers, initial events, live events, reconnect resume, heartbeat)

### Fixed
- SSE `SELECT` used `event` column but schema has `event_json` — patched query to `event_json`
- SSE handler connecting before `Audit.__init__` creates table → `no such table: events` swallowed by bare `except` — now caught specifically and re-tried
- Test assertion `payload["action"]` was lowercase `"deny"`, not `Action.DENY` enum — broadened to accept any of `{deny, Action.DENY, DENY}`

## [0.4.0] - 2026-08-13

### Added
- Continue.dev adapter (`.continue/hooks/agentgate.py`)
- GitHub Actions adapter (`/annotate` workflow commands for PR check-runs)
- Telegram notification channel (`AGENTGATE_TELEGRAM_BOT_TOKEN`, `AGENTGATE_TELEGRAM_CHAT_ID`)
- `actions_annotate.py` — converts audit deny / ask events into `::error file=line,col::msg` workflow commands

### Fixed
- Hook script path normalization on Windows

## [0.3.0] - 2026-08-12

### Added
- Aider adapter (`~/.aider.conf.yml` integration)
- Cursor adapter (`~/.cursor/hooks.json` integration)
- `agentgate install-cursor-hook` + `agentgate install-continue-hook`
- `agentgate replay <policy> <db>` — replay an audit log through a new policy to see what would have changed

## [0.2.0] - 2026-08-11

### Added
- mitmproxy addon (`agentgate proxy --policy foo.yaml`) — intercepts HTTP/HTTPS requests against a domain allow/deny list
- DNS-layer interception (`agentgate dns`) — experimental
- WebSocket approval flow (`agentgate approval-server` listens on :8765 by default)
- 10-step `scripts/verify.sh` end-to-end check

## [0.1.0] - 2026-08-10

### Added
- Initial release.
- `agentgate install-hook` — registers a PreToolUse hook with Claude Code that intercepts Bash / Read / Write / Edit / WebFetch / Grep / Glob
- YAML policy format with `rules[]`, `match.tool`, `match.command_glob`, `match.command_regex`, `match.path_glob`, `action: allow | deny | ask`, `default: deny | allow`, `network: bool`
- `agentgate init` — scaffold a new policy file
- `agentgate eval --policy foo.yaml --event-json '{...}'` — evaluate a single event against a policy
- `agentgate audit --db audit.db` — query the audit log
- `agentgate stats --db audit.db` — aggregate audit counts
- `agentgate dashboard --db audit.db` — single-page HTML viewer
- Slack incoming webhook notification channel
- File fallback notification (writes to `agentgate-asks.jsonl` for testing)
- Apache-2.0 license

[Unreleased]: https://github.com/FelixMa01/agentgate/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/FelixMa01/agentgate/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/FelixMa01/agentgate/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/FelixMa01/agentgate/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/FelixMa01/agentgate/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/FelixMa01/agentgate/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/FelixMa01/agentgate/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/FelixMa01/agentgate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/FelixMa01/agentgate/releases/tag/v0.1.0