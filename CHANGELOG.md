# Changelog

All notable changes to AgentGate are documented here. Dates are UTC.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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