# Changelog

All notable changes to AgentGate are documented here. Dates are ISO 8601.

## [0.3.0] — 2026-08-14

### Added
- **CLI split**: `cli.py` (463 lines) split into 13 sub-modules under `src/agentgate/cli/` for easier navigation and contribution.
- **Three new policy examples**: `examples/policy-secure.yaml` (deny by default), `examples/policy-permissive.yaml` (solo dev), `examples/policy-team.yaml` (shared repo + audit).
- **`metadata` block in policies**: optional YAML keys (`author`, `name`, `version`, `last_reviewed`, `description`) for compliance audits. `agentgate validate` renders them and warns if missing.
- **`docs/policy-reference.md`**: complete reference for the YAML format, match keys, glob/regex patterns, network policy, and examples.
- **`agentgate stats --json`**: machine-readable output for monitoring / Slack bot integration.
- **`agentgate eval --dry-run`**: evaluate without writing to the audit DB (useful when iterating on a policy).
- **`agentgate replay --audit-id N`**: re-evaluate a stored audit event against a (possibly new) policy. Highlights when the decision would have changed — useful for policy migrations.
- **`Audit.get(id)`**: new method on the Audit class for the replay command.
- **Better error messages**:
  - Port collision in `proxy`, `approval-server`, `dashboard` now suggests an alternative free port (`--port 8081` etc.).
  - YAML parse errors now point to the offending line/column.
- **End-to-end smoke test in CI**: `scripts/verify.sh` is now part of GitHub Actions (in addition to pytest).
- **CONTRIBUTING.md**: developer guide including a "50 lines to add a new agent adapter" recipe.

### Changed
- `Policy` dataclass gains `metadata` field and three convenience properties: `allowed_domains`, `denied_domains`, `require_https`.
- All CLI subcommand modules use the delayed `main.add_command(cmd)` registration pattern to avoid circular imports.

## [0.2.0] — 2026-08-14

### Added
- **Cursor hook adapter** (`agentgate.cursor_hook`, `agentgate install-cursor-hook`) — supports Cursor's `beforeShellExecution`, `beforeFileEdit`, `beforeFileRead` events.
- **`evaluate_event()`** shared between Claude Code and Cursor hooks.
- 5 new tests for the Cursor adapter (53 total).

## [0.1.1] — 2026-08-14

### Fixed
- README install URL pointed at the placeholder `you/agentgate` instead of the real repo.

## [0.1.0] — 2026-08-14

Initial public release. 48 unit tests, GitHub Actions on Py 3.12 + 3.13.

### Day-by-day summary

- **Day 1** — Project skeleton + Policy DSL + SQLite audit + CLI (`init`, `eval`, `audit`, `stats`, `validate`)
- **Day 2** — Claude Code `PreToolUse` hook + real interception + `install-hook` / `uninstall-hook`
- **Day 3** — Network egress proxy (mitmproxy add-on) + DNS/domain filtering
- **Day 4** — Slack approval webhook + cross-process HTTP server + SQLite-backed approval store
- **Day 5** — Dashboard HTTP server + single-page HTML viewer + README

## Comparison: project at start vs. end

| | Start (Day 0) | End (v0.3.0) |
|---|---|---|
| LOC | 0 | ~1300 |
| Tests | 0 | 53 |
| Adaptors | 0 | 2 (Claude Code, Cursor) |
| Commands | 0 | 13 |
| Release | — | v0.3.0 on PyPI |
| CI | — | pytest + e2e on Py 3.12 + 3.13 |