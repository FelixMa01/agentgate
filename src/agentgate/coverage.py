"""Policy coverage analyzer.

Reads a policy.yaml and an audit.db (or fixture JSONL) of historical
events, then reports:

- Which rules fired (matched) and how often
- Which rules are dead (defined but never matched)
- Which tools/commands appeared in events but aren't covered by any rule

Output formats: human-readable table (default) or JSON for CI gating.

Usage:
    agentgate coverage --policy ./policy.yaml --db ./audit.db
    agentgate coverage --policy ./policy.yaml --fixtures ./events.jsonl --json
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .policy import load_policy


@dataclass
class CoverageReport:
    rules_total: int
    rules_matched: int
    rules_dead: list[str] = field(default_factory=list)
    tools_uncovered: list[tuple[str, int]] = field(default_factory=list)
    rule_hit_counts: dict[str, int] = field(default_factory=dict)

    @property
    def coverage_pct(self) -> float:
        if self.rules_total == 0:
            return 100.0
        return round(100.0 * self.rules_matched / self.rules_total, 1)


def _events_from_db(db_path: str | Path) -> list[dict]:
    """Read events from the audit SQLite DB. Returns list of event dicts
    reconstructed from the stored event_json column."""
    p = Path(db_path)
    if not p.exists():
        return []
    conn = sqlite3.connect(p)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT event_json, rule_id, action FROM events ORDER BY id"
    ).fetchall()
    out = []
    for r in rows:
        try:
            ev = json.loads(r["event_json"])
        except (json.JSONDecodeError, TypeError):
            continue
        ev["_rule_id"] = r["rule_id"]
        ev["_action"] = r["action"]
        out.append(ev)
    conn.close()
    return out


def _events_from_jsonl(path: str | Path) -> list[dict]:
    """Read events from a JSONL fixture file (one event per line)."""
    out = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def analyze(
    policy_path: str | Path,
    events: list[dict] | None = None,
    db_path: str | Path | None = None,
    fixtures: str | Path | None = None,
) -> CoverageReport:
    """Run coverage analysis. Pass `events` for in-memory use; otherwise
    point at a `--db` or `--fixtures` path."""
    policy = load_policy(policy_path)
    if events is None:
        if db_path is not None:
            events = _events_from_db(db_path)
        elif fixtures is not None:
            events = _events_from_jsonl(fixtures)
    hit_counter: Counter[str] = Counter()
    tool_counter: Counter[str] = Counter()
    matched_rule_ids: set[str] = set()
    for ev in events or []:
        tool = ev.get("tool", "<unknown>")
        tool_counter[tool] += 1
        # Re-evaluate against the current policy (matches() may differ
        # from the historical rule_id if the policy has changed).
        for rule in policy.rules:
            if rule.matches(ev):
                hit_counter[rule.id] += 1
                matched_rule_ids.add(rule.id)
                break
    dead = [r.id for r in policy.rules if r.id not in matched_rule_ids]
    known_tools = {r.match.get("tool") for r in policy.rules if "tool" in r.match}
    known_tools.discard(None)
    uncovered = [
        (t, n) for t, n in tool_counter.most_common()
        if t not in known_tools and t != "<unknown>"
    ]
    return CoverageReport(
        rules_total=len(policy.rules),
        rules_matched=len(matched_rule_ids),
        rules_dead=dead,
        tools_uncovered=uncovered,
        rule_hit_counts=dict(hit_counter),
    )


def format_report(report: CoverageReport) -> str:
    """Render a human-readable table."""
    lines = [
        f"Coverage: {report.coverage_pct}%  "
        f"({report.rules_matched}/{report.rules_total} rules matched)",
        "",
        "Rule hits:",
    ]
    if not report.rule_hit_counts:
        lines.append("  (no events)")
    else:
        for rid, n in sorted(report.rule_hit_counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {n:>5}  {rid}")
    if report.rules_dead:
        lines += ["", "Dead rules (defined but never matched):"]
        for rid in report.rules_dead:
            lines.append(f"  - {rid}")
    if report.tools_uncovered:
        lines += ["", "Tools in events but not covered by any rule:"]
        for tool, n in report.tools_uncovered:
            lines.append(f"  {n:>5}  {tool}")
    return "\n".join(lines) + "\n"
