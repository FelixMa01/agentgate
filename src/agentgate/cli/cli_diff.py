"""`agentgate policy diff` — compare two policies.

Walks a representative set of "canary events" through both policies and
reports any decision changes. Also shows rule-level diff (added, removed,
changed action/reason/match).

Usage:
  agentgate policy diff old.yaml new.yaml [--canary-tool Bash]...
  agentgate policy diff old.yaml new.yaml --json
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from ..policy import Action, Policy, load_policy

CANARY_EVENTS: list[dict[str, Any]] = [
    {"tool": "Bash", "command": "ls -la"},
    {"tool": "Bash", "command": "rm -rf /tmp/foo"},
    {"tool": "Bash", "command": "curl http://example.com"},
    {"tool": "Write", "file": "src/main.py", "content": "x"},
    {"tool": "Edit", "file": "README.md", "content": "y"},
    {"tool": "Read", "file": "config.yaml"},
    {"tool": "WebFetch", "url": "https://example.com"},
    {"tool": "Glob", "pattern": "*.py"},
    {"tool": "Grep", "pattern": "TODO"},
    {"tool": "NotebookEdit", "file": "nb.ipynb"},
    {"tool": "SomeUnknownTool", "arg": "x"},
]


def _decision_change(a: tuple[Action, object], b: tuple[Action, object]) -> dict[str, Any]:
    act_a, rule_a = a
    act_b, rule_b = b
    if act_a == act_b and (rule_a.id if rule_a else None) == (rule_b.id if rule_b else None):
        return {}
    return {
        "old_action": str(act_a),
        "new_action": str(act_b),
        "old_rule": rule_a.id if rule_a else None,
        "new_rule": rule_b.id if rule_b else None,
    }


def diff_policies(a: Policy, b: Policy, canary_events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Run canary events through both policies, summarize changes + rule-level diff."""
    events = canary_events if canary_events is not None else CANARY_EVENTS
    decision_changes: list[dict[str, Any]] = []
    for ev in events:
        a_dec = a.evaluate(ev)
        b_dec = b.evaluate(ev)
        chg = _decision_change(a_dec, b_dec)
        if chg:
            decision_changes.append({"event": ev, **chg})
    # Rule-level diff
    a_rules = {r.id: r for r in a.rules}
    b_rules = {r.id: r for r in b.rules}
    added = sorted(b_rules.keys() - a_rules.keys())
    removed = sorted(a_rules.keys() - b_rules.keys())
    changed: list[dict[str, Any]] = []
    for rid in a_rules.keys() & b_rules.keys():
        ar, br = a_rules[rid], b_rules[rid]
        if ar.action != br.action:
            changed.append({"id": rid, "field": "action", "old": str(ar.action), "new": str(br.action)})
        if ar.match != br.match:
            changed.append({"id": rid, "field": "match", "old": dict(ar.match), "new": dict(br.match)})
        if ar.reason != br.reason:
            changed.append({"id": rid, "field": "reason", "old": ar.reason, "new": br.reason})
    return {
        "decision_changes": decision_changes,
        "rules_added": added,
        "rules_removed": removed,
        "rules_changed": changed,
    }


def _format_text(diff: dict[str, Any]) -> str:
    lines: list[str] = []
    n = len(diff["decision_changes"])
    lines.append(f"Decision changes: {n}")
    for c in diff["decision_changes"]:
        ev = c["event"]
        ev_summary = ", ".join(f"{k}={v!r}" for k, v in ev.items())
        lines.append(
            f"  - {ev_summary}"
            f"\n      {c['old_action']} ({c['old_rule'] or '<default>'})"
            f" -> {c['new_action']} ({c['new_rule'] or '<default>'})"
        )
    if diff["rules_added"]:
        lines.append(f"\nRules added ({len(diff['rules_added'])}):")
        for rid in diff["rules_added"]:
            lines.append(f"  + {rid}")
    if diff["rules_removed"]:
        lines.append(f"\nRules removed ({len(diff['rules_removed'])}):")
        for rid in diff["rules_removed"]:
            lines.append(f"  - {rid}")
    if diff["rules_changed"]:
        lines.append(f"\nRules changed ({len(diff['rules_changed'])}):")
        for c in diff["rules_changed"]:
            lines.append(f"  ~ {c['id']}.{c['field']}: {c['old']!r} -> {c['new']!r}")
    if n == 0 and not diff["rules_added"] and not diff["rules_removed"] and not diff["rules_changed"]:
        lines.append("\nNo changes.")
    return "\n".join(lines)


@click.command("diff")
@click.argument("policy_a", type=click.Path(exists=True))
@click.argument("policy_b", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def diff_cmd(policy_a: str, policy_b: str, as_json: bool) -> None:
    """Compare two policies."""
    a = load_policy(Path(policy_a))
    b = load_policy(Path(policy_b))
    diff = diff_policies(a, b)
    if as_json:
        click.echo(json.dumps(diff, indent=2))
        return
    click.echo(_format_text(diff))
