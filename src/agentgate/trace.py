"""Record a session of policy events and replay them against a new policy.

Two halves:

- :class:`TraceRecorder` — append each ``Policy.evaluate`` event to a
  ``.agentgate/trace.jsonl`` file (one JSON object per line).
- :func:`replay` — load a trace file, evaluate each event against a new
  policy, and report any divergences from the recorded decision.

Use case: a CI step replays the previous day's trace against a freshly
edited policy to confirm the change didn't accidentally let a destructive
command through.

Usage::

    # record
    rec = TraceRecorder()
    pol.evaluate(event, _trace=rec.append)
    rec.save("/tmp/today.jsonl")

    # replay
    divs = replay("/tmp/today.jsonl", new_policy)
    print(divs)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class TraceEntry:
    ts: float
    tool: str
    event: dict[str, Any]
    decision: str          # allow/deny/ask/log
    rule_id: str | None
    rule_name: str | None
    reason: str | None


class TraceRecorder:
    """Append-only recorder. Threadsafe via the global lock of the caller."""

    def __init__(self, sink: list[TraceEntry] | None = None):
        self._entries: list[TraceEntry] = sink if sink is not None else []

    def append(self, *, ts: float, tool: str, event: dict,
               decision: str, rule_id: str | None,
               rule_name: str | None, reason: str | None) -> None:
        self._entries.append(TraceEntry(
            ts=ts, tool=tool, event=event,
            decision=decision, rule_id=rule_id,
            rule_name=rule_name, reason=reason,
        ))

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w") as f:
            for e in self._entries:
                f.write(json.dumps({
                    "ts": e.ts,
                    "tool": e.tool,
                    "event": e.event,
                    "decision": e.decision,
                    "rule_id": e.rule_id,
                    "rule_name": e.rule_name,
                    "reason": e.reason,
                }) + "\n")

    def __len__(self) -> int:
        return len(self._entries)


@dataclass
class Divergence:
    line: int
    event: dict[str, Any]
    recorded: str
    replayed: str
    note: str


def replay(path: str | Path, policy) -> list[Divergence]:
    """Replay a trace file against a policy. Return the divergences."""
    p = Path(path)
    divs: list[Divergence] = []
    with p.open() as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            event = entry.get("event") or {}
            recorded = entry.get("decision")
            try:
                # Policy.evaluate returns either (action, rule) or
                # (action, rule_id, rule_name, reason) depending on version.
                result = policy.evaluate(event)
                replayed_action = result[0]
                if len(result) >= 4:
                    replayed_rule_id = result[1].id if hasattr(result[1], "id") else result[1]
                    replayed_reason = result[3]
                else:
                    rule = result[1] if len(result) > 1 else None
                    replayed_rule_id = rule.id if rule else None
                    replayed_reason = None
                replayed = str(replayed_action.value)
            except Exception as exc:
                divs.append(Divergence(
                    line=i, event=event, recorded=recorded or "?",
                    replayed="ERROR", note=f"evaluation failed: {exc}",
                ))
                continue
            if replayed != recorded:
                divs.append(Divergence(
                    line=i, event=event, recorded=recorded or "?",
                    replayed=replayed,
                    note=f"recorded rule={entry.get('rule_id')}, "
                         f"new rule={replayed_rule_id}; "
                         f"reason: {entry.get('reason')} -> {replayed_reason}",
                ))
    return divs


def format_divergences(divs: list[Divergence]) -> str:
    if not divs:
        return "✓ 0 divergences — replay matches recorded behavior."
    out = [f"✗ {len(divs)} divergences:"]
    for d in divs:
        out.append(f"  line {d.line}: recorded={d.recorded} -> replayed={d.replayed}")
        out.append(f"    event: {json.dumps(d.event, default=str)[:120]}")
        out.append(f"    {d.note}")
    return "\n".join(out)
