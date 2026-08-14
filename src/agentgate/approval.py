"""Approval store — pending asks + their resolutions, backed by SQLite.

Two layers:
  - In-process: an in-memory dict for the asker thread to wait on a Condition.
  - On-disk: SQLite table so the HTTP server (separate process) can write the
    resolution and the asker thread can wake up by polling.

The HTTP server runs `resolve(token, decision)`, which both:
  1. Inserts into the SQLite `approvals` table.
  2. Wakes any in-process waiters on the same machine (different process,
     so the local notify is best-effort — the asker thread also polls).

The asker thread calls `wait(token, timeout)` which:
  1. Blocks on a Condition (fast path).
  2. On timeout, re-checks the SQLite table (cross-process path).
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    token TEXT PRIMARY KEY,
    created REAL NOT NULL,
    event_json TEXT NOT NULL,
    tool TEXT,
    rule_id TEXT,
    decision TEXT,
    resolved_at REAL
);
CREATE INDEX IF NOT EXISTS idx_approvals_resolved ON approvals(resolved_at);
"""


def _db_path() -> Path:
    """Where to keep the shared approvals DB.

    Honors AGENTGATE_DB env var (same DB the audit lives in), with a sidecar
    `approvals` table. Falls back to the per-user temp dir.
    """
    db = os.environ.get("AGENTGATE_DB")
    if db:
        return Path(db)
    import tempfile

    return Path(tempfile.gettempdir()) / "agentgate-approvals.db"


@dataclass
class PendingAsk:
    token: str
    created: float
    event: dict
    decision: str | None = None
    resolved_at: float | None = None
    cv: threading.Condition = field(default_factory=threading.Condition)


class ApprovalStore:
    def __init__(self, db_path: Path | str | None = None):
        self.db_path = Path(db_path) if db_path else _db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._pending: dict[str, PendingAsk] = {}
        # Initialise the table (idempotent).
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(SCHEMA)

    def request(self, event: dict, tool: str, rule: str | None = None) -> PendingAsk:
        import secrets

        token = secrets.token_urlsafe(8)
        now = time.time()
        ask = PendingAsk(
            token=token, created=now, event={"event": event, "tool": tool, "rule": rule}
        )
        with self._lock:
            self._pending[token] = ask
        # Persist so the HTTP server (or any other process) can see this ask.
        with sqlite3.connect(self.db_path) as conn:
            import json as _json

            conn.execute(
                """INSERT OR REPLACE INTO approvals
                   (token, created, event_json, tool, rule_id)
                   VALUES (?, ?, ?, ?, ?)""",
                (token, now, _json.dumps({"event": event, "tool": tool, "rule": rule}), tool, rule),
            )
        return ask

    def resolve(self, token: str, decision: str) -> bool:
        """Cross-process resolution. Returns True if the ask existed."""
        now = time.time()
        updated = 0
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                """UPDATE approvals
                   SET decision = ?, resolved_at = ?
                   WHERE token = ? AND decision IS NULL""",
                (decision, now, token),
            )
            updated = cur.rowcount
            conn.commit()
        # Also wake any in-process waiters (same process).
        with self._lock:
            ask = self._pending.get(token)
        if ask:
            with ask.cv:
                ask.decision = decision
                ask.resolved_at = now
                ask.cv.notify_all()
        return updated > 0 or ask is not None

    def get(self, token: str) -> PendingAsk | None:
        with self._lock:
            local = self._pending.get(token)
        if local:
            return local
        # Fall back to SQLite (ask created by another process).
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT token, created, event_json, tool, rule_id, decision, resolved_at "
                "FROM approvals WHERE token = ?",
                (token,),
            ).fetchone()
        if not row:
            return None
        import json as _json

        return PendingAsk(
            token=row["token"],
            created=row["created"],
            event=_json.loads(row["event_json"]),
            decision=row["decision"],
            resolved_at=row["resolved_at"],
        )

    def wait(self, token: str, timeout: float) -> str | None:
        """Block until resolved (in-process or cross-process via SQLite poll)."""
        with self._lock:
            ask = self._pending.get(token)
        if not ask:
            # Poll the DB
            return self._poll_until_resolved(token, timeout)
        with ask.cv:
            # Re-check DB first — resolution may have happened before we got here.
            db_decision = self._db_decision(token)
            if db_decision:
                ask.decision = db_decision
                return db_decision
            ask.cv.wait(timeout=timeout)
            # After waking (or timeout), re-read in case the resolution came
            # from another process.
            db_decision = self._db_decision(token)
            if db_decision:
                ask.decision = db_decision
            return ask.decision

    def _db_decision(self, token: str) -> str | None:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT decision FROM approvals WHERE token = ?", (token,)
            ).fetchone()
        return row[0] if row and row[0] else None

    def _poll_until_resolved(self, token: str, timeout: float) -> str | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            d = self._db_decision(token)
            if d:
                return d
            time.sleep(0.2)
        return self._db_decision(token)

    def cleanup(self, max_age: float = 600) -> int:
        cutoff = time.time() - max_age
        n_db = 0
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "DELETE FROM approvals WHERE resolved_at IS NOT NULL AND resolved_at < ?",
                (cutoff,),
            )
            n_db = cur.rowcount
        with self._lock:
            stale = []
            for t, a in list(self._pending.items()):
                resolved_at = a.resolved_at
                if resolved_at is None:
                    # Look up the DB's authoritative resolution time.
                    with sqlite3.connect(self.db_path) as conn:
                        row = conn.execute(
                            "SELECT resolved_at FROM approvals WHERE token = ?",
                            (t,),
                        ).fetchone()
                    if row and row[0] and row[0] < cutoff:
                        resolved_at = row[0]
                if resolved_at is not None and resolved_at < cutoff:
                    stale.append(t)
            for t in stale:
                self._pending.pop(t, None)
        return n_db + len(stale)


# Process-global store — both the hook (caller) and HTTP server (resolver)
# import this same singleton.
def _build_store() -> ApprovalStore:
    return ApprovalStore(_db_path())


STORE = _build_store()
