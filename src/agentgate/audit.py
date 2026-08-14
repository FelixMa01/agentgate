"""SQLite-backed audit trail of every evaluated event."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from .policy import Action

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    source TEXT NOT NULL,        -- 'claude-code' | 'network' | 'file' | 'manual'
    agent TEXT,                   -- agent identifier if known
    action TEXT NOT NULL,         -- allow | deny | ask | log
    rule_id TEXT,
    rule_name TEXT,
    event_json TEXT NOT NULL,     -- raw event payload
    reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
"""


class Audit:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def record(
        self,
        *,
        source: str,
        action: Action,
        event: dict,
        rule_id: str | None = None,
        rule_name: str | None = None,
        agent: str | None = None,
        reason: str | None = None,
    ) -> int:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO events
                   (ts, source, agent, action, rule_id, rule_name, event_json, reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    time.time(),
                    source,
                    agent,
                    action.value,
                    rule_id,
                    rule_name,
                    json.dumps(event, default=str),
                    reason,
                ),
            )
            assert cur.lastrowid is not None
            return cur.lastrowid

    def recent(self, limit: int = 50, action: Action | None = None) -> list[dict]:
        sql = "SELECT * FROM events"
        params: tuple = ()
        if action is not None:
            sql += " WHERE action = ?"
            params = (action.value,)
        sql += " ORDER BY id DESC LIMIT ?"
        params = (*params, limit)
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def by_source(self) -> dict[str, int]:
        """Count events grouped by source (claude-code, proxy, manual, etc.)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT COALESCE(source, 'unknown') AS source, COUNT(*) AS n "
                "FROM events GROUP BY source ORDER BY n DESC"
            ).fetchall()
        return {r["source"]: r["n"] for r in rows}

    def by_rule(self) -> dict[str, int]:
        """Count events grouped by rule_id."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT COALESCE(rule_id, '(default)') AS rule_id, COUNT(*) AS n "
                "FROM events GROUP BY rule_id ORDER BY n DESC"
            ).fetchall()
        return {r["rule_id"]: r["n"] for r in rows}



    def since_within(self, since_ts: int, action: str | None = None) -> list[dict]:
        """Return events since a unix timestamp, optionally filtered by action."""
        sql = "SELECT * FROM events WHERE ts >= ?"
        params: list = [since_ts]
        if action:
            sql += " AND action = ?"
            # Convert Action enum to its string value
            action_value = action.value if hasattr(action, "value") else action
            params.append(action_value)
        sql += " ORDER BY ts DESC"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            # id, ts, source, agent, action, rule_id, rule_name, event_json, reason
            {"id": r[0], "ts": r[1], "source": r[2], "agent": r[3],
             "action": r[4], "rule_id": r[5], "rule_name": r[6],
             "event_json": r[7], "reason": r[8] if len(r) > 8 else None}
            for r in rows
        ]

    def counts_per_bucket(self, since_ts: int, bucket_seconds: int = 3600) -> list[dict]:
        """Return event counts grouped by time bucket since `since_ts` (unix seconds).

        Returns a list of dicts: {ts, count, allow, deny, ask} for each non-empty bucket.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    CAST(ts / ? AS INTEGER) * ? AS bucket_ts,
                    action,
                    COUNT(*) AS n
                FROM events
                WHERE ts >= ?
                GROUP BY bucket_ts, action
                ORDER BY bucket_ts ASC
                """,
                (bucket_seconds, bucket_seconds, since_ts),
            ).fetchall()
        buckets: dict[int, dict] = {}
        for bucket_ts, action, n in rows:
            action_name = action.value if hasattr(action, "value") else str(action)
            b = buckets.setdefault(int(bucket_ts), {
                "ts": int(bucket_ts), "count": 0, "allow": 0, "deny": 0, "ask": 0,
            })
            b["count"] += int(n)
            if action_name in b:
                b[action_name] = int(n)
        return list(buckets.values())

    def since(self, after_id: int = 0, limit: int = 500) -> list[dict]:
        """Return events with id > after_id, ordered ascending."""
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, ts, source, agent, action, rule_id, "
                "rule_name, event_json, reason FROM events "
                "WHERE id > ? ORDER BY id ASC LIMIT ?",
                (after_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT action, COUNT(*) AS n
                   FROM events GROUP BY action"""
            ).fetchall()
            return {r["action"]: r["n"] for r in rows}
