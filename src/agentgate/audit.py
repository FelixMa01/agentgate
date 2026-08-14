"""SQLite-backed audit trail of every evaluated event."""
from __future__ import annotations
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable

from .policy import Action, Policy


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
        params = params + (limit,)
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def stats(self) -> dict:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT action, COUNT(*) AS n
                   FROM events GROUP BY action"""
            ).fetchall()
            return {r["action"]: r["n"] for r in rows}