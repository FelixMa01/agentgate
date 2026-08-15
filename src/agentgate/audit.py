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
    reason TEXT,
    chain_hash TEXT,              -- SHA-256 of (prev_chain_hash + this row) — tamper-evident chain
    prev_chain_hash TEXT,         -- previous event's chain_hash (NULL for first row)
    resolved INTEGER DEFAULT 0,   -- 0=pending ask, 1=approved, 2=denied
    resolved_by TEXT,             -- who/what approved/denied
    resolved_at REAL,             -- unix timestamp of resolution
    receipt_signature TEXT        -- optional Ed25519 signature over (prev_sig + chain_hash + action + event)
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
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """Backfill columns added in newer releases on existing dbs."""
        cur = conn.execute("PRAGMA table_info(events)")
        cols = {row[1] for row in cur.fetchall()}
        if "receipt_signature" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN receipt_signature TEXT")

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
        sign: bool = False,
    ) -> int:
        import hashlib
        ts = time.time()
        with self._lock, self._connect() as conn:
            # Get previous hash for the chain
            prev = conn.execute(
                "SELECT chain_hash, receipt_signature FROM events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = prev[0] if prev else None
            prev_receipt_sig = prev[1] if prev else None

            event_json = json.dumps(event, default=str)
            # Compute this row's hash (chain_hash) — binds prev + own content
            row_data = f"{prev_hash or ''}|{ts}|{source}|{agent or ''}|{action.value}|{rule_id or ''}|{event_json}|{reason or ''}"
            chain_hash = hashlib.sha256(row_data.encode("utf-8")).hexdigest()

            # Optional Ed25519 receipt. Off by default so existing tests
            # and read paths are unchanged; enable via AGENTGATE_SIGN=1 or
            # by passing sign=True from the proxy.
            receipt_sig = None
            if sign:
                try:
                    from .receipts import ReceiptKeyPair, receipt_envelope
                    kp = ReceiptKeyPair.load_or_create()
                    env = receipt_envelope(
                        prev_receipt_signature=prev_receipt_sig,
                        chain_hash=chain_hash,
                        action=action.value,
                        event=event,
                        keypair=kp,
                    )
                    receipt_sig = env["signature"]
                except Exception:
                    receipt_sig = None

            cur = conn.execute(
                """INSERT INTO events
                   (ts, source, agent, action, rule_id, rule_name, event_json, reason, chain_hash, prev_chain_hash, receipt_signature)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ts,
                    source,
                    agent,
                    action.value,
                    rule_id,
                    rule_name,
                    event_json,
                    reason,
                    chain_hash,
                    prev_hash,
                    receipt_sig,
                ),
            )
            assert cur.lastrowid is not None
            return cur.lastrowid

    def verify_chain(self) -> dict:
        """Verify the hash chain. Returns a summary dict.

        - valid: True if chain is intact
        - checked: number of rows checked
        - first_broken_id: id of first row whose hash doesn't match (None if OK)
        """
        import hashlib
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, ts, source, agent, action, rule_id, event_json, reason, chain_hash, prev_chain_hash "
                "FROM events ORDER BY id ASC"
            ).fetchall()
            prev_hash = None
            first_broken = None
            checked = 0
            for r in rows:
                row_data = f"{prev_hash or ''}|{r['ts']}|{r['source']}|{r['agent'] or ''}|{r['action']}|{r['rule_id'] or ''}|{r['event_json']}|{r['reason'] or ''}"
                expected = hashlib.sha256(row_data.encode("utf-8")).hexdigest()
                checked += 1
                if (expected != r["chain_hash"] or r["prev_chain_hash"] != prev_hash) and first_broken is None:
                    first_broken = r["id"]
                prev_hash = r["chain_hash"]
            return {
                "valid": first_broken is None,
                "checked": checked,
                "first_broken_id": first_broken,
                "total_rows": len(rows),
            }

    def pending_asks(self, limit: int = 50) -> list[dict]:
        """Return pending ASK events that have not been resolved."""
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT * FROM events WHERE action = ? AND resolved = 0 "
                "ORDER BY id DESC LIMIT ?",
                (Action.ASK.value, limit),
            )
            return [dict(r) for r in cur.fetchall()]

    def resolve(self, event_id: int, decision: str, resolved_by: str = "user") -> bool:
        """Mark an ASK event as resolved. decision: 'allow' | 'deny'.

        Returns True if a row was updated, False if not found / already resolved.
        """
        resolved = 1 if decision == "allow" else 2
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE events SET resolved = ?, resolved_by = ?, resolved_at = ? "
                "WHERE id = ? AND resolved = 0",
                (resolved, resolved_by, time.time(), event_id),
            )
            return cur.rowcount > 0

    def counts_by_action(self, action: Action | None = None) -> dict[str, int]:
        """Return {action_name: count}. If action given, returns {"count": N}."""
        with self._connect() as conn:
            if action is not None:
                row = conn.execute(
                    "SELECT COUNT(*) FROM events WHERE action = ?",
                    (action.value,),
                ).fetchone()
                return {"count": row[0]}
            rows = conn.execute(
                "SELECT action, COUNT(*) FROM events GROUP BY action"
            ).fetchall()
        return {r[0]: r[1] for r in rows}

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
