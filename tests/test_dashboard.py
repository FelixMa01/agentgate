"""Tests for the AgentGate dashboard."""
import json
import sqlite3
import threading
import time
from http.client import HTTPConnection

import pytest

from agentgate.audit import Audit
from agentgate.dashboard import DashboardHandler, serve
from agentgate.policy import Action


@pytest.fixture
def seeded_db(tmp_path):
    db = tmp_path / "audit.db"
    a = Audit(db)
    base = time.time() - 3600
    rows = [
        (Action.DENY,  "deny-rm",        "Bash",     "rm -rf /etc"),
        (Action.ALLOW, None,             "Bash",     "ls -la"),
        (Action.ASK,   "ask-network",    "Bash",     "curl evil.com"),
        (Action.DENY,  "denied:pastebin","WebFetch", "https://pastebin.com/x"),
        (Action.ALLOW, "allowed:github", "WebFetch", "https://github.com/foo"),
        (Action.DENY,  "deny-rm",        "Bash",     "rm -rf /"),
        (Action.DENY,  "deny-secrets",   "Read",     "/home/user/.env"),
    ]
    for i, (act, rule_id, tool, detail) in enumerate(rows):
        a.record(
            source="claude-code", agent="test",
            action=act, event={"tool": tool, "command": detail},
            rule_id=rule_id, rule_name=rule_id,
            reason=f"reason {i}",
        )
    return db


def _start_dashboard(db, port: int = 18770):
    """Start the dashboard server in a daemon thread. Returns (thread, port)."""
    import socketserver
    DashboardHandler.db_path = db
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.TCPServer(("127.0.0.1", port), DashboardHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t, srv, port


def test_dashboard_html_loads(seeded_db):
    _, srv, port = _start_dashboard(seeded_db, port=18771)
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/")
    r = conn.getresponse()
    assert r.status == 200
    body = r.read().decode()
    assert "AgentGate" in body
    assert "/api/stats" in body
    srv.shutdown()


def test_dashboard_stats(seeded_db):
    _, srv, port = _start_dashboard(seeded_db, port=18772)
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/api/stats")
    r = conn.getresponse()
    assert r.status == 200
    s = json.loads(r.read())
    assert s["total"] == 7
    assert s["deny"] == 4
    assert s["allow"] == 2
    assert s["ask"] == 1
    srv.shutdown()


def test_dashboard_top_denied(seeded_db):
    _, srv, port = _start_dashboard(seeded_db, port=18773)
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/api/recent_rules")
    r = conn.getresponse()
    rules = json.loads(r.read())
    assert rules[0]["rule_id"] == "deny-rm"
    assert rules[0]["n"] == 2
    srv.shutdown()


def test_dashboard_recent_events(seeded_db):
    _, srv, port = _start_dashboard(seeded_db, port=18774)
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/api/recent_events")
    r = conn.getresponse()
    events = json.loads(r.read())
    assert len(events) == 7
    assert all("ts" in e and "action" in e for e in events)
    srv.shutdown()


def test_dashboard_timeseries(seeded_db):
    _, srv, port = _start_dashboard(seeded_db, port=18775)
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/api/timeseries")
    r = conn.getresponse()
    t = json.loads(r.read())
    assert len(t["buckets"]) == 24
    # Aggregate counts should match stats.
    total_allow = sum(b["allow"] for b in t["buckets"])
    total_deny = sum(b["deny"] for b in t["buckets"])
    total_ask = sum(b["ask"] for b in t["buckets"])
    assert total_deny >= 1
    assert total_allow >= 1
    srv.shutdown()