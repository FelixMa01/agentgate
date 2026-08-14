"""Tests for approval store + Slack notification + approval HTTP server."""
import io
import json
import threading
import time
from http.client import HTTPConnection
from urllib.parse import quote

import pytest

from agentgate.approval import ApprovalStore, STORE as GLOBAL_STORE
from agentgate.approval_server import _render
from agentgate.notify import build_ask_message, notify_ask, post_to_slack


# ----- ApprovalStore -----

def test_store_request_and_wait():
    s = ApprovalStore()
    ask = s.request({"tool": "Bash", "command": "ls"}, "Bash", "rule-1")
    assert ask.token
    assert ask.decision is None
    # Resolve from another thread
    def _resolve():
        time.sleep(0.05)
        s.resolve(ask.token, "allow")
    threading.Thread(target=_resolve).start()
    assert s.wait(ask.token, timeout=1.0) == "allow"


def test_store_wait_times_out():
    s = ApprovalStore()
    ask = s.request({}, "x", None)
    assert s.wait(ask.token, timeout=0.1) is None


def test_store_resolve_unknown():
    s = ApprovalStore()
    assert s.resolve("nope", "allow") is False


def test_store_cleanup_resolved():
    s = ApprovalStore()
    ask = s.request({}, "x", None)
    s.resolve(ask.token, "deny")
    # Backdate both DB and in-memory so cleanup removes them.
    backdated = time.time() - 999
    ask.resolved_at = backdated
    import sqlite3
    with sqlite3.connect(s.db_path) as conn:
        conn.execute(
            "UPDATE approvals SET resolved_at = ? WHERE token = ?",
            (backdated, ask.token),
        )
    n = s.cleanup(max_age=10)
    assert n >= 1
    assert ask.token not in s._pending
    with sqlite3.connect(s.db_path) as conn:
        rows = conn.execute(
            "SELECT token FROM approvals WHERE token = ?", (ask.token,)
        ).fetchall()
    assert rows == []


# ----- Slack notify -----

def test_build_ask_message_includes_buttons():
    msg = build_ask_message(
        token="abc123", tool="Bash",
        event={"command": "rm -rf /etc"},
        rule_name="Block rm -rf", reason="dangerous",
        approval_host="localhost:8765",
    )
    s = json.dumps(msg)
    assert "localhost:8765/approve/abc123?d=allow" in s
    assert "localhost:8765/approve/abc123?d=deny" in s
    assert "Bash" in s


def test_post_to_slack_bad_url():
    ok, msg = post_to_slack("http://invalid.invalid.local/abc", {})
    assert ok is False


def test_notify_ask_falls_back_to_file(tmp_path, monkeypatch):
    """With no AGENTGATE_SLACK_WEBHOOK set, notify_ask writes to AGENTGATE_ASK_FALLBACK."""
    monkeypatch.delenv("AGENTGATE_SLACK_WEBHOOK", raising=False)
    target = tmp_path / "asks.jsonl"
    monkeypatch.setenv("AGENTGATE_ASK_FALLBACK", str(target))
    status = notify_ask("tk1", "Bash", {"command": "x"}, "r", "why")
    assert status.startswith("file:")
    from pathlib import Path
    f = Path(target)
    assert f.exists()
    last_line = f.read_text().strip().splitlines()[-1]
    payload = json.loads(last_line)
    assert "tk1" in json.dumps(payload)


# ----- Approval HTTP server (in-process) -----

def _start_server_in_thread(host: str = "127.0.0.1", port: int = 0) -> tuple[threading.Thread, str, int]:
    """Start the approval server in a daemon thread. Returns (thread, host, actual_port)."""
    import socketserver
    from agentgate.approval_server import Handler
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer((host, port), Handler)
    actual_port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t, host, actual_port


def test_http_health():
    _, host, port = _start_server_in_thread(port=18765)
    conn = HTTPConnection(host, port, timeout=5)
    conn.request("GET", "/health")
    resp = conn.getresponse()
    assert resp.status == 200
    assert b"ok" in resp.read()


def test_http_approve_then_status_shows_resolution():
    from agentgate.approval import STORE as global_store
    # Use the singleton the HTTP server reads from.
    ask = global_store.request({"tool": "Bash", "command": "curl evil.com"}, "Bash", "r")
    _, host, port = _start_server_in_thread(port=18766)
    conn = HTTPConnection(host, port, timeout=5)
    conn.request("GET", f"/approve/{ask.token}?d=deny")
    resp = conn.getresponse()
    body = resp.read().decode()
    assert resp.status == 200
    assert "DENY" in body or "deny" in body
    # Confirm the store received the resolution
    assert ask.decision == "deny"


def test_http_unknown_token_returns_404():
    _, host, port = _start_server_in_thread(port=18767)
    conn = HTTPConnection(host, port, timeout=5)
    conn.request("GET", "/approve/does-not-exist?d=allow")
    resp = conn.getresponse()
    assert resp.status == 404


def test_render_includes_event():
    body = _render({"tool": "Bash", "command": "ls"}, decision=None, token="t1")
    assert "Bash" in body
    assert "t1" in body
    assert "Allow" in body and "Deny" in body