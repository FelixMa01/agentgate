"""Tests for the dashboard SSE endpoint."""

import json
import socket
import threading
import time
from http.client import HTTPConnection
from pathlib import Path

import pytest

from agentgate.dashboard import serve


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_sse_stream_yields_new_events(tmp_path):
    """End-to-end: start server, record events, ensure SSE pushes them."""
    db = tmp_path / "audit.db"
    port = _free_port()
    t = threading.Thread(target=serve, args=(str(db), "127.0.0.1", port), daemon=True)
    t.start()
    time.sleep(0.5)

    # Open an SSE connection in a background thread.
    chunks: list[str] = []
    done = threading.Event()

    def reader():
        conn = HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", "/api/events/stream")
        resp = conn.getresponse()
        assert resp.status == 200
        assert "text/event-stream" in resp.getheader("Content-Type", "")
        # Read until we see at least one 'event: audit' line, with a timeout.
        buf = b""
        deadline = time.time() + 5
        while time.time() < deadline and not done.is_set():
            chunk = resp.read(256)
            if not chunk:
                break
            buf += chunk
            if b"event: audit" in buf:
                break
        chunks.append(buf.decode("utf-8", errors="replace"))
        conn.close()

    rt = threading.Thread(target=reader, daemon=True)
    rt.start()
    time.sleep(1)  # let SSE initialize last_id

    # Now write a new event into the same DB.
    from agentgate.audit import Audit
    from agentgate.policy import Action

    audit = Audit(str(db))
    audit.record(
        source="test",
        agent="sse",
        action=Action.DENY,
        event={"tool": "Bash", "command": "rm -rf /"},
        rule_id="deny-rm",
        rule_name="Block destructive rm",
        reason="sse test",
    )
    rt.join(timeout=6)
    done.set()

    assert len(chunks) == 1
    body = chunks[0]
    # Should contain at least one 'event: audit' line.
    assert "event: audit" in body
    # And the data should be valid JSON.
    for line in body.splitlines():
        if line.startswith("data: "):
            payload = json.loads(line[len("data: ") :])
            assert payload["action"] in {"deny", "Action.DENY", "DENY"}
            assert payload["rule_id"] == "deny-rm"
