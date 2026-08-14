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
    """End-to-end: start server, record events, ensure SSE pushes them.

    Uses a raw socket (instead of HTTPConnection) so we can read byte by
    byte until the full SSE message terminator (\n\n) arrives. The
    server polls at 200ms so a single new row is pushed within ~1s.
    """
    db = tmp_path / "audit.db"
    port = _free_port()
    t = threading.Thread(target=serve, args=(str(db), "127.0.0.1", port), daemon=True)
    t.start()
    time.sleep(0.5)

    chunks: list[str] = []
    reader_error: list[str] = []
    reader_done = threading.Event()

    def reader():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(("127.0.0.1", port))
            sock.sendall(b"GET /api/events/stream HTTP/1.1\r\n"
                          b"Host: localhost\r\n"
                          b"Connection: keep-alive\r\n\r\n")
            # Read until we've consumed the response headers.
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    return
                buf += chunk
            # Then read until we see at least one full SSE message
            # (terminated by \n\n after 'event: audit').
            deadline = time.time() + 10
            saw_event = False
            while time.time() < deadline:
                try:
                    chunk = sock.recv(4096)
                except TimeoutError:
                    break
                if not chunk:
                    break
                buf += chunk
                if b"event: audit" in buf:
                    saw_event = True
                if saw_event and b"\n\n" in buf.split(b"event: audit", 1)[1]:
                    break
            chunks.append(buf.decode("utf-8", errors="replace"))
            sock.close()
        except Exception as e:
            reader_error.append(repr(e))

    rt = threading.Thread(target=reader, daemon=True)
    rt.start()
    time.sleep(1)  # let SSE initialize last_id

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
    rt.join(timeout=12)
    reader_done.set()

    if reader_error:
        pytest.fail(f"reader thread error: {reader_error[0]}")
    assert chunks, "reader thread produced no chunks"
    body = chunks[0]
    # Strip the HTTP headers.
    if "\r\n\r\n" in body:
        body = body.split("\r\n\r\n", 1)[1]
    assert "event: audit" in body, f"no 'event: audit' in body: {body!r}"
    # Find the data: line and parse it as JSON.
    data_line = None
    for line in body.splitlines():
        if line.startswith("data: "):
            data_line = line[len("data: "):]
            break
    assert data_line is not None, f"no data: line in body: {body!r}"
    payload = json.loads(data_line)
    assert payload["rule_id"] == "deny-rm"
    assert payload["action"] == "deny"
