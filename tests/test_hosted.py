"""Tests for hosted mode — uses an in-process HTTP server."""
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from agentgate.hosted import pull_policy, push_events
from agentgate.audit import Audit
from agentgate.policy import Action


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def fake_hosted():
    """Spin up a tiny hosted server with a hard-coded policy + cursor endpoint."""
    events: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a, **kw): pass

        def do_GET(self):
            if self.path == "/policy.yaml":
                body = b"version: 1\ndefault: allow\nrules: []\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/yaml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif "/api/events?cursor=last_id" in self.path:
                last_id = max((e["id"] for e in events), default=0)
                body = json.dumps({"last_id": last_id}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if "/api/events" in self.path:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                payload = json.loads(body)
                events.extend(payload.get("events", []))
                response = json.dumps({"accepted": len(events)}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            else:
                self.send_response(404)
                self.end_headers()

    port = _free_port()
    server = HTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)
    yield f"http://127.0.0.1:{port}", events
    server.shutdown()


def test_pull_policy_caches_to_file(fake_hosted, tmp_path):
    base, _ = fake_hosted
    out = tmp_path / "policy.yaml"
    path = pull_policy(url=f"{base}/policy.yaml", cache=out)
    assert Path(path).read_text().startswith("version: 1")


def test_pull_policy_uses_env_url(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGATE_HOSTED_URL", "http://nonexistent.invalid")
    with pytest.raises(RuntimeError):
        pull_policy(cache=tmp_path / "x.yaml")


def test_push_events_uploads_new(fake_hosted, tmp_path):
    base, events = fake_hosted
    db = tmp_path / "audit.db"
    audit = Audit(str(db))
    audit.record(source="t", action=Action.DENY, event={"x": 1}, rule_id="r1")
    audit.record(source="t", action=Action.ALLOW, event={"y": 2})
    n = push_events(str(db), url=f"{base}/api/events")
    assert n == 2
    assert len(events) == 2
    assert events[0]["rule_id"] == "r1"


def test_push_events_respects_cursor(fake_hosted, tmp_path):
    base, events = fake_hosted
    db = tmp_path / "audit.db"
    audit = Audit(str(db))
    audit.record(source="t", action=Action.DENY, event={"x": 1})
    push_events(str(db), url=f"{base}/api/events")
    assert len(events) == 1
    # Now add another and push again — cursor should prevent re-uploading.
    audit.record(source="t", action=Action.ALLOW, event={"y": 2})
    n = push_events(str(db), url=f"{base}/api/events")
    assert n == 1
    assert len(events) == 2


def test_push_events_empty_db(fake_hosted, tmp_path):
    base, events = fake_hosted
    db = tmp_path / "audit.db"
    Audit(str(db))  # touch the schema
    n = push_events(str(db), url=f"{base}/api/events")
    assert n == 0
    assert len(events) == 0
