"""Tests for the ask queue dashboard endpoints + Audit.resolve/pending_asks."""
import json
import socket
import threading
import time
import urllib.request

import pytest

from agentgate.audit import Audit
from agentgate.policy import Action


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _start_server(db, port):
    from agentgate.dashboard import serve
    t = threading.Thread(target=serve, args=(str(db), "127.0.0.1", port), daemon=True)
    t.start()
    time.sleep(0.3)
    return t


def _post(url, body):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    return urllib.request.urlopen(req)


def test_pending_asks_empty(tmp_path):
    db = tmp_path / "audit.db"
    Audit(str(db))
    assert Audit(str(db)).pending_asks() == []


def test_pending_asks_returns_only_unresolved(tmp_path):
    db = tmp_path / "audit.db"
    a = Audit(str(db))
    a.record(source="x", agent="a1", action=Action.ASK,
             event={"tool": "Bash", "command": "rm"},
             rule_id="ask-rm", rule_name="ask-rm", reason="x")
    a.record(source="x", agent="a1", action=Action.DENY,
             event={"tool": "Bash", "command": "rm"},
             rule_id="ask-rm", rule_name="ask-rm", reason="x")
    pending = a.pending_asks()
    assert len(pending) == 1
    assert pending[0]["action"] == "ask"


def test_resolve_marks_event(tmp_path):
    db = tmp_path / "audit.db"
    a = Audit(str(db))
    a.record(source="x", agent="a1", action=Action.ASK,
             event={"tool": "Bash", "command": "ls"},
             rule_id="ask-ls", rule_name="ask-ls", reason="x")
    pending = a.pending_asks()
    event_id = pending[0]["id"]
    assert a.resolve(event_id, "allow", resolved_by="reviewer")
    # Resolved events no longer appear in pending list.
    assert a.pending_asks() == []
    # Second resolve returns False.
    assert not a.resolve(event_id, "deny")


def test_api_asks_pending_returns_events(tmp_path):
    db = tmp_path / "audit.db"
    a = Audit(str(db))
    for tool in ["Bash", "Read", "WebFetch"]:
        a.record(source="claude-code", agent="agent1", action=Action.ASK,
                 event={"tool": tool}, rule_id=f"r-{tool}",
                 rule_name=f"r-{tool}", reason="x")
    port = _free_port()
    _start_server(db, port)
    resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/asks/pending?limit=10")
    data = json.loads(resp.read())
    assert len(data) == 3
    assert all(e["resolved"] == 0 for e in data)
    assert all(e["event"]["tool"] in {"Bash", "Read", "WebFetch"} for e in data)


def test_api_asks_resolve_updates_pending_count(tmp_path):
    db = tmp_path / "audit.db"
    a = Audit(str(db))
    for _ in range(3):
        a.record(source="claude-code", agent="agent1", action=Action.ASK,
                 event={"tool": "Bash"}, rule_id="r", rule_name="r", reason="x")
    port = _free_port()
    _start_server(db, port)
    before = json.loads(urllib.request.urlopen(
        f"http://127.0.0.1:{port}/api/asks/pending?limit=10"
    ).read())
    target = before[0]["id"]
    _post(f"http://127.0.0.1:{port}/api/asks/resolve", {"id": target, "decision": "allow"})
    after = json.loads(urllib.request.urlopen(
        f"http://127.0.0.1:{port}/api/asks/pending?limit=10"
    ).read())
    assert len(after) == 2
    assert target not in {e["id"] for e in after}


def test_api_asks_resolve_rejects_bad_payload(tmp_path):
    db = tmp_path / "audit.db"
    a = Audit(str(db))
    a.record(source="x", agent="a1", action=Action.ASK,
             event={"tool": "Bash"}, rule_id="r", rule_name="r", reason="x")
    port = _free_port()
    _start_server(db, port)
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"http://127.0.0.1:{port}/api/asks/resolve", {"id": "not-int", "decision": "allow"})
    assert exc.value.code == 400


def test_api_asks_page_renders(tmp_path):
    db = tmp_path / "audit.db"
    port = _free_port()
    _start_server(db, port)
    resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/asks")
    assert resp.status == 200
    body = resp.read().decode()
    assert "Ask Queue" in body
    assert "/api/asks/pending" in body
    assert "/api/asks/resolve" in body


def test_resolve_unknown_id_returns_404(tmp_path):
    db = tmp_path / "audit.db"
    port = _free_port()
    _start_server(db, port)
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(f"http://127.0.0.1:{port}/api/asks/resolve", {"id": 99999, "decision": "allow"})
    assert exc.value.code == 404
