"""Tests for the dashboard HTTP endpoints."""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

from agentgate.audit import Audit
from agentgate.policy import Action


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture
def db_path(tmp_path):
    p = tmp_path / "audit.db"
    a = Audit(str(p))
    for i in range(3):
        a.record(source="manual", action=Action("deny"), rule_id=f"r{i}",
                 rule_name=f"r{i}", event={"tool": "Bash", "i": i})
    return p


@pytest.fixture
def server(db_path):
    port = _free_port()
    env = os.environ.copy()
    p = subprocess.Popen(
        [sys.executable, "-m", "agentgate.cli.__init__", "dashboard",
         "--db", str(db_path), "--port", str(port), "--host", "127.0.0.1"],
        cwd="/Users/macbookm4air32g/projects/agentgate",
        env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(30):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/stats", timeout=1).read()
            break
        except Exception:
            time.sleep(0.2)
    yield f"http://127.0.0.1:{port}"
    p.terminate()
    try:
        p.wait(timeout=2)
    except subprocess.TimeoutExpired:
        p.kill()


def test_dashboard_index_html(server):
    body = urllib.request.urlopen(server + "/").read().decode()
    assert "AgentGate" in body
    assert "tsChart" in body
    assert "loadTimeseries" in body
    assert "cdn.jsdelivr.net" in body


def test_dashboard_stats_timeseries(server):
    body = urllib.request.urlopen(server + "/api/stats/timeseries?hours=1").read().decode()
    data = json.loads(body)
    assert data["hours"] == 1
    assert data["bucket_seconds"] == 3600
    assert len(data["buckets"]) >= 1
    total = sum(b["count"] for b in data["buckets"])
    assert total == 3


def test_dashboard_events_filter(server):
    body = urllib.request.urlopen(server + "/api/events?action=deny").read().decode()
    events = json.loads(body)
    assert len(events) >= 1
    assert all(e["action"] == "deny" for e in events)
