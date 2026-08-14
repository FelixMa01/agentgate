"""Tests for the alerts CLI and Audit.counts_per_bucket / since_within."""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from agentgate.audit import Audit
from agentgate.policy import Action


@pytest.fixture
def db_path(tmp_path):
    p = tmp_path / "audit.db"
    audit = Audit(str(p))
    for i, (action_str, source) in enumerate([
        ("deny", "manual"), ("deny", "manual"), ("deny", "network"),
        ("allow", "manual"), ("allow", "network"),
    ]):
        audit.record(
            source=source, action=Action(action_str), rule_id=f"rule-{i}",
            rule_name=f"rule-{i}",
            event={"tool": "Bash", "i": i},
        )
    return p


def test_counts_per_bucket(db_path):
    a = Audit(str(db_path))
    buckets = a.counts_per_bucket(since_ts=int(time.time()) - 3600, bucket_seconds=3600)
    assert len(buckets) >= 1
    total = sum(b["count"] for b in buckets)
    assert total == 5
    total_deny = sum(b["deny"] for b in buckets)
    total_allow = sum(b["allow"] for b in buckets)
    assert total_deny == 3
    assert total_allow == 2


def test_since_within_filters_by_action(db_path):
    a = Audit(str(db_path))
    events = a.since_within(int(time.time()) - 3600, action="deny")
    assert len(events) == 3
    assert all(e["action"] == "deny" for e in events)


def test_alerts_cli_no_match(db_path, tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - name: never\n"
        "    window_minutes: 60\n"
        "    threshold: 9999\n"
        "    action: deny\n"
        "    message: 'count={{count}}'\n"
    )
    r = subprocess.run(
        [sys.executable, "-m", "agentgate.cli.__init__", "alerts",
         "--db", str(db_path), "--rules", str(rules)],
        capture_output=True, text=True, cwd="/Users/macbookm4air32g/projects/agentgate",
    )
    assert r.returncode == 0
    assert "0 alerts fired" in r.stdout


def test_alerts_cli_fires(db_path, tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - name: any-deny\n"
        "    window_minutes: 60\n"
        "    threshold: 2\n"
        "    action: deny\n"
        "    message: 'denies={{count}}'\n"
    )
    r = subprocess.run(
        [sys.executable, "-m", "agentgate.cli.__init__", "alerts",
         "--db", str(db_path), "--rules", str(rules)],
        capture_output=True, text=True, cwd="/Users/macbookm4air32g/projects/agentgate",
    )
    assert r.returncode == 0
    assert "1 alerts fired" in r.stdout
    assert "denies=3" in r.stdout
