"""Tests for `agentgate audit verify` (hash-chain integrity)."""
import os
import tempfile

import pytest
from click.testing import CliRunner

from agentgate.audit import Audit
from agentgate.cli.__init__ import main
from agentgate.policy import Action


@pytest.fixture
def db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    a = Audit(path)
    for i in range(3):
        a.record(
            source="claude-code",
            action=Action.ALLOW,
            event={"tool": "Read", "command": f"cmd-{i}"},
            rule_id=f"r{i}",
            rule_name=f"rule {i}",
            agent="test",
        )
    yield path
    os.unlink(path)


def test_chain_valid_after_records(db):
    a = Audit(db)
    result = a.verify_chain()
    assert result["valid"] is True
    assert result["checked"] == 3
    assert result["first_broken_id"] is None


def test_chain_detects_tampered_row(db):
    # Directly tamper with one row's event_json after recording
    import sqlite3
    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE events SET event_json = ? WHERE id = 2",
        ('{"tool": "Read", "command": "TAMPERED"}',),
    )
    conn.commit()
    conn.close()

    a = Audit(db)
    result = a.verify_chain()
    assert result["valid"] is False
    assert result["first_broken_id"] == 2


def test_chain_detects_deleted_row(db):
    """If a row is deleted, the chain breaks at the next row."""
    import sqlite3
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM events WHERE id = 2")
    conn.commit()
    conn.close()

    a = Audit(db)
    result = a.verify_chain()
    assert result["valid"] is False


def test_cli_audit_verify_ok(db):
    r = CliRunner().invoke(main, ["audit", "verify", "--db", db])
    assert r.exit_code == 0, r.output
    assert "OK" in r.output
    assert "3 rows" in r.output


def test_cli_audit_verify_json(db):
    r = CliRunner().invoke(main, ["audit", "verify", "--db", db, "--json"])
    assert r.exit_code == 0, r.output
    import json
    data = json.loads(r.output)
    assert data["valid"] is True


def test_cli_audit_verify_broken(db):
    import sqlite3
    conn = sqlite3.connect(db)
    conn.execute("UPDATE events SET event_json = ? WHERE id = 1", ('"x"',))
    conn.commit()
    conn.close()
    r = CliRunner().invoke(main, ["audit", "verify", "--db", db])
    assert r.exit_code == 1
    assert "BROKEN" in r.output
