"""Tests for AgentGate core."""

from pathlib import Path

import pytest

from agentgate.audit import Audit
from agentgate.policy import Action, load_policy


@pytest.fixture
def policy(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text("""
version: 1
default: allow
rules:
  - id: deny-rm
    name: Block rm -rf
    match:
      tool: Bash
      command_glob: "rm -rf /*"
    action: deny
    reason: "dangerous"

  - id: ask-secrets
    name: Ask before reading secrets
    match: {tool: Read, file_glob: ".env*"}
    action: ask

  - id: log-grep
    name: Log all grep
    match: {tool: Grep}
    action: log
""")
    return p


def test_load_policy(policy: Path):
    pol = load_policy(policy)
    assert len(pol.rules) == 3
    assert pol.default_action == Action.ALLOW


def test_rule_glob_match(policy: Path):
    pol = load_policy(policy)
    action, rule = pol.evaluate({"tool": "Bash", "command": "rm -rf /etc"})
    assert action == Action.DENY
    assert rule and rule.id == "deny-rm"


def test_rule_glob_no_match(policy: Path):
    pol = load_policy(policy)
    action, rule = pol.evaluate({"tool": "Bash", "command": "ls -la"})
    assert action == Action.ALLOW
    assert rule is None


def test_list_match(policy: Path):
    pol = load_policy(policy)
    action, rule = pol.evaluate({"tool": "Read", "file": ".env.production"})
    assert action == Action.ASK
    assert rule and rule.id == "ask-secrets"


def test_default_action(tmp_path: Path):
    p = tmp_path / "p.yaml"
    p.write_text("version: 1\ndefault: deny\nrules: []")
    pol = load_policy(p)
    action, _rule = pol.evaluate({"tool": "Bash", "command": "ls"})
    assert action == Action.DENY


def test_audit_record(tmp_path: Path):
    db = Audit(tmp_path / "test.db")
    eid = db.record(
        source="manual",
        action=Action.DENY,
        event={"x": 1},
        rule_id="r1",
        rule_name="Test",
        reason="because",
    )
    assert eid > 0
    rows = db.recent()
    assert len(rows) == 1
    assert rows[0]["action"] == "deny"


def test_audit_filter(tmp_path: Path):
    db = Audit(tmp_path / "test.db")
    db.record(source="manual", action=Action.ALLOW, event={})
    db.record(source="manual", action=Action.DENY, event={})
    denied = db.recent(action=Action.DENY)
    assert len(denied) == 1


def test_cli_eval_runs(tmp_path: Path, policy: Path, monkeypatch):
    """Smoke-test: init -> eval -> audit shows the recorded decision."""
    from click.testing import CliRunner

    from agentgate.cli import main as cli_main

    runner = CliRunner()
    db_path = tmp_path / "audit.db"

    # eval a denied command
    res = runner.invoke(
        cli_main,
        [
            "eval",
            "-p",
            str(policy),
            "--db",
            str(db_path),
            "--event-json",
            '{"tool": "Bash", "command": "rm -rf /etc"}',
        ],
    )
    assert res.exit_code == 0
    assert "DENY" in res.output

    # audit shows the entry
    res2 = runner.invoke(cli_main, ["audit", "--db", str(db_path)])
    assert res2.exit_code == 0
    assert "deny-rm" in res2.output
