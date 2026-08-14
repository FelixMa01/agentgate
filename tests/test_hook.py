"""Tests for the Claude Code PreToolUse hook payload translation."""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentgate.hook import claude_event_to_agent_event, decision_to_cc_response
from agentgate.hook import main as hook_main
from agentgate.policy import Action


def _stdin(payload: dict) -> io.StringIO:
    return io.StringIO(json.dumps(payload))


def test_translate_bash():
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "abc",
        "cwd": "/tmp",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /etc"},
    }
    event, tool, agent = claude_event_to_agent_event(payload)
    assert tool == "Bash"
    assert event["tool"] == "Bash"
    assert event["command"] == "rm -rf /etc"
    assert event["cwd"] == "/tmp"
    assert event["session_id"] == "abc"
    assert agent == "abc"


def test_translate_read_file():
    payload = {
        "tool_name": "Read",
        "tool_input": {"file_path": "/home/user/.env"},
    }
    event, _, _ = claude_event_to_agent_event(payload)
    assert event["tool"] == "Read"
    assert event["file"] == "/home/user/.env"


def test_translate_write_content():
    payload = {
        "tool_name": "Write",
        "tool_input": {"file_path": "x.py", "content": "print('hi')"},
    }
    event, _, _ = claude_event_to_agent_event(payload)
    assert event["content"] == "print('hi')"


def test_translate_webfetch():
    payload = {
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://pastebin.com/raw/abc"},
    }
    event, _, _ = claude_event_to_agent_event(payload)
    assert event["url"] == "https://pastebin.com/raw/abc"


def test_decision_deny():
    out = decision_to_cc_response(Action.DENY, "danger")
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert out["hookSpecificOutput"]["permissionDecisionReason"] == "danger"
    assert "AgentGate" in out["systemMessage"]


def test_decision_ask():
    out = decision_to_cc_response(Action.ASK, "review me")
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_decision_allow():
    out = decision_to_cc_response(Action.ALLOW, "")
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert "permissionDecisionReason" not in out["hookSpecificOutput"]


def test_hook_end_to_end_deny(tmp_path, monkeypatch):
    """Feed a real Claude Code PreToolUse payload through the hook and assert deny."""
    policy = tmp_path / "policy.yaml"
    policy.write_text("""
version: 1
default: allow
rules:
  - id: deny-rm
    name: Block rm -rf
    match:
      tool: Bash
      command: "rm -rf /*"
    action: deny
""")
    db = tmp_path / "audit.db"

    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "test-session",
        "cwd": str(tmp_path),
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /etc"},
    }
    monkeypatch.setenv("AGENTGATE_POLICY", str(policy))
    monkeypatch.setenv("AGENTGATE_DB", str(db))
    monkeypatch.setattr(sys, "stdin", _stdin(payload))
    captured = io.StringIO()
    monkeypatch.setattr(sys, "stdout", captured)

    rc = hook_main()
    assert rc == 0
    out = json.loads(captured.getvalue())
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert (
        out["hookSpecificOutput"]["permissionDecisionReason"] == ""
        or "reason" not in out["hookSpecificOutput"]
    )
    # the rule had empty reason so permissionDecisionReason may be missing; check systemMessage
    assert "AgentGate" in out.get("systemMessage", "")

    # verify audit recorded
    from agentgate.audit import Audit

    rows = Audit(db).recent()
    assert len(rows) == 1
    assert rows[0]["action"] == "deny"
    assert rows[0]["source"] == "claude-code"


def test_hook_end_to_end_allow(tmp_path, monkeypatch):
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\ndefault: allow\nrules: []\n")
    db = tmp_path / "audit.db"
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "s",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
    }
    monkeypatch.setenv("AGENTGATE_POLICY", str(policy))
    monkeypatch.setenv("AGENTGATE_DB", str(db))
    monkeypatch.setattr(sys, "stdin", _stdin(payload))
    captured = io.StringIO()
    monkeypatch.setattr(sys, "stdout", captured)

    rc = hook_main()
    assert rc == 0
    out = json.loads(captured.getvalue())
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_hook_fails_open_on_missing_env(monkeypatch, tmp_path):
    """No env vars -> fail open (exit 0, no stdout JSON)."""
    monkeypatch.delenv("AGENTGATE_POLICY", raising=False)
    monkeypatch.delenv("AGENTGATE_DB", raising=False)
    monkeypatch.setattr(sys, "stdin", _stdin({"tool_name": "Bash", "tool_input": {"command": "x"}}))
    captured = io.StringIO()
    monkeypatch.setattr(sys, "stdout", captured)
    rc = hook_main()
    assert rc == 0
    assert captured.getvalue() == ""


def test_hook_script_via_subprocess(tmp_path):
    """Real subprocess invocation of bin/agentgate-hook.py, simulating how
    Claude Code itself spawns it. Uses the project venv's Python to ensure
    dependencies are available.
    """
    repo_root = Path(__file__).resolve().parents[1]
    hook_script = repo_root / "bin" / "agentgate-hook.py"
    if not hook_script.exists():
        pytest.skip("hook script missing")

    # Locate the project venv Python (the one uv created).
    venv_python = repo_root / ".venv" / "bin" / "python"
    if not venv_python.exists():
        pytest.skip(f"project venv missing at {venv_python}")

    policy = tmp_path / "policy.yaml"
    policy.write_text("""
version: 1
default: allow
rules:
  - id: deny-rm
    match: {tool: Bash, command: "rm -rf /*"}
    action: deny
""")
    db = tmp_path / "audit.db"
    payload = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "session_id": "subproc",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /etc"},
        }
    )

    env = os.environ.copy()
    env["AGENTGATE_POLICY"] = str(policy)
    env["AGENTGATE_DB"] = str(db)

    proc = subprocess.run(
        [str(venv_python), str(hook_script)],
        input=payload.encode(),
        capture_output=True,
        env=env,
        timeout=30,
    )
    if proc.returncode != 0:
        pytest.fail(
            f"hook exited {proc.returncode}\nstdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
        )
    out = json.loads(proc.stdout.decode())
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
