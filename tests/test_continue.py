"""Tests for the Continue.dev hook adapter."""

import json
import subprocess
from pathlib import Path

import pytest

from agentgate.continue_hook import continue_payload_to_event


def test_continue_payload_to_event_bash():
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /etc"},
        "session_id": "s1",
        "cwd": "/home/me",
    }
    event, tool, _agent = continue_payload_to_event(payload)
    assert event["tool"] == "Bash"
    assert event["command"] == "rm -rf /etc"
    assert tool == "Bash"
    # agent may be None for Continue payload (Claude has it pre-populated)


def test_continue_payload_to_event_read():
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/etc/passwd"},
    }
    event, tool, _ = continue_payload_to_event(payload)
    assert event["tool"] == "Read"
    assert tool == "Read"


def test_continue_subprocess_deny(tmp_path):
    """Real subprocess test: Continue-style payload → deny."""
    project_root = Path(__file__).resolve().parents[1]
    py = project_root / ".venv" / "bin" / "python"
    if not py.exists():
        pytest.skip(".venv not built")

    policy = tmp_path / "p.yaml"
    policy.write_text("""
version: 1
default: allow
rules:
  - id: deny-rm
    match: {tool: Bash, command: "rm -rf /*"}
    action: deny
""")
    db = tmp_path / "audit.db"
    payload = tmp_path / "payload.json"
    payload.write_text(
        json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /etc"},
            }
        )
    )
    result = subprocess.run(
        [str(py), "-m", "agentgate.continue_hook"],
        env={
            "AGENTGATE_POLICY": str(policy),
            "AGENTGATE_DB": str(db),
            "AGENTGATE_PAYLOAD_FILE": str(payload),
            "PATH": "/usr/bin:/usr/local/bin",
            "HOME": str(tmp_path),
            "LANG": "C",
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    out = json.loads(result.stdout.strip())
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_install_continue_hook_creates_settings(tmp_path):
    project_root = Path(__file__).resolve().parents[1]
    py = project_root / ".venv" / "bin" / "python"
    if not py.exists():
        pytest.skip(".venv not built")

    policy = tmp_path / "p.yaml"
    policy.write_text("version: 1\ndefault: allow\nrules: []\n")
    db = tmp_path / "audit.db"
    result = subprocess.run(
        [
            str(py),
            "-m",
            "agentgate.cli.__init__",
            "install-continue-hook",
            "-p",
            str(policy),
            "--db",
            str(db),
            "--target",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    cfg = tmp_path / ".continue" / "settings.json"
    assert cfg.exists()
    data = json.loads(cfg.read_text())
    assert "PreToolUse" in data["hooks"]
    cmd_entry = data["hooks"]["PreToolUse"][0]["hooks"][0]
    assert "AGENTGATE_POLICY" in cmd_entry["command"]
