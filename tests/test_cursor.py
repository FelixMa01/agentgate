"""Tests for the Cursor hook adapter."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentgate.cursor_hook import cursor_to_event, render_response


def test_cursor_shell_event():
    payload = {
        "hook_event_name": "beforeShellExecution",
        "tool_name": "Shell",
        "tool_input": {"command": "rm -rf /etc"},
        "session_id": "s1",
        "cwd": "/home/me",
    }
    event = cursor_to_event(payload)
    assert event["tool"] == "Bash"
    assert event["command"] == "rm -rf /etc"
    assert event["agent"] == "cursor"
    assert event["session_id"] == "s1"
    assert event["cwd"] == "/home/me"


def test_cursor_file_edit_event():
    payload = {
        "hook_event_name": "beforeFileEdit",
        "tool_name": "Edit",
        "tool_input": {"file_path": "/etc/passwd"},
    }
    event = cursor_to_event(payload)
    assert event["tool"] == "Edit"
    assert event["command"] == "/etc/passwd"


def test_cursor_unknown_event_passes_through():
    payload = {
        "hook_event_name": "beforeSomethingUnknown",
        "tool_name": "Thing",
        "tool_input": {"foo": "bar"},
    }
    event = cursor_to_event(payload)
    assert event["tool"] == "Thing"
    assert event["_raw_event_name"] == "beforeSomethingUnknown"
    assert event["foo"] == "bar"


def test_cursor_response_shape():
    out = render_response("deny", "bad command")
    assert out == {"decision": "deny", "reason": "bad command"}

    out_empty = render_response("allow", "")
    assert out_empty == {"decision": "allow"}


def test_cursor_hook_subprocess(tmp_path):
    """Run the cursor_hook CLI as a real subprocess with a payload file."""
    # Need the .venv python
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
    payload.write_text(json.dumps({
        "hook_event_name": "beforeShellExecution",
        "tool_name": "Shell",
        "tool_input": {"command": "rm -rf /etc"},
    }))

    result = subprocess.run(
        [str(py), "-m", "agentgate.cursor_hook"],
        env={
            "AGENTGATE_POLICY": str(policy),
            "AGENTGATE_DB": str(db),
            "AGENTGATE_PAYLOAD_FILE": str(payload),
            "PATH": "/usr/bin:/usr/local/bin",
            "HOME": str(tmp_path),
            "LANG": "C",
        },
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    out = json.loads(result.stdout.strip())
    assert out["decision"] == "deny"