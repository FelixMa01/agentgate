"""Tests for the Aider adapter."""
import json

from agentgate.aider_adapter import aider_payload_to_event


def test_aider_bash_to_bash_event():
    event = aider_payload_to_event({"action": "bash", "command": "rm -rf /", "cwd": "/x"})
    assert event["tool"] == "Bash"
    assert event["command"] == "rm -rf /"
    assert event["agent"] == "aider"
    assert event["cwd"] == "/x"


def test_aider_read_to_read_event():
    event = aider_payload_to_event({"action": "read", "path": "/etc/passwd"})
    assert event["tool"] == "Read"
    assert event["file_path"] == "/etc/passwd"


def test_aider_write_to_write_event():
    event = aider_payload_to_event({"action": "write", "path": "x.py", "content": "print(1)"})
    assert event["tool"] == "Write"
    assert event["file_path"] == "x.py"


def test_aider_unknown_defaults_to_bash():
    event = aider_payload_to_event({"action": "weird", "command": "ls"})
    assert event["tool"] == "Bash"
    # Unknown kinds still produce a Bash event but with empty command.
    assert "command" in event