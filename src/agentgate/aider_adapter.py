"""Aider adapter — wrap shell commands before they execute.

Aider doesn't have a real PreToolUse-style hook system. The closest thing is
its `--no-auto-commits` and `--edit-format` flags, plus the `aider` CLI
itself shells out to git/python/etc.

The pragmatic AgentGate approach: an `aider` wrapper script that imports
`evaluate_event`, evaluates any tool call the agent emits, and either
forwards to the real aider or denies based on the result.

For a tighter integration: use Aider's `aider --no-auto-commits` plus a
pre-commit git hook that calls `agentgate eval` on every commit.

This module provides:
- `aider_payload_to_event()` — turn a synthetic Aider payload into an event.
- `aider_decide()` — run policy + audit, return (action, reason).
- A `bin/agentgate-aider` launcher script.

The launcher is meant to be put on PATH ahead of the real `aider` so
typing `aider` actually invokes AgentGate-wrapped aider.
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path


# Aider doesn't expose tool-level hooks; we use a simpler model: the launcher
# asks the user for confirmation on every Bash-like operation Aider performs,
# gated by the AgentGate policy.

_AIDER_TO_AGENTGATE = {
    "bash": "Bash",
    "read": "Read",
    "write": "Write",
    "edit": "Edit",
    "git_commit": "Bash",
}


def aider_payload_to_event(payload: dict) -> dict:
    """Translate a synthetic Aider payload into AgentGate event schema.

    The payload is constructed by the launcher wrapper, not by Aider itself.
    Schema (one key per call type):
        {action: "bash", command: "pytest", cwd: "..."}
        {action: "read", path: "/etc/passwd"}
        {action: "write", path: "x.py", content: "..."}
        {action: "edit", path: "x.py", diff: "..."}
    """
    kind = payload.get("action", "bash")
    tool = _AIDER_TO_AGENTGATE.get(kind, "Bash")
    event = {
        "tool": tool,
        "agent": "aider",
        "cwd": payload.get("cwd"),
    }
    if kind in ("bash", "git_commit"):
        event["command"] = payload.get("command", "")
    elif kind in ("read", "write", "edit"):
        event["file_path"] = payload.get("path", "")
    else:
        # Unknown kind: best-effort — if the payload has command/path, use it.
        if "command" in payload:
            event["command"] = payload["command"]
        if "path" in payload:
            event["file_path"] = payload["path"]
    return event


def main() -> int:
    from .hook import evaluate_event
    payload_file = os.environ.get("AGENTGATE_PAYLOAD_FILE")
    if payload_file:
        payload = json.loads(Path(payload_file).read_text())
    else:
        payload = json.load(sys.stdin)
    event = aider_payload_to_event(payload)
    action, reason = evaluate_event(event, source="aider")
    print(json.dumps({"action": action.value, "reason": reason}))
    return 0


if __name__ == "__main__":
    sys.exit(main())