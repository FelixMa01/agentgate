"""Cursor hook adapter — reads Cursor's hook JSON and produces AgentGate events.

Cursor invokes a configured shell command before each tool call. The command
receives JSON on stdin and is expected to write a JSON response on stdout.
This is documented to be very similar to Claude Code's PreToolUse format, but
the exact event name / field set is not yet part of Cursor's public docs.

If Cursor's payload schema changes, only `_CURSOR_TO_AGENTGATE` needs updating.

Example payload (inferred from public community discussion):
    {
        "hook_event_name": "beforeShellExecution",
        "tool_name": "Shell",
        "tool_input": {"command": "rm -rf /etc"},
        "session_id": "...",
        "cwd": "..."
    }

The hook exits 0 with a JSON body, e.g.:
    {"decision": "deny", "reason": "..."}
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path


# Mapping from Cursor hook events → AgentGate event schema.
# Keys are read from the hook payload; values are the AgentGate event keys.
_CURSOR_TO_AGENTGATE: dict[str, dict[str, str]] = {
    "beforeShellExecution": {"tool_name": "Bash", "tool_input_key": "command"},
    "beforeFileEdit":       {"tool_name": "Edit", "tool_input_key": "file_path"},
    "beforeFileRead":       {"tool_name": "Read", "tool_input_key": "file_path"},
    "beforeMCPExecution":   {"tool_name": "MCP",  "tool_input_key": "request"},
}


def cursor_to_event(payload: dict) -> dict:
    """Translate a Cursor hook payload into AgentGate event schema."""
    event_name = payload.get("hook_event_name", "")
    mapping = _CURSOR_TO_AGENTGATE.get(event_name)
    if mapping is None:
        # Unknown / future event — pass through so logging still happens.
        return {
            "tool": payload.get("tool_name", "Unknown"),
            "agent": "cursor",
            "session_id": payload.get("session_id"),
            "cwd": payload.get("cwd"),
            "_raw_event_name": event_name,
            **payload.get("tool_input", {}),
        }
    tool_input = payload.get("tool_input", {})
    return {
        "tool": mapping["tool_name"],
        "command": tool_input.get(mapping["tool_input_key"]),
        "agent": "cursor",
        "session_id": payload.get("session_id"),
        "cwd": payload.get("cwd"),
    }


def render_response(decision: str, reason: str = "") -> dict:
    """Translate AgentGate's decision into Cursor's response shape."""
    out = {"decision": decision}
    if reason:
        out["reason"] = reason
    return out


def main() -> int:
    from .hook import evaluate_event  # reuse the main hook runner
    payload_file = os.environ.get("AGENTGATE_PAYLOAD_FILE")
    if payload_file:
        payload = json.loads(Path(payload_file).read_text())
    else:
        payload = json.load(sys.stdin)
    event = cursor_to_event(payload)
    action, reason = evaluate_event(event, source="cursor")
    print(json.dumps(render_response(action.value, reason)))
    return 0


if __name__ == "__main__":
    sys.exit(main())