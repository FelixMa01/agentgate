"""Gemini CLI hook adapter.

Gemini CLI (https://github.com/google-gemini/gemini-cli) uses hooks for
tool-call interception. The BeforeTool event sends a JSON payload similar to
Claude Code's PreToolUse, but with two key differences:

  - hook_event_name is "BeforeTool" (not "PreToolUse")
  - tool input is nested directly, not under "tool_input"

The Gemini CLI hook contract allows a Python script to be wired in via
~/.gemini/settings.json:

    {
      "hooks": {
        "BeforeTool": [
          {
            "matcher": ".*",
            "hooks": [{"type": "command", "command": "agentgate-gemini-hook"}]
          }
        ]
      }
    }

Wiring:
    agentgate install-gemini-hook
        writes ~/.gemini/settings.json (or a project-local override)
        and points the BeforeTool hook at the agentgate-gemini-hook launcher.

Response format Gemini CLI accepts (from the hook SDK contract):
  {"decision": "allow|deny|block", "reason": "..."}
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .hook import EXTRA_FIELDS


def gemini_payload_to_event(payload: dict) -> tuple[dict, str, str | None]:
    """Translate a Gemini CLI BeforeTool payload to AgentGate event schema.

    Gemini CLI payload shape (per hooks docs):
        {
          "session_id": "...",
          "transcript_path": "...",
          "cwd": "...",
          "hook_event_name": "BeforeTool",
          "tool_name": "run_shell_command" | "read_file" | ...,
          "tool_input": {...}     # NOTE: present in Gemini >=0.5
        }

    Some older Gemini versions nest params under a different key; we accept
    both for forward-compat.

    Returns (event, tool_name, agent_label) — same contract as Claude Code's
    translator in .hook.
    """
    tool = payload.get("tool_name", "Unknown")
    # Gemini nests args either as "tool_input" (newer) or as the top-level
    # keys minus our metadata (older). Prefer tool_input when present.
    tool_input = (
        payload["tool_input"]
        if isinstance(payload.get("tool_input"), dict)
        else payload
    )

    event: dict = {"tool": tool}

    # Map common tool fields (mirrors hook.claude_event_to_agent_event)
    if "command" in tool_input:
        event["command"] = tool_input["command"]
    if "file_path" in tool_input:
        event["file"] = tool_input["file_path"]
    if "path" in tool_input:
        event["file"] = tool_input["path"]
    if "pattern" in tool_input:
        event["pattern"] = tool_input["pattern"]
    if "url" in tool_input:
        event["url"] = tool_input["url"]
    if "content" in tool_input and tool in ("WriteFile", "EditFile", "Replace"):
        event["content"] = tool_input["content"]

    for k in EXTRA_FIELDS:
        if k in payload:
            event[k] = payload[k]

    agent_label = payload.get("agent_id") or payload.get("session_id") or "gemini-cli"
    return event, tool, agent_label


def decision_to_gemini_response(action_value: str, reason: str | None) -> dict:
    """Map AgentGate action -> Gemini CLI BeforeTool JSON output."""
    if action_value == "deny":
        decision = "block"
    elif action_value == "ask":
        decision = "block"  # Gemini CLI has no ask primitive — ASK maps to block
    else:
        decision = "allow"
    out: dict = {"decision": decision}
    if reason:
        out["reason"] = reason
    return out


def main() -> int:
    from .hook import evaluate_event

    payload_file = os.environ.get("AGENTGATE_PAYLOAD_FILE")
    payload = json.loads(Path(payload_file).read_text()) if payload_file else json.load(sys.stdin)
    event, _tool, _agent = gemini_payload_to_event(payload)
    action, reason = evaluate_event(event, source="gemini-cli")
    out = decision_to_gemini_response(action.value, reason)
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
