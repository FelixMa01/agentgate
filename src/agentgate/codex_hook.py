"""Codex CLI hook adapter.

OpenAI Codex CLI (https://github.com/openai/codex) supports a hooks system
similar to Claude Code's. The `Before` tool hook fires before every
shell command, and the wire format is JSON on stdin:

    {
      "hook_event_name": "Before",
      "tool_name": "shell" | "apply_patch" | "read_file" | ...,
      "tool_input": {"command": "..."} | {"path": "...", "content": "..."},
      "session_id": "...",
      "cwd": "...",
      "agent_id": "..."
    }

Codex CLI's response contract (per https://docs/codex-cli/hooks):
    {"decision": "allow" | "deny" | "ask", "reason": "..."}

Wiring (project-local):
    codex/hooks.json:
        {
          "hooks": {
            "Before": [
              {
                "matcher": ".*",
                "hooks": [{"type": "command", "command": "agentgate-codex-hook"}]
              }
            ]
          }
        }

`agentgate install-codex-hook` writes this file for you.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .hook import EXTRA_FIELDS


def codex_payload_to_event(payload: dict) -> tuple[dict, str, str | None]:
    """Translate a Codex CLI Before payload to AgentGate event schema.

    Codex payload shape:
        {
          "hook_event_name": "Before",
          "session_id": "...",
          "cwd": "...",
          "agent_id": "...",
          "tool_name": "shell" | "apply_patch" | "read_file" | ...,
          "tool_input": {"command": "..."}  # shape depends on tool_name
        }

    Returns (event, tool_name, agent_label) — same contract as Claude Code's
    translator.
    """
    tool = payload.get("tool_name", "Unknown")
    tool_input = payload.get("tool_input", {}) if isinstance(payload.get("tool_input"), dict) else {}

    event: dict = {"tool": _codex_tool_to_agentgate(tool)}

    # Tool-name mapping: Codex names -> AgentGate names for consistent policy
    if tool == "shell":
        event["command"] = tool_input.get("command", "")
    elif tool == "apply_patch":
        # apply_patch is essentially a write/edit. The patch text goes under
        # 'content' so file_glob matches can see it.
        event["file"] = tool_input.get("path", "")
        event["content"] = tool_input.get("patch", "")
    elif tool in ("read_file", "view"):
        event["file"] = tool_input.get("path", "")
    elif tool == "list_dir":
        event["pattern"] = tool_input.get("path", "")
    elif tool == "web_fetch":
        event["url"] = tool_input.get("url", "")
    else:
        # Unknown tool: forward everything we have, best-effort.
        for key in ("command", "path", "url", "content"):
            if key in tool_input:
                agent_key = "file" if key == "path" else key
                event[agent_key] = tool_input[key]

    for k in EXTRA_FIELDS:
        if k in payload:
            event[k] = payload[k]

    agent_label = payload.get("agent_id") or payload.get("session_id") or "codex-cli"
    return event, event["tool"], agent_label


def _codex_tool_to_agentgate(codex_tool: str) -> str:
    """Map Codex CLI tool names onto AgentGate's vocabulary so a single
    policy.yaml matches both agents without per-agent rule duplication."""
    return {
        "shell": "Bash",
        "apply_patch": "Edit",
        "read_file": "Read",
        "view": "Read",
        "list_dir": "Glob",
        "web_fetch": "WebFetch",
        "grep_files": "Grep",
    }.get(codex_tool, codex_tool)


def decision_to_codex_response(action_value: str, reason: str | None) -> dict:
    """Map AgentGate action -> Codex CLI Before JSON output.

    Codex CLI accepts {decision: allow|deny|ask, reason: ...}.
    """
    decision = action_value if action_value in ("allow", "deny", "ask") else "deny"
    out: dict = {"decision": decision}
    if reason:
        out["reason"] = reason
    return out


def main() -> int:
    from .hook import evaluate_event

    payload_file = os.environ.get("AGENTGATE_PAYLOAD_FILE")
    payload = json.loads(Path(payload_file).read_text()) if payload_file else json.load(sys.stdin)
    event, _tool, _agent = codex_payload_to_event(payload)
    action, reason = evaluate_event(event, source="codex-cli")
    out = decision_to_codex_response(action.value, reason)
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
