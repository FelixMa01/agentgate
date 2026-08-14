"""Continue.dev hook adapter.

Continue.dev (https://continue.dev) uses the same PreToolUse hook format as
Claude Code — the project's docs explicitly call this out as a feature:

    "Claude Code-compatible hooks system for Continue CLI."

So `agentgate install-hook` (which writes .claude/settings.local.json) works
out of the box. Continue.dev will read the same settings file.

This module provides:
- `continue_payload_to_event()` — convert Continue's payload to AgentGate event
  (mostly a no-op since formats match).
- A `bin/agentgate-continue-hook` launcher so users can wire it into
  `.continue/settings.json` for project-local config that doesn't pollute
  their Claude settings.
- `install-continue-hook` CLI command.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Continue.dev uses the same wire format as Claude Code for PreToolUse.
# We import the translator so the mapping is consistent.
from .hook import claude_event_to_agent_event


def continue_payload_to_event(payload: dict) -> tuple[dict, str, str | None]:
    """Translate a Continue.dev payload to AgentGate event schema.

    Continue.dev payload format is identical to Claude Code's:
        {"hook_event_name": "PreToolUse", "tool_name": "Bash",
         "tool_input": {"command": "..."}, "session_id": "...", "cwd": "..."}

    Returns (event, tool, agent) like the Claude Code translator.
    """
    return claude_event_to_agent_event(payload)


def main() -> int:
    from .hook import evaluate_event

    payload_file = os.environ.get("AGENTGATE_PAYLOAD_FILE")
    payload = json.loads(Path(payload_file).read_text()) if payload_file else json.load(sys.stdin)
    event, _tool, _agent = continue_payload_to_event(payload)
    action, reason = evaluate_event(event, source="continue")
    # Continue.dev uses the same response shape as Claude Code.
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": action.value,
        },
    }
    if reason:
        out["hookSpecificOutput"]["permissionDecisionReason"] = reason
        out["systemMessage"] = f"AgentGate: {action.value.upper()} \u2014 {reason}"
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
