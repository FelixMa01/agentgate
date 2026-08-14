"""AgentGate hook — runs as a Claude Code PreToolUse hook.

Reads JSON from stdin (Claude Code's hook payload), maps it to our event
schema, evaluates the policy, records the decision in the audit DB, and
writes the JSON response Claude Code reads on stdout.

Schema mapping:
    Claude Code input            -> AgentGate event
    -----------------------------    ---------------------------
    tool_name                    -> tool
    tool_input.command           -> command
    tool_input.file_path         -> file
    tool_input.content           -> content
    tool_input.pattern           -> pattern (Grep/Glob)
    tool_input.url               -> url (WebFetch)
    session_id                   -> session_id
    cwd                          -> cwd
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path

from .audit import Audit
from .policy import Action, load_policy


# Fields we propagate into the audit log if present.
EXTRA_FIELDS = ("session_id", "cwd", "agent_id", "agent_type")


def claude_event_to_agent_event(payload: dict) -> tuple[dict, str, str | None]:
    """Translate a Claude Code PreToolUse payload to an AgentGate event.

    Returns (event_dict, tool_name, agent_label).
    """
    tool = payload.get("tool_name", "Unknown")
    tool_input = payload.get("tool_input") or {}
    event: dict = {"tool": tool}

    # Map common tool fields
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
    if "content" in tool_input and tool in ("Write", "Edit", "NotebookEdit"):
        event["content"] = tool_input["content"]

    # Propagate context
    for k in EXTRA_FIELDS:
        if k in payload:
            event[k] = payload[k]

    agent_label = payload.get("agent_id") or payload.get("session_id") or "claude-code"
    return event, tool, agent_label


def decision_to_cc_response(action: Action, reason: str | None) -> dict:
    """Map AgentGate action -> Claude Code PreToolUse JSON output."""
    if action == Action.DENY:
        decision = "deny"
    elif action == Action.ASK:
        decision = "ask"
    else:
        decision = "allow"
    out: dict = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
        }
    }
    if reason:
        out["hookSpecificOutput"]["permissionDecisionReason"] = reason
        # Surface to user too; systemMessage shows on stdout to terminal.
        out["systemMessage"] = f"AgentGate: {decision.upper()} — {reason}"
    return out


def main() -> int:
    policy_path = os.environ.get("AGENTGATE_POLICY")
    db_path = os.environ.get("AGENTGATE_DB")
    if not policy_path or not db_path:
        print(
            "AgentGate hook: AGENTGATE_POLICY and AGENTGATE_DB must be set",
            file=sys.stderr,
        )
        return 0  # fail open — let Claude proceed if misconfigured

    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        # Empty/invalid stdin: nothing to evaluate.
        return 0

    # Only handle PreToolUse; ignore other events (we shouldn't be called for them).
    if payload.get("hook_event_name") not in (None, "PreToolUse"):
        return 0

    event, tool, agent = claude_event_to_agent_event(payload)

    try:
        policy = load_policy(policy_path)
        audit = Audit(db_path)
    except Exception as exc:
        # Fail open on internal error so we don't block the agent.
        print(f"AgentGate: internal error ({exc}); failing open", file=sys.stderr)
        return 0

    action, rule = policy.evaluate(event)
    audit.record(
        source="claude-code",
        agent=agent,
        action=action,
        event=event,
        rule_id=rule.id if rule else None,
        rule_name=rule.name if rule else None,
        reason=rule.reason if rule else None,
    )
    reason = (rule.reason if rule else "") or (rule.name if rule else "")
    response = decision_to_cc_response(action, reason)
    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())