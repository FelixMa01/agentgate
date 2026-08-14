"""AgentGate hook — runs as a Claude Code PreToolUse hook.

Reads JSON from stdin (Claude Code's hook payload), maps it to our event
schema, evaluates the policy, records the decision in the audit DB, and
writes the JSON response Claude Code reads on stdout.

For ASK actions, notifies Slack (or a file fallback) and waits up to
AGENTGATE_ASK_TIMEOUT seconds (default 60) for a human to approve/deny
via the approval server (agentgate approval-server).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .approval import STORE
from .audit import Audit
from .notify import notify_ask
from .policy import Action, event_provenance, load_policy

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


def evaluate_event(event: dict, source: str = "claude-code") -> tuple[Action, str]:
    """Run policy + ASK flow for an AgentGate event, record audit rows,
    and return the final (action, reason). Returns ('allow', '') on misconfig.

    Shared between the Claude Code hook and the Cursor hook so both adapters
    funnel through the same policy + audit + approval flow.
    """
    policy_path = os.environ.get("AGENTGATE_POLICY")
    db_path = os.environ.get("AGENTGATE_DB")
    if not policy_path or not db_path:
        print("AgentGate: AGENTGATE_POLICY and AGENTGATE_DB must be set", file=sys.stderr)
        return Action.ALLOW, ""
    try:
        policy = load_policy(policy_path)
        audit = Audit(db_path)
    except Exception as exc:
        print(f"AgentGate: internal error ({exc}); failing open", file=sys.stderr)
        return Action.ALLOW, ""

    tool = event.get("tool", "?")
    action, rule = policy.evaluate(event)
    reason = (rule.reason if rule else "") or (rule.name if rule else "")
    agent = event.get("agent") or source

    if action == Action.ASK:
        ask = STORE.request(event, tool, rule.id if rule else None)
        prov = event_provenance(event, rule.id if rule else None)
        try:
            status = notify_ask(
                ask.token,
                tool,
                event,
                rule.name if rule else None,
                reason,
            )
        except Exception as exc:
            status = f"notify-error: {exc}"
        audit.record(
            source=source,
            agent=agent,
            action=Action.ASK,
            event={**event, "_ask_token": ask.token, "_notify": status, "_provenance": prov},
            rule_id=rule.id if rule else None,
            rule_name=rule.name if rule else None,
            reason=reason,
        )
        timeout = float(os.environ.get("AGENTGATE_ASK_TIMEOUT", "60"))
        decision = STORE.wait(ask.token, timeout=timeout)
        if decision is None:
            decision_str = "deny"
            timeout_note = f"AgentGate ASK timed out after {timeout:.0f}s → denied"
        else:
            decision_str = decision
            timeout_note = ""
        action = Action(decision_str)
        audit.record(
            source=source,
            agent=agent,
            action=action,
            event={**event, "_ask_token": ask.token, "_resolved": decision_str, "_provenance": prov},
            rule_id=rule.id if rule else None,
            rule_name=rule.name if rule else None,
            reason=(reason + " " + timeout_note).strip(),
        )
    else:
        audit.record(
            source=source,
            agent=agent,
            action=action,
            event=event,
            rule_id=rule.id if rule else None,
            rule_name=rule.name if rule else None,
            reason=reason or None,
        )
    return action, reason


def main() -> int:
    policy_path = os.environ.get("AGENTGATE_POLICY")
    db_path = os.environ.get("AGENTGATE_DB")
    if not policy_path or not db_path:
        print(
            "AgentGate hook: AGENTGATE_POLICY and AGENTGATE_DB must be set",
            file=sys.stderr,
        )
        return 0  # fail open — let Claude proceed if misconfigured

    # Read payload: stdin by default, or AGENTGATE_PAYLOAD_FILE for environments
    # where stdin is already consumed (background launches, harness tests).
    payload_file = os.environ.get("AGENTGATE_PAYLOAD_FILE")
    if payload_file:
        try:
            payload = json.loads(Path(payload_file).read_text())
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"AgentGate hook: cannot load payload file: {e}", file=sys.stderr)
            return 0
    else:
        try:
            payload = json.load(sys.stdin)
        except json.JSONDecodeError:
            # Empty/invalid stdin: nothing to evaluate.
            return 0

    # Only handle PreToolUse; ignore other events (we shouldn't be called for them).
    if payload.get("hook_event_name") not in (None, "PreToolUse"):
        return 0

    event, _tool, _agent = claude_event_to_agent_event(payload)
    action, reason = evaluate_event(event, source="claude-code")
    response = decision_to_cc_response(action, reason)
    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
