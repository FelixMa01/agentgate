"""Minimal MCP stdio server exposing AgentGate tools.

Speaks JSON-RPC 2.0 over stdin/stdout. Tools:
- policy_lookup(event) — run an event through a policy
- audit_recent(limit, action?, since?) — list recent audit events
- audit_count(action?) — count events by action
- policy_test_tool(tool_name) — list policy rules that match a tool

The server reads requests from stdin (one JSON object per line) and writes
responses on stdout. Set AGENTGATE_POLICY and AGENTGATE_DB env vars.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

from .audit import Audit
from .policy import Action, load_policy


def _read_message(stream) -> dict | None:
    """Read one JSON object from the stream (any line containing JSON)."""
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return {"error": "invalid_json", "raw": line[:200]}
    return None


def _result(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


TOOLS = [
    {
        "name": "policy_lookup",
        "description": "Run an event through the loaded policy and return the decision.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event": {"type": "object", "description": "Event dict with tool, command, file, url, etc."},
            },
            "required": ["event"],
        },
    },
    {
        "name": "audit_recent",
        "description": "List recent audit events.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 20, "minimum": 1, "maximum": 500},
                "action": {"type": "string", "enum": ["allow", "ask", "deny"]},
                "since": {"type": "string", "description": "ISO timestamp; only events after this."},
            },
        },
    },
    {
        "name": "audit_count",
        "description": "Count events by action (and optionally source).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["allow", "ask", "deny"]},
            },
        },
    },
    {
        "name": "policy_test_tool",
        "description": "List all policy rules whose match references the given tool name.",
        "inputSchema": {
            "type": "object",
            "properties": {"tool_name": {"type": "string"}},
            "required": ["tool_name"],
        },
    },
]


def handle_initialize(req_id: Any) -> dict:
    return _result(req_id, {
        "protocolVersion": "2024-11-05",
        "serverInfo": {"name": "agentgate", "version": "0.9.0"},
        "capabilities": {"tools": {}},
    })


def handle_list_tools(req_id: Any) -> dict:
    return _result(req_id, {"tools": TOOLS})


def _policy_and_db():
    """Load policy + open audit db from env, or raise ValueError."""
    policy_path = os.environ.get("AGENTGATE_POLICY")
    db_path = os.environ.get("AGENTGATE_DB")
    if not policy_path or not db_path:
        raise ValueError("AGENTGATE_POLICY and AGENTGATE_DB must be set in env")
    return load_policy(policy_path), Audit(db_path)


def handle_call_tool(req_id: Any, params: dict) -> dict:
    name = params.get("name")
    args = params.get("arguments", {}) or {}
    try:
        policy, audit = _policy_and_db()
    except Exception as exc:
        return _error(req_id, -32000, str(exc))

    try:
        if name == "policy_lookup":
            event = args["event"]
            meta = policy.evaluate_with_meta(event)
            return _result(req_id, {
                "content": [{
                    "type": "text",
                    "text": json.dumps({
                        "decision": meta["effective_action"],
                        "raw_decision": meta["raw_action"],
                        "matched_rule": meta["rule_id"],
                        "rule_name": meta["rule_name"],
                        "reason": meta["rule_reason"],
                        "mode": meta["mode"],
                    }, indent=2),
                }],
            })
        elif name == "audit_recent":
            limit = int(args.get("limit", 20))
            action_str = args.get("action")
            since = args.get("since")
            action_enum = Action(action_str) if action_str else None
            rows = audit.recent(limit=limit, action=action_enum)
            if since:
                rows = [r for r in rows if r["ts"] >= since]
            return _result(req_id, {
                "content": [{"type": "text", "text": json.dumps([dict(r) for r in rows], default=str, indent=2)}],
            })
        elif name == "audit_count":
            counts = audit.counts_by_action(action=args.get("action"))
            return _result(req_id, {
                "content": [{"type": "text", "text": json.dumps(counts, indent=2)}],
            })
        elif name == "policy_test_tool":
            tool = args["tool_name"].lower()
            def _tool_matches(rule_tool):
                if isinstance(rule_tool, list):
                    return any(t.lower() == tool for t in rule_tool)
                return (rule_tool or "").lower() == tool
            matching = [r for r in policy.rules if _tool_matches(r.match.get("tool"))]
            return _result(req_id, {
                "content": [{"type": "text", "text": json.dumps(
                    [{"id": r.id, "action": str(r.action), "reason": r.reason} for r in matching],
                    indent=2,
                )}],
            })
        else:
            return _error(req_id, -32601, f"unknown tool: {name}")
    except KeyError as e:
        return _error(req_id, -32602, f"missing argument: {e}")
    except Exception as exc:
        return _error(req_id, -32603, f"tool error: {exc}")


def serve_stdio() -> None:
    """Main loop: read JSON-RPC requests from stdin, write responses on stdout."""
    stdin = sys.stdin
    stdout = sys.stdout
    for msg in stdin:
        msg = msg.strip()
        if not msg:
            continue
        try:
            req = json.loads(msg)
        except json.JSONDecodeError:
            stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        method = req.get("method")
        req_id = req.get("id")
        params = req.get("params", {}) or {}

        if method == "initialize":
            resp = handle_initialize(req_id)
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            resp = handle_list_tools(req_id)
        elif method == "tools/call":
            resp = handle_call_tool(req_id, params)
        elif method == "ping":
            resp = _result(req_id, {})
        else:
            resp = _error(req_id, -32601, f"method not found: {method}")
        stdout.write(json.dumps(resp) + "\n")
        stdout.flush()


if __name__ == "__main__":
    serve_stdio()
