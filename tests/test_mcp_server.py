"""Tests for the MCP stdio server (handle_* pure functions)."""
import json
import os
import sys

import pytest

sys.path.insert(0, "/Users/macbookm4air32g/projects/agentgate/src")
from agentgate import mcp_server

NL = chr(10)  # newline
POLICY_TEXT = (
    'version: 1' + NL
    + 'default_action: ask' + NL
    + 'rules:' + NL
    + '  - id: deny-rm' + NL
    + '    match:' + NL
    + '      tool: Bash' + NL
    + '      command_regex: "rm' + chr(92) + chr(92) + 's+"' + NL
    + '    action: deny' + NL
    + '    reason: rm blocked' + NL
    + '  - id: allow-reads' + NL
    + '    match:' + NL
    + '      tool: [Read, Glob, Grep]' + NL
    + '    action: allow' + NL
    + '    reason: read-only' + NL
    + ''
)



@pytest.fixture
def policy_and_db(tmp_path, monkeypatch):
    policy = tmp_path / "policy.yaml"
    db = tmp_path / "audit.db"
    policy.write_text(POLICY_TEXT)
    monkeypatch.setenv("AGENTGATE_POLICY", str(policy))
    monkeypatch.setenv("AGENTGATE_DB", str(db))
    return policy, db


def test_initialize_returns_protocol_info():
    resp = mcp_server.handle_initialize(1)
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 1
    assert resp["result"]["serverInfo"]["name"] == "agentgate"
    assert "protocolVersion" in resp["result"]


def test_list_tools_includes_all_four():
    resp = mcp_server.handle_list_tools(2)
    names = {t["name"] for t in resp["result"]["tools"]}
    assert names == {"policy_lookup", "audit_recent", "audit_count", "policy_test_tool"}


def test_policy_lookup_deny(policy_and_db):
    resp = mcp_server.handle_call_tool(3, {
        "name": "policy_lookup",
        "arguments": {"event": {"tool": "Bash", "command": "rm -rf /"}},
    })
    body = json.loads(resp["result"]["content"][0]["text"])
    assert body["decision"] == "deny"
    assert body["matched_rule"] == "deny-rm"


def test_policy_lookup_default_ask(policy_and_db):
    resp = mcp_server.handle_call_tool(4, {
        "name": "policy_lookup",
        "arguments": {"event": {"tool": "Bash", "command": "ls -la"}},
    })
    body = json.loads(resp["result"]["content"][0]["text"])
    assert body["decision"] in ("ask", "allow")


def test_policy_test_tool_finds_rule(policy_and_db):
    resp = mcp_server.handle_call_tool(5, {
        "name": "policy_test_tool",
        "arguments": {"tool_name": "Bash"},
    })
    rules = json.loads(resp["result"]["content"][0]["text"])
    assert any(r["id"] == "deny-rm" for r in rules)


def test_audit_count_empty_db(policy_and_db):
    resp = mcp_server.handle_call_tool(6, {"name": "audit_count", "arguments": {}})
    assert json.loads(resp["result"]["content"][0]["text"]) == {}


def test_audit_count_after_record(policy_and_db):
    from agentgate.audit import Audit
    from agentgate.policy import Action
    audit = Audit(os.environ["AGENTGATE_DB"])
    audit.record(source="test", agent="x", action=Action.DENY,
                 event={"tool": "Bash", "command": "rm"}, rule_id="deny-rm",
                 rule_name="deny-rm", reason="x")
    resp = mcp_server.handle_call_tool(7, {"name": "audit_count", "arguments": {}})
    counts = json.loads(resp["result"]["content"][0]["text"])
    assert counts.get("deny") == 1


def test_audit_recent_returns_recorded(policy_and_db):
    from agentgate.audit import Audit
    from agentgate.policy import Action
    audit = Audit(os.environ["AGENTGATE_DB"])
    audit.record(source="test", agent="x", action=Action.ASK,
                 event={"tool": "Bash", "command": "ls"}, rule_id="r1",
                 rule_name="r1", reason="x")
    resp = mcp_server.handle_call_tool(8, {"name": "audit_recent", "arguments": {"limit": 10}})
    events = json.loads(resp["result"]["content"][0]["text"])
    assert len(events) >= 1
    assert events[0]["agent"] == "x"


def test_unknown_tool_returns_error():
    resp = mcp_server.handle_call_tool(9, {"name": "nope", "arguments": {}})
    assert "error" in resp


def test_missing_env_raises(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENTGATE_POLICY", raising=False)
    monkeypatch.delenv("AGENTGATE_DB", raising=False)
    resp = mcp_server.handle_call_tool(10, {"name": "policy_lookup", "arguments": {"event": {"tool": "Bash"}}})
    assert "error" in resp
