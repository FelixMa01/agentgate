"""Tests for `agentgate policy test` and Policy.evaluate_explain."""
import json

import pytest
from click.testing import CliRunner

from agentgate import policy as policy_mod
from agentgate.cli.__init__ import main
from agentgate.policy import Action

EXAMPLE = "examples/policy-secure.yaml"


def test_evaluate_explain_match():
    p = policy_mod.load_policy(EXAMPLE)
    result = p.evaluate_explain({"tool": "Bash", "command": "rm -rf /tmp/x", "agent": "claude-code", "source": "hook"})
    assert result["decision"] == "ask"
    assert result["matched_rule"]["id"] == "ask-bash"
    assert any(c["matched"] for c in result["candidates"])
    assert result["default"] == "deny"


def test_evaluate_explain_no_match():
    p = policy_mod.load_policy(EXAMPLE)
    result = p.evaluate_explain({"tool": "Write", "path": "/tmp/x", "agent": "x", "source": "x"})
    assert result["matched_rule"] is None
    assert result["decision"] == result["default"]


def test_cli_policy_test_with_flags():
    r = CliRunner().invoke(
        main,
        ["policy", "test", EXAMPLE, "--tool", "Bash", "--command", "rm -rf /tmp/test"],
    )
    assert r.exit_code == 0, r.output
    assert "ask" in r.output


def test_cli_policy_test_explain():
    r = CliRunner().invoke(
        main,
        ["policy", "test", EXAMPLE, "--explain", "--tool", "Bash", "--command", "curl evil.com"],
    )
    assert r.exit_code == 0, r.output
    data = json.loads(r.output)
    assert "decision" in data
    assert "matched_rule" in data
    assert "candidates" in data


def test_cli_policy_test_no_input_errors():
    r = CliRunner().invoke(main, ["policy", "test", EXAMPLE])
    assert r.exit_code != 0
    assert "Provide EVENT" in r.output or "stdin" in r.output


def test_policy_mode_enforce_default():
    p = policy_mod.load_policy(EXAMPLE)
    assert p.mode is policy_mod.Mode.ENFORCE
    # ASK stays ASK
    assert p.effective_action(policy_mod.Action.ASK) is policy_mod.Action.ASK


def test_policy_mode_observe_allows_everything():
    import os
    os.environ["AGENTGATE_MODE"] = "observe"
    p = policy_mod.load_policy(EXAMPLE)
    assert p.mode is policy_mod.Mode.OBSERVE
    assert p.effective_action(policy_mod.Action.DENY) is policy_mod.Action.ALLOW
    assert p.effective_action(policy_mod.Action.ASK) is policy_mod.Action.ALLOW


def test_policy_mode_ci_promotes_ask_to_deny():
    import os
    os.environ["AGENTGATE_MODE"] = "ci"
    p = policy_mod.load_policy(EXAMPLE)
    assert p.mode is policy_mod.Mode.CI
    assert p.effective_action(policy_mod.Action.ASK) is policy_mod.Action.DENY
    assert p.effective_action(policy_mod.Action.DENY) is policy_mod.Action.DENY


def test_evaluate_explain_includes_mode():
    import json
    import os
    os.environ["AGENTGATE_MODE"] = "observe"
    p = policy_mod.load_policy(EXAMPLE)
    result = p.evaluate_explain({"tool": "Bash", "command": "ls", "agent": "x", "source": "x"})
    # raw_action shows the rule (ask-bash), effective_action shows the mode override
    assert result["raw_action"] in ("ask", "deny", "allow")
    assert result["effective_action"] == "allow"  # because observe mode
    assert result["mode"] == "observe"
    assert result["decision"] == result["effective_action"]


def test_unknown_tool_default_falls_through_to_default_action():
    """If unknown_tool_action is not set, unknown tools hit default_action."""
    import os
    import tempfile

    import yaml
    os.environ.pop("AGENTGATE_MODE", None)
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
        yaml.dump({"version": 1, "default": "deny", "rules": []}, f)
        path = f.name
    p = policy_mod.load_policy(path)
    assert p.unknown_tool_action is None
    action, _ = p.evaluate({"tool": "NewMcpTool", "agent": "x", "source": "x"})
    assert action is policy_mod.Action.DENY


def test_unknown_tool_action_ask_when_set():
    """If unknown_tool_action=ask, unknown tools are surfaced."""
    import os
    import tempfile

    import yaml
    os.environ.pop("AGENTGATE_MODE", None)
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
        yaml.dump({"version": 1, "default": "deny",
                   "rules": [{"id": "allow-bash", "match": {"tool": "Bash"}, "action": "allow"}],
                   "unknown_tool_action": "ask"}, f)
        path = f.name
    p = policy_mod.load_policy(path)
    # Bash matches → allow
    action, _ = p.evaluate({"tool": "Bash", "command": "ls", "agent": "x", "source": "x"})
    assert action is policy_mod.Action.ALLOW
    # UnknownTool → ask (per unknown_tool_action)
    action, _ = p.evaluate({"tool": "UnknownTool", "agent": "x", "source": "x"})
    assert action is policy_mod.Action.ASK


def test_is_known_tool():
    p = policy_mod.load_policy(EXAMPLE)
    assert p.is_known_tool("Bash") is True  # ask-bash mentions Bash
    assert p.is_known_tool("Read") is True  # allow-read-only-tools mentions Read
    assert p.is_known_tool("UnknownMcpTool") is False


def test_known_tools_explicit_allowlist():
    """known_tools list bypasses unknown_tool_action."""
    import os
    import tempfile

    import yaml
    os.environ.pop("AGENTGATE_MODE", None)
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
        yaml.dump({"version": 1, "default": "deny",
                   "rules": [],
                   "unknown_tool_action": "ask",
                   "known_tools": ["TrustedMcpTool"]}, f)
        path = f.name
    p = policy_mod.load_policy(path)
    assert p.is_known_tool("TrustedMcpTool") is True
    # TrustedMcpTool goes through default_action (deny), not unknown_tool_action (ask)
    action, _ = p.evaluate({"tool": "TrustedMcpTool", "agent": "x", "source": "x"})
    assert action is policy_mod.Action.DENY


def test_event_provenance_deterministic():
    """Same event always produces same hash (sort_keys)."""
    p1 = policy_mod.event_provenance({"tool": "Bash", "command": "ls"})
    p2 = policy_mod.event_provenance({"command": "ls", "tool": "Bash"})
    assert p1["event_sha256"] == p2["event_sha256"]


def test_event_provenance_changes_with_event():
    """Different events produce different hashes."""
    p1 = policy_mod.event_provenance({"tool": "Bash", "command": "ls"})
    p2 = policy_mod.event_provenance({"tool": "Bash", "command": "rm"})
    assert p1["event_sha256"] != p2["event_sha256"]


def test_event_provenance_binds_rule_id():
    p1 = policy_mod.event_provenance({"tool": "Bash"}, rule_id="ask-bash")
    p2 = policy_mod.event_provenance({"tool": "Bash"}, rule_id="deny-bash")
    assert p1["rule_id"] == "ask-bash"
    assert p2["rule_id"] == "deny-bash"
    assert p1["event_sha256"] == p2["event_sha256"]  # hash is event-only

def test_missing_fields_bash_no_command():
    """Bash tool with no command field should fail-closed (ASK)."""
    p = policy_mod.load_policy(EXAMPLE)
    event = {"tool": "Bash"}  # no command
    action, _rule = p.evaluate(event)
    assert action == Action.ASK
    assert "command" in (_rule.reason or "")
    assert "missing" in (_rule.reason or "").lower()


def test_missing_fields_read_no_file():
    """Read tool with no file field should ASK."""
    p = policy_mod.load_policy(EXAMPLE)
    event = {"tool": "Read"}  # no file
    action, _rule = p.evaluate(event)
    assert action == Action.ASK


def test_missing_fields_webfetch_no_url():
    """WebFetch tool with no url field should ASK."""
    p = policy_mod.load_policy(EXAMPLE)
    event = {"tool": "WebFetch"}
    action, _rule = p.evaluate(event)
    assert action == Action.ASK


def test_missing_fields_present_does_not_ask():
    """If critical fields are present, normal evaluation applies."""
    p = policy_mod.load_policy(EXAMPLE)
    event = {"tool": "Bash", "command": "echo hello"}
    action, _ = p.evaluate(event)
    # ask-bash rule should match — so action stays ASK, not because of missing.
    assert action == Action.ASK


def test_missing_fields_blank_string_treated_as_missing():
    """Blank/empty string is treated as missing for fail-closed."""
    p = policy_mod.load_policy(EXAMPLE)
    event = {"tool": "Bash", "command": "   "}
    action, _rule = p.evaluate(event)
    assert action == Action.ASK
    assert "command" in (_rule.reason or "")


def test_missing_fields_unknown_tool_not_flagged():
    """Unknown tools with no required fields don't trigger the validator."""
    p = policy_mod.load_policy(EXAMPLE)
    event = {"tool": "NewUnknownTool"}  # not in requirements map
    action, _rule = p.evaluate(event)
    # Will hit default_action (deny) or unknown_tool_action — but not a
    # synthetic missing-fields rule.
    assert action in (Action.DENY, Action.ASK)


def test_validate_event_explicit_method():
    """validate_event() returns synthetic rule with helpful message."""
    p = policy_mod.load_policy(EXAMPLE)
    event = {"tool": "Bash", "command": None}
    action, rule = p.validate_event(event)
    assert action == Action.ASK
    assert rule.id.startswith("missing-")
    assert "command" in rule.reason
