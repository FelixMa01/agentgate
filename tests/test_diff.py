"""Tests for `agentgate policy diff` (diff_policies + CLI)."""
import json

import pytest
from click.testing import CliRunner

from agentgate.cli.cli_diff import diff_cmd, diff_policies
from agentgate.policy import load_policy


@pytest.fixture
def base_policy(tmp_path):
    p = tmp_path / "base.yaml"
    p.write_text(
        "version: 1\n"
        "default_action: allow\n"
        "rules:\n"
        "  - id: deny-rm\n"
        "    match:\n"
        "      tool: Bash\n"
        "      command_regex: 'rm\\s+'\n"
        "    action: deny\n"
        "    reason: rm blocked\n"
        "  - id: allow-reads\n"
        "    match:\n"
        "      tool: [Read, Glob, Grep]\n"
        "    action: allow\n"
        "    reason: read-only\n"
    )
    return load_policy(p)


@pytest.fixture
def modified_policy(tmp_path):
    p = tmp_path / "modified.yaml"
    # deny-rm -> ask-rm (relax), add allow-web, remove allow-reads
    p.write_text(
        "version: 1\n"
        "default_action: deny\n"
        "rules:\n"
        "  - id: ask-rm\n"
        "    match:\n"
        "      tool: Bash\n"
        "      command_regex: 'rm\\s+'\n"
        "    action: ask\n"
        "    reason: rm asks user\n"
        "  - id: allow-web\n"
        "    match:\n"
        "      tool: WebFetch\n"
        "    action: allow\n"
        "    reason: web allowed\n"
    )
    return load_policy(p)


def test_identical_policies_no_changes(tmp_path):
    p_text = (
        "version: 1\n"
        "default_action: allow\n"
        "rules:\n"
        "  - id: r1\n"
        "    match: {tool: Bash}\n"
        "    action: deny\n"
        "    reason: x\n"
    )
    pa = tmp_path / "a.yaml"
    pa.write_text(p_text)
    pb = tmp_path / "b.yaml"
    pb.write_text(p_text)
    diff = diff_policies(load_policy(pa), load_policy(pb))
    assert diff["decision_changes"] == []
    assert diff["rules_added"] == []
    assert diff["rules_removed"] == []
    assert diff["rules_changed"] == []


def test_rule_renamed_detected_as_change(base_policy, modified_policy):
    diff = diff_policies(base_policy, modified_policy)
    # deny-rm removed, ask-rm added — that's "removed" + "added", NOT a change
    assert "deny-rm" in diff["rules_removed"]
    assert "ask-rm" in diff["rules_added"]


def test_rule_modified_in_place_detected(tmp_path):
    pa_text = (
        "version: 1\n"
        "default_action: allow\n"
        "rules:\n"
        "  - id: r1\n"
        "    match: {tool: Bash}\n"
        "    action: deny\n"
        "    reason: a\n"
    )
    pb_text = (
        "version: 1\n"
        "default_action: allow\n"
        "rules:\n"
        "  - id: r1\n"
        "    match: {tool: Bash}\n"
        "    action: ask\n"
        "    reason: b\n"
    )
    pa = tmp_path / "a.yaml"
    pa.write_text(pa_text)
    pb = tmp_path / "b.yaml"
    pb.write_text(pb_text)
    diff = diff_policies(load_policy(pa), load_policy(pb))
    assert any(c["field"] == "action" and c["old"] == "deny" and c["new"] == "ask"
               for c in diff["rules_changed"])
    assert any(c["field"] == "reason" and c["old"] == "a" and c["new"] == "b"
               for c in diff["rules_changed"])


def test_decision_change_when_default_action_changes(base_policy, modified_policy):
    diff = diff_policies(base_policy, modified_policy)
    # default_action: allow -> deny affects every event with no rule match
    assert any(c["event"]["tool"] == "Write" for c in diff["decision_changes"])
    assert any(c["event"]["tool"] == "Edit" for c in diff["decision_changes"])


def test_decision_change_when_rule_relaxes(base_policy, modified_policy):
    diff = diff_policies(base_policy, modified_policy)
    # rm -rf /tmp/foo: was deny (deny-rm), now ask (ask-rm)
    rm_change = next((c for c in diff["decision_changes"]
                      if c["event"].get("command", "").startswith("rm")), None)
    assert rm_change is not None, f"no rm change found: {diff}"
    assert rm_change["old_action"] == "deny"
    assert rm_change["new_action"] == "ask"


def test_custom_canary_events(base_policy, modified_policy):
    custom = [{"tool": "Bash", "command": "echo hi"}]
    diff = diff_policies(base_policy, modified_policy, canary_events=custom)
    # Only echo in canary — may or may not change. Just assert structure.
    assert isinstance(diff["decision_changes"], list)


def test_cli_diff_text_output(base_policy, modified_policy, tmp_path):
    pa = tmp_path / "a.yaml"
    pb = tmp_path / "b.yaml"
    # Save policies to disk for the CLI to load
    pa.write_text(_policy_text(base_policy))
    pb.write_text(_policy_text(modified_policy))
    runner = CliRunner()
    result = runner.invoke(diff_cmd, [str(pa), str(pb)])
    assert result.exit_code == 0, result.output
    assert "Decision changes:" in result.output
    assert "Rules added" in result.output
    assert "Rules removed" in result.output


def test_cli_diff_json_output(base_policy, modified_policy, tmp_path):
    pa = tmp_path / "a.yaml"
    pb = tmp_path / "b.yaml"
    pa.write_text(_policy_text(base_policy))
    pb.write_text(_policy_text(modified_policy))
    runner = CliRunner()
    result = runner.invoke(diff_cmd, [str(pa), str(pb), "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert "decision_changes" in data
    assert "rules_added" in data
    assert "rules_removed" in data
    assert "rules_changed" in data


def _policy_text(p):
    """Serialize Policy back to YAML (for CLI fixtures)."""
    import yaml
    return yaml.safe_dump({
        "version": p.version,
        "default_action": str(p.default_action),
        "rules": [
            {"id": r.id, "match": dict(r.match), "action": str(r.action), "reason": r.reason}
            for r in p.rules
        ],
    }, sort_keys=False)
