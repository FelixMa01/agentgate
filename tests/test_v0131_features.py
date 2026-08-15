"""Tests for v0.13.1 features: lint, templates, trace, benchmarks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentgate.benchmarks import VECTORS, run_bench
from agentgate.lint import LintSeverity, lint_policy
from agentgate.policy import Action, load_policy
from agentgate.templates import get_template, list_templates, render_template
from agentgate.trace import TraceRecorder, replay

# === B1: lint ==========================================================

def test_lint_clean_policy_has_no_findings():
    policy = {
        "version": 1,
        "default": "deny",
        "rules": [
            {"id": "allow-read", "match": {"tool": "Read"}, "action": "allow"},
            {"id": "deny-rm", "match": {"tool": "Bash", "command_regex": "rm"}, "action": "deny"},
        ],
    }
    assert lint_policy(policy) == []


def test_lint_flags_bad_action():
    policy = {"version": 1, "default": "allow", "rules": [
        {"id": "x", "match": {"tool": "Read"}, "action": "yeet"},
    ]}
    findings = lint_policy(policy)
    assert any(f.rule == "bad-action" for f in findings)


def test_lint_flags_unknown_tool():
    policy = {"version": 1, "default": "allow", "rules": [
        {"id": "x", "match": {"tool": "Wibble"}, "action": "allow"},
    ]}
    findings = lint_policy(policy)
    assert any(f.rule == "unknown-tool" for f in findings)


def test_lint_flags_shadowed_rule():
    policy = {"version": 1, "default": "allow", "rules": [
        {"id": "allow-read", "match": {"tool": "Read"}, "action": "allow"},
        {"id": "allow-read-all", "match": {"tool": "Read", "file_regex": ".*"}, "action": "allow"},
    ]}
    findings = lint_policy(policy)
    assert any(f.rule == "shadowed-rule" for f in findings)


def test_lint_flags_duplicate_ids():
    policy = {"version": 1, "default": "allow", "rules": [
        {"id": "dup", "match": {"tool": "Read"}, "action": "allow"},
        {"id": "dup", "match": {"tool": "Write"}, "action": "ask"},
    ]}
    findings = lint_policy(policy)
    assert any(f.rule == "duplicate-id" for f in findings)


def test_lint_flags_catchall_allow():
    policy = {"version": 1, "default": "ask", "rules": [
        {"id": "allow-everything", "match": {"tool": "*"}, "action": "allow"},
    ]}
    findings = lint_policy(policy)
    assert any(f.rule == "catchall-allow" for f in findings)


def test_lint_flags_network_contradiction():
    policy = {
        "version": 1, "default": "allow", "rules": [],
        "network": {"allowed_domains": ["x.com"], "blocked_domains": ["x.com"]},
    }
    findings = lint_policy(policy)
    assert any(f.rule == "network-domain-contradiction" for f in findings)


def test_lint_flags_cel_unknown_key():
    policy = {"version": 1, "default": "deny", "rules": [
        {"id": "x", "match": {"tool": "Bash"}, "action": "deny",
         "when": 'event.fictional_key == "x"'},
    ]}
    findings = lint_policy(policy)
    assert any(f.rule == "cel-unknown-key" for f in findings)


def test_lint_flags_bad_rate_limit():
    policy = {"version": 1, "default": "deny", "rules": [
        {"id": "x", "match": {"tool": "Bash"}, "action": "ask",
         "rate_limit": {"bogus": 1}},
    ]}
    findings = lint_policy(policy)
    assert any(f.rule == "bad-rate-limit-keys" for f in findings)


def test_lint_format_report_includes_counts():
    from agentgate.lint import format_report
    policy = {"version": 1, "default": "yeet", "rules": [
        {"id": "x", "match": {}, "action": "allow"},
    ]}
    findings = lint_policy(policy)
    out = format_report(findings)
    assert "errors" in out and "warnings" in out


# === B2: templates ====================================================

def test_templates_all_have_required_names():
    names = {t.name for t in list_templates()}
    assert {"yolo", "enterprise", "airgapped", "ci-cd", "pair-programming"}.issubset(names)


def test_template_renders_valid_yaml(tmp_path):
    for t in list_templates():
        yaml_text = render_template(t.name)
        import yaml as _y
        parsed = _y.safe_load(yaml_text)
        assert isinstance(parsed, dict)
        assert "rules" in parsed


def test_template_unknown_raises():
    with pytest.raises(ValueError):
        render_template("does-not-exist")


# === B3: trace ========================================================

def test_trace_recorder_save_load_round_trip(tmp_path):
    rec = TraceRecorder()
    rec.append(ts=1.0, tool="Bash", event={"tool": "Bash", "command": "ls"},
               decision="allow", rule_id="allow-read", rule_name="Allow Read", reason=None)
    rec.append(ts=2.0, tool="Bash", event={"tool": "Bash", "command": "rm -rf /"},
               decision="deny", rule_id="deny-rm", rule_name="Deny rm", reason="destructive")
    path = tmp_path / "trace.jsonl"
    rec.save(path)
    assert path.exists()
    lines = path.read_text().strip().split("\n")
    assert len(lines) == 2
    entry = json.loads(lines[0])
    assert entry["tool"] == "Bash"
    assert entry["decision"] == "allow"


def test_replay_matches_recorded_with_same_policy(tmp_path):
    from agentgate.benchmarks import _default_policy
    pol = _default_policy()
    rec = TraceRecorder()
    for v in VECTORS[:5]:
        result = pol.evaluate(v.event)
        action = result[0]
        rid = result[1].id if len(result) > 1 and result[1] else None
        rname = result[2] if len(result) > 2 else None
        reason = result[3] if len(result) > 3 else None
        rec.append(
            ts=0.0, tool=v.event.get("tool", "?"),
            event=v.event, decision=action.value,
            rule_id=rid, rule_name=rname, reason=reason,
        )
    trace = tmp_path / "trace.jsonl"
    rec.save(trace)
    divs = replay(trace, pol)
    assert divs == []


def test_replay_detects_divergence(tmp_path):
    from agentgate.benchmarks import _default_policy
    rec = TraceRecorder()
    rec.append(ts=0.0, tool="Bash", event={"tool": "Bash", "command": "ls"},
               decision="allow", rule_id=None, rule_name=None, reason=None)
    trace = tmp_path / "trace.jsonl"
    rec.save(trace)
    # Use a strict policy that would deny "ls"
    from agentgate.policy import Policy, Rule
    strict = Policy(version=1, default_action=Action.DENY, rules=[
        Rule(id="deny-anything", match={"tool": "Bash"}, action=Action.DENY),
    ])
    divs = replay(trace, strict)
    assert len(divs) == 1
    assert divs[0].recorded == "allow"
    assert divs[0].replayed == "deny"


# === B4: benchmarks ===================================================

def test_bench_runs_with_default_policy():
    summary = run_bench()
    assert summary["total"] == len(VECTORS)
    # Should be high — at least 80% accuracy on the curated set.
    assert summary["accuracy"] >= 0.80, f"only {summary['accuracy']*100:.1f}% accuracy"


def test_bench_catches_destructive():
    summary = run_bench()
    destructive_names = [v.name for v in VECTORS if v.category == "destructive"]
    failures = {f["name"] for f in summary["failures"]}
    missed = [n for n in destructive_names if n in failures]
    assert not missed, f"missed destructive ops: {missed}"


def test_bench_catches_exfiltration():
    summary = run_bench()
    exfil_names = [v.name for v in VECTORS if v.category == "exfil"]
    failures = {f["name"] for f in summary["failures"]}
    missed = [n for n in exfil_names if n in failures]
    assert not missed, f"missed exfil: {missed}"


def test_bench_exempts_provider_hosts():
    summary = run_bench()
    failures = {f["name"] for f in summary["failures"]}
    assert "anthropic-self-call" not in failures
    assert "openai-self-call" not in failures
