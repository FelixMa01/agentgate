"""Tests for v0.12.0 features: Codex CLI hook, CEL `when`, env manager,
token-bucket rate limiter, coverage report, Discord notify."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import urllib.error
from pathlib import Path
from unittest.mock import patch as mock_patch

import pytest

# === F2: CEL-lite =====================================================

def test_cel_basic_equality():
    from agentgate.policy import evaluate_cel
    assert evaluate_cel('event.tool == "Bash"', {"tool": "Bash"})
    assert not evaluate_cel('event.tool == "Bash"', {"tool": "Read"})


def test_cel_and_combination():
    from agentgate.policy import evaluate_cel
    expr = 'event.cwd == "/srv" and event.tool == "Bash"'
    assert evaluate_cel(expr, {"cwd": "/srv", "tool": "Bash"})
    assert not evaluate_cel(expr, {"cwd": "/srv", "tool": "Read"})
    assert not evaluate_cel(expr, {"cwd": "/tmp", "tool": "Bash"})


def test_cel_in_with_list_literal():
    from agentgate.policy import evaluate_cel
    assert evaluate_cel('event.x in [1,2,3]', {"x": 2})
    assert evaluate_cel('event.x not in [1,2,3]', {"x": 5})


def test_cel_chained_comparison():
    from agentgate.policy import evaluate_cel
    assert evaluate_cel("1 < 2 < 3", {})
    assert not evaluate_cel("1 < 2 < 1", {})


def test_cel_uncomparable_returns_false():
    from agentgate.policy import evaluate_cel
    # "abc" > 5 raises TypeError; we fail-closed (False).
    assert not evaluate_cel('event.foo > 5', {"foo": "bar"})


def test_rule_when_skips_match():
    """A rule with `when:` only fires when the condition is true."""
    from agentgate.policy import Action, Rule, load_policy
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write("""
version: 1
default_action: allow
rules:
  - id: gated-deny
    match: {tool: Read, file: /etc/passwd}
    action: deny
    when: 'event.cwd != "/srv"'
""")
        path = f.name
    pol = load_policy(path)
    e = {"tool": "Read", "file": "/etc/passwd", "cwd": "/srv"}
    # cwd == "/srv" -> when is False -> rule skips -> default allow
    assert pol.evaluate(e)[0] == Action.ALLOW
    e2 = dict(e, cwd="/tmp")
    # cwd != "/srv" -> when is True -> rule fires -> deny
    assert pol.evaluate(e2)[0] == Action.DENY


# === F5: rate limiter =================================================

def test_rate_limit_allows_burst_then_drops():
    from agentgate.policy import Action, load_policy
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write("""
version: 1
default: deny
rules:
  - id: ask-twice
    match: {tool: Bash}
    action: ask
    rate_limit: {capacity: 2, refill_per_sec: 0.0}
""")
        path = f.name
    pol = load_policy(path)
    e = {"tool": "Bash", "command": "ls"}
    assert pol.evaluate(e)[0] == Action.ASK
    assert pol.evaluate(e)[0] == Action.ASK
    # Third call: bucket empty, rule skipped -> default deny
    assert pol.evaluate(e)[0] == Action.DENY


def test_rate_limit_deny_rules_unaffected():
    """Deny rules must not be subject to rate limits."""
    from agentgate.policy import Action, load_policy
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write("""
version: 1
default: allow
rules:
  - id: deny-rm
    match: {tool: Bash, command_regex: 'rm -rf.*'}
    action: deny
    rate_limit: {capacity: 1, refill_per_sec: 0.0}
""")
        path = f.name
    pol = load_policy(path)
    e = {"tool": "Bash", "command": "rm -rf /"}
    # Even after bucket empty, deny still fires.
    for _ in range(5):
        assert pol.evaluate(e)[0] == Action.DENY


# === F1: Codex CLI hook ===============================================

def test_codex_shell_translates_to_bash():
    from agentgate.codex_hook import codex_payload_to_event
    payload = {
        "hook_event_name": "Before",
        "session_id": "sess-x",
        "cwd": "/home/x",
        "agent_id": "codex-1",
        "tool_name": "shell",
        "tool_input": {"command": "ls -la"},
    }
    event, tool, _agent = codex_payload_to_event(payload)
    assert tool == "Bash"
    assert event["command"] == "ls -la"
    assert event["session_id"] == "sess-x"


def test_codex_apply_patch_translates_to_edit():
    from agentgate.codex_hook import codex_payload_to_event
    payload = {
        "tool_name": "apply_patch",
        "tool_input": {"path": "/etc/passwd", "patch": "..."},
    }
    event, tool, _ = codex_payload_to_event(payload)
    assert tool == "Edit"
    assert event["file"] == "/etc/passwd"
    assert event["content"] == "..."


def test_codex_decision_response_shape():
    from agentgate.codex_hook import decision_to_codex_response
    assert decision_to_codex_response("deny", "blocked") == {"decision": "deny", "reason": "blocked"}
    assert decision_to_codex_response("ask", None) == {"decision": "ask"}


# === F4: env manager =================================================

def test_env_manager_add_use_active(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    from agentgate.environments import CONFIG_PATH, Environment, EnvironmentStore

    store = EnvironmentStore.load()
    store.set(Environment(name="dev", policy="p-dev.yaml", db="dev.db"))
    store.set(Environment(name="prod", policy="p-prod.yaml", db="prod.db", mode="enforce"))
    store.save()

    store2 = EnvironmentStore.load()
    assert set(store2.environments) == {"dev", "prod"}

    env = store2.use("prod")
    assert env.name == "prod"
    assert store2.active_name() == "prod"
    assert CONFIG_PATH.exists()


# === F6: coverage =====================================================

def test_coverage_finds_dead_rules(tmp_path: Path):
    from agentgate.coverage import analyze
    pol = tmp_path / "p.yaml"
    pol.write_text("""
version: 1
default: allow
rules:
  - id: allow-bash
    match: {tool: Bash}
    action: allow
  - id: deny-read-etc
    match: {tool: Read, file: /etc/passwd}
    action: deny
""")
    events = [
        {"tool": "Bash", "command": "ls"},
        {"tool": "Bash", "command": "pwd"},
    ]
    report = analyze(pol, events=events)
    assert report.rules_total == 2
    assert report.rules_matched == 1
    assert "deny-read-etc" in report.rules_dead


def test_coverage_finds_uncovered_tools(tmp_path: Path):
    from agentgate.coverage import analyze
    pol = tmp_path / "p.yaml"
    pol.write_text("""
version: 1
default: allow
rules:
  - id: allow-bash
    match: {tool: Bash}
    action: allow
""")
    events = [
        {"tool": "WebFetch", "url": "https://example.com"},
        {"tool": "WebFetch", "url": "https://other.com"},
    ]
    report = analyze(pol, events=events)
    assert any(t == "WebFetch" for t, _ in report.tools_uncovered)


# === F7: Discord notify ===============================================

def test_post_to_discord_truncates_long_message():
    from agentgate.notify import post_to_discord
    captured = {}
    class FakeResp:
        status = 204
        def read(self):
            return b""
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    def fake_urlopen(req, timeout=None):
        captured["body"] = json.loads(req.data)
        return FakeResp()
    with mock_patch("agentgate.notify.urllib.request.urlopen", side_effect=fake_urlopen):
        # 5000 chars > 1900 cap
        _ok, _msg = post_to_discord("http://example/hook", "x" * 5000)
    assert _ok is True
    assert captured["body"]["content"].endswith("\u2026 (truncated)")
    assert len(captured["body"]["content"]) <= 2000


def test_post_to_discord_handles_http_error():
    from agentgate.notify import post_to_discord
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 429, "Too Many", {}, None)
    with mock_patch("agentgate.notify.urllib.request.urlopen", side_effect=fake_urlopen):
        ok, msg = post_to_discord("http://example/hook", "hi")
    assert ok is False
    assert "429" in msg


def test_notify_ask_prefers_telegram_over_discord(tmp_path: Path, monkeypatch):
    """Telegram still wins over Discord (channel precedence)."""
    from agentgate import notify
    monkeypatch.setenv("AGENTGATE_TELEGRAM_BOT_TOKEN", "tok")
    monkeypatch.setenv("AGENTGATE_TELEGRAM_CHAT_ID", "123")
    monkeypatch.setenv("AGENTGATE_DISCORD_WEBHOOK", "http://discord/hook")

    calls = []
    def fake_post_telegram(*a, **kw):
        calls.append("telegram")
        return True, "ok"
    def fake_post_discord(*a, **kw):
        calls.append("discord")
        return True, "ok"
    with mock_patch.object(notify, "post_to_telegram", side_effect=fake_post_telegram), \
         mock_patch.object(notify, "post_to_discord", side_effect=fake_post_discord):
        result = notify.notify_ask("tok", "Bash", {"command": "ls"}, "r", "why")
    assert calls == ["telegram"]
    assert result == "telegram:ok"
