"""Tests for v0.11.0 features: dry-run mode, PolicyWatcher, /metrics, gemini hook,
HMAC-signed webhooks, exponential backoff."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path

import pytest

from agentgate.policy import Mode, Policy, PolicyWatcher, load_policy
from agentgate.webhooks import (
    SIGNATURE_HEADER,
    Webhook,
    deliver,
    sign,
    verify_signature,
)

# ─── Dry-run mode ──────────────────────────────────────────────────────────────


def test_dry_run_mode_is_in_enum():
    assert Mode.DRY_RUN.value == "dry-run"


def test_dry_run_never_blocks_ask(tmp_path: Path):
    """Even ASK verdicts become ALLOW in dry-run so the agent keeps running."""
    from agentgate.policy import Action
    pol = Policy(rules=[], default_action=Action.ASK, mode=Mode.DRY_RUN)
    assert pol.effective_action(Action.ASK) is Action.ALLOW
    assert pol.effective_action(Action.DENY) is Action.ALLOW


def test_dry_run_from_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENTGATE_MODE", "dry-run")
    assert Mode.from_env() is Mode.DRY_RUN


# ─── PolicyWatcher (hot reload) ────────────────────────────────────────────────


def test_watcher_loads_on_init(tmp_path: Path):
    pol_path = tmp_path / "policy.yaml"
    pol_path.write_text("version: 1\ndefault_action: allow\nrules: []\n")
    w = PolicyWatcher(pol_path)
    assert w.policy.default_action.value == "allow"
    assert not w.changed()


def test_watcher_detects_mtime_change(tmp_path: Path):
    pol_path = tmp_path / "policy.yaml"
    pol_path.write_text("version: 1\ndefault_action: allow\nrules: []\n")
    w = PolicyWatcher(pol_path)
    # Touch with a future mtime
    future = time.time() + 5
    import os
    os.utime(pol_path, (future, future))
    assert w.changed()
    w.reload()
    assert not w.changed()


def test_watcher_picks_up_new_rule(tmp_path: Path):
    pol_path = tmp_path / "policy.yaml"
    pol_path.write_text("version: 1\ndefault_action: allow\nrules: []\n")
    w = PolicyWatcher(pol_path)
    assert len(w.policy.rules) == 0
    pol_path.write_text(
        "version: 1\ndefault_action: allow\n"
        "rules:\n  - id: r1\n    match: {tool: Bash}\n    action: deny\n"
    )
    # mtime change
    future = time.time() + 5
    import os
    os.utime(pol_path, (future, future))
    new_pol = w.maybe_reload()
    assert len(new_pol.rules) == 1


def test_watcher_missing_file_does_not_crash(tmp_path: Path):
    pol_path = tmp_path / "policy.yaml"
    pol_path.write_text("version: 1\ndefault_action: allow\nrules: []\n")
    w = PolicyWatcher(pol_path)
    pol_path.unlink()
    assert not w.changed()  # missing file returns False, doesn't throw


# ─── Webhook HMAC signing ──────────────────────────────────────────────────────


def test_sign_produces_stable_hex():
    secret = "shh"
    body = b'{"event":"x"}'
    h1 = sign(secret, body)
    h2 = sign(secret, body)
    assert h1 == h2
    assert h1.startswith("sha256=")
    assert len(h1) == len("sha256=") + 64  # sha256 hex


def test_verify_signature_accepts_correct():
    secret = "shh"
    body = b'{"event":"x"}'
    assert verify_signature(secret, body, sign(secret, body)) is True


def test_verify_signature_rejects_wrong():
    secret = "shh"
    body = b'{"event":"x"}'
    assert verify_signature(secret, body, sign("wrong", body)) is False
    assert verify_signature(secret, body, "") is False


def test_deliver_signs_when_secret_set(monkeypatch: pytest.MonkeyPatch):
    """When a webhook has a secret, the request includes X-AgentGate-Signature."""
    from agentgate.webhooks import deliver

    captured: dict = {}

    def fake_urlopen(req, timeout=5.0):
        captured["headers"] = dict(req.headers)
        captured["body"] = req.data

        class R:
            status = 200

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False

        return R()

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    wh = Webhook(name="signed", url="http://example.com", on={"action": "deny"}, secret="topsecret")
    deliver({"action": "deny", "rule_id": "r1", "rule_name": "n", "source": "s",
             "agent": "a", "reason": "x"}, webhooks=[wh], base_backoff=0)
    # urllib canonicalizes header names to lowercase
    headers_lc = {k.lower(): v for k, v in captured["headers"].items()}
    assert SIGNATURE_HEADER.lower() in headers_lc
    body = captured["body"]
    header = headers_lc[SIGNATURE_HEADER.lower()]
    assert verify_signature("topsecret", body, header)


def test_deliver_unsigned_when_no_secret(monkeypatch: pytest.MonkeyPatch):
    """No secret → no signature header."""
    captured: dict = {}

    def fake_urlopen(req, timeout=5.0):
        captured["headers"] = dict(req.headers)

        class R:
            status = 200

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False

        return R()

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    wh = Webhook(name="plain", url="http://example.com", on={"action": "deny"})
    deliver({"action": "deny", "rule_id": "r1", "rule_name": "n", "source": "s",
             "agent": "a", "reason": "x"}, webhooks=[wh], base_backoff=0)
    headers_lc = {k.lower(): v for k, v in captured["headers"].items()}
    assert SIGNATURE_HEADER.lower() not in headers_lc


def test_deliver_exponential_backoff(monkeypatch: pytest.MonkeyPatch):
    """Failed deliveries retry with exponential backoff."""
    sleeps: list[float] = []

    def fake_sleep(s: float) -> None:
        sleeps.append(s)

    import agentgate.webhooks as wh_mod
    monkeypatch.setattr(wh_mod.time, "sleep", fake_sleep)

    call_count = {"n": 0}

    def always_fail(req, timeout=5.0):
        call_count["n"] += 1
        raise OSError("nope")

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", always_fail)
    wh = Webhook(name="fail", url="http://x", on={"action": "deny"})
    results = deliver({"action": "deny"}, webhooks=[wh], max_attempts=4, base_backoff=1.0)
    assert call_count["n"] == 4
    # 4 attempts → 3 sleeps: 1.0, 2.0, 4.0
    assert sleeps == [1.0, 2.0, 4.0]
    assert results == [("fail", False, "nope")]


# ─── Gemini CLI hook translation ───────────────────────────────────────────────


def test_gemini_payload_translation():
    from agentgate.gemini_hook import gemini_payload_to_event

    payload = {
        "hook_event_name": "BeforeTool",
        "session_id": "sess-1",
        "cwd": "/tmp",
        "tool_name": "run_shell_command",
        "tool_input": {"command": "echo hi"},
    }
    event, tool, agent = gemini_payload_to_event(payload)
    assert tool == "run_shell_command"
    assert event["command"] == "echo hi"
    assert event["tool"] == "run_shell_command"
    assert event["session_id"] == "sess-1"
    assert agent == "sess-1"


def test_gemini_payload_top_level_fallback():
    """Older Gemini versions: tool_input NOT nested; fields at top level."""
    from agentgate.gemini_hook import gemini_payload_to_event

    payload = {
        "hook_event_name": "BeforeTool",
        "session_id": "sess-1",
        "cwd": "/tmp",
        "tool_name": "read_file",
        "path": "/etc/passwd",  # top-level, not under tool_input
    }
    event, tool, _agent = gemini_payload_to_event(payload)
    assert tool == "read_file"
    assert event["file"] == "/etc/passwd"


def test_gemini_response_maps_deny_to_block():
    from agentgate.gemini_hook import decision_to_gemini_response
    assert decision_to_gemini_response("deny", "bad")["decision"] == "block"
    assert decision_to_gemini_response("ask", "?")["decision"] == "block"
    assert decision_to_gemini_response("allow", "")["decision"] == "allow"


# ─── /metrics endpoint ─────────────────────────────────────────────────────────


def test_prometheus_metrics_endpoint(tmp_path: Path):
    """The dashboard /metrics endpoint emits Prometheus exposition format."""
    import socket
    import socketserver
    import threading
    import urllib.request

    from agentgate.audit import Audit
    from agentgate.dashboard import serve

    db = tmp_path / "audit.db"
    from agentgate.policy import Action as _A
    Audit(str(db)).record(
        source="claude-code", agent="claude", action=_A.DENY,
        event={"command": "rm -rf /"}, rule_id="r1", rule_name="n", reason="x",
    )

    # Pick a free port and start the dashboard
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    t = threading.Thread(target=serve, args=(str(db), "127.0.0.1", port), daemon=True)
    t.start()
    for _ in range(30):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.1)

    body = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics").read().decode()
    assert "agentgate_events_total" in body
    assert 'action="deny"' in body
    assert "agentgate_uptime_seconds" in body
