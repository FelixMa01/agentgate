"""Tests for the notification module (Slack + Telegram + file fallback)."""
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from agentgate.notify import (
    post_to_telegram, post_to_slack, build_telegram_message,
    build_ask_message, notify_ask, _md_escape,
)


def test_md_escape_basic():
    assert _md_escape("hello.world") == "hello\\.world"
    assert _md_escape("[a]b(c)") == "\\[a\\]b\\(c\\)"
    assert _md_escape("a_b*c") == "a\\_b\\*c"


def test_build_telegram_message_includes_urls(monkeypatch):
    monkeypatch.setenv("AGENTGATE_APPROVAL_HOST", "127.0.0.1:8765")
    msg = build_telegram_message("tok123", "Bash", {"tool": "Bash", "command": "rm -rf /"},
                                 "danger", "mass delete", "127.0.0.1:8765")
    assert "tok123" in msg
    assert "127.0.0.1:8765/approve/tok123?d=allow" in msg
    assert "127.0.0.1:8765/approve/tok123?d=deny" in msg
    assert "Bash" in msg
    assert "danger" in msg
    # MarkdownV2-escaped content
    assert "\\- approval requested" in msg
    # Body should not contain Slack Block Kit syntax
    assert '"blocks"' not in msg


def test_post_to_telegram_success():
    """Mocked telegram bot returns ok."""
    fake_resp = MagicMock()
    fake_resp.read.return_value = json.dumps({"ok": True}).encode()
    fake_resp.__enter__ = lambda s: s
    fake_resp.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=fake_resp):
        ok, msg = post_to_telegram("bot:TOKEN", "12345", "hello")
    assert ok is True
    assert msg == "ok"


def test_post_to_telegram_failure():
    fake_resp = MagicMock()
    fake_resp.read.return_value = json.dumps({"ok": False, "description": "chat not found"}).encode()
    fake_resp.__enter__ = lambda s: s
    fake_resp.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=fake_resp):
        ok, msg = post_to_telegram("bot:TOKEN", "999", "hello")
    assert ok is False
    assert "chat not found" in msg


def test_notify_telegram_takes_precedence(monkeypatch, tmp_path, capsys):
    """When Telegram creds are set, notify_ask uses Telegram (not Slack/file)."""
    monkeypatch.setenv("AGENTGATE_TELEGRAM_BOT_TOKEN", "bot:TOKEN")
    monkeypatch.setenv("AGENTGATE_TELEGRAM_CHAT_ID", "999")
    monkeypatch.delenv("AGENTGATE_SLACK_WEBHOOK", raising=False)
    monkeypatch.setenv("AGENTGATE_APPROVAL_HOST", "127.0.0.1:8765")
    with patch("agentgate.notify.post_to_telegram", return_value=(True, "ok")) as m:
        status = notify_ask("tok", "Bash", {"tool": "Bash", "command": "ls"}, "rule", "reason")
    assert "telegram" in status
    assert "ok" in status
    m.assert_called_once()


def test_notify_slack_when_no_telegram(monkeypatch):
    monkeypatch.delenv("AGENTGATE_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("AGENTGATE_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.setenv("AGENTGATE_SLACK_WEBHOOK", "https://hooks.slack.com/x")
    monkeypatch.setenv("AGENTGATE_APPROVAL_HOST", "127.0.0.1:8765")
    with patch("agentgate.notify.post_to_slack", return_value=(True, "ok")) as m:
        status = notify_ask("tok", "Bash", {"tool": "Bash", "command": "ls"}, "rule", "reason")
    assert "slack" in status
    assert "ok" in status
    m.assert_called_once()


def test_notify_file_fallback(monkeypatch, tmp_path):
    """When nothing is configured, write to file."""
    monkeypatch.delenv("AGENTGATE_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("AGENTGATE_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.delenv("AGENTGATE_SLACK_WEBHOOK", raising=False)
    monkeypatch.setenv("AGENTGATE_APPROVAL_HOST", "127.0.0.1:8765")
    # Redirect the file path
    target = tmp_path / "asks.jsonl"
    with patch("agentgate.notify.Path") as MP:
        MP.return_value.parent.mkdir = MagicMock()
        # open is a builtin so we patch the open() in the notify module.
        import builtins
        original_open = builtins.open
        def fake_open(path, *args, **kwargs):
            if str(path) == "/tmp/agentgate-asks.jsonl":
                return original_open(target, *args, **kwargs)
            return original_open(path, *args, **kwargs)
        with patch("builtins.open", side_effect=fake_open):
            status = notify_ask("tok", "Bash", {"command": "ls"}, "rule", "reason")
    assert "file" in status
    lines = target.read_text().strip().split("\n")
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["token"] == "tok"
    assert payload["tool"] == "Bash"
    assert "approval_url" in payload