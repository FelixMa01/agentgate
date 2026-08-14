"""Multi-channel notification — send an ASK message via Slack OR Telegram.

Configuration via env vars (set by install-hook or export'd manually):
  AGENTGATE_SLACK_WEBHOOK   — Slack incoming webhook URL
  AGENTGATE_TELEGRAM_BOT_TOKEN + AGENTGATE_TELEGRAM_CHAT_ID — Telegram bot
  AGENTGATE_APPROVAL_HOST   — host:port of the approval server (default 127.0.0.1:8765)
  AGENTGATE_APPROVAL_SCHEME — http | https (default http)

Channel precedence: Telegram if both Telegram creds are set, else Slack,
else file fallback. This matches user preference — Telegram first.

Falls back to writing the message to a local file if nothing is configured
(handy for first-run smoke tests without setting up a channel).
"""
from __future__ import annotations
import json
import os
import sys
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any


def post_to_slack(webhook_url: str, payload: dict[str, Any]) -> tuple[bool, str]:
    """Post a JSON payload to a Slack incoming webhook."""
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        webhook_url, data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return True, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return False, f"URL error: {e.reason}"
    except Exception as e:
        return False, f"error: {e}"


def post_to_telegram(bot_token: str, chat_id: str, text: str) -> tuple[bool, str]:
    """Send a plain text message via Telegram Bot API."""
    api = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    body = json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "MarkdownV2"}).encode()
    req = urllib.request.Request(api, data=body,
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            if data.get("ok"):
                return True, "ok"
            return False, f"telegram: {data.get('description', 'unknown')}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return False, f"URL error: {e.reason}"
    except Exception as e:
        return False, f"error: {e}"


def _md_escape(s: str) -> str:
    """Escape characters that Telegram MarkdownV2 interprets."""
    return (s.replace("\\", "\\\\")
             .replace("_", "\\_").replace("*", "\\*")
             .replace("[", "\\[").replace("]", "\\]")
             .replace("(", "\\(").replace(")", "\\)")
             .replace("`", "\\`").replace("~", "\\~")
             .replace(">", "\\>").replace("#", "\\#")
             .replace("+", "\\+").replace("-", "\\-")
             .replace("=", "\\=").replace("|", "\\|")
             .replace("{", "\\{").replace("}", "\\}")
             .replace(".", "\\.").replace("!", "\\!"))


def build_ask_message(token: str, tool: str, event: dict, rule_name: str | None,
                      reason: str | None, approval_host: str,
                      scheme: str = "http") -> dict[str, Any]:
    """Build a Slack message body (Block Kit) with Approve / Deny buttons."""
    base = f"{scheme}://{approval_host}/approve/{token}"
    return {
        "text": f"\U0001f6e1\ufe0f AgentGate ask: {tool}",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text",
                                          "text": "\U0001f6e1\ufe0f AgentGate \u2014 approval requested"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Tool:*\n`{tool}`"},
                {"type": "mrkdwn", "text": f"*Rule:*\n{rule_name or '(default)'}"},
                {"type": "mrkdwn", "text": f"*Reason:*\n{reason or '\u2014'}"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn",
                                          "text": f"*Event:*\n```{json.dumps(event, indent=2, default=str)[:1500]}```"}},
            {"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "\u2705 Allow"},
                 "style": "primary", "url": f"{base}?d=allow"},
                {"type": "button", "text": {"type": "plain_text", "text": "\u2717 Deny"},
                 "style": "danger",  "url": f"{base}?d=deny"},
            ]},
            {"type": "context", "elements": [
                {"type": "mrkdwn", "text": f"Token: `{token}` (auto-expires in 10 min)"},
            ]},
        ],
    }


def build_telegram_message(token: str, tool: str, event: dict, rule_name: str | None,
                           reason: str | None, approval_host: str,
                           scheme: str = "http") -> str:
    """Build a Telegram-friendly plain-text message.

    Telegram can't render Slack buttons — the user has to copy the approve URL
    and curl it (or click it if their approval server has a public URL).
    """
    base = f"{scheme}://{approval_host}/approve/{token}"
    e = _md_escape
    lines = [
        "\U0001f6e1\ufe0f *AgentGate \\- approval requested*",
        "",
        f"*Tool:* `{e(tool)}`",
        f"*Rule:* {e(rule_name) if rule_name else '(default)'}",
        f"*Reason:* {e(reason) if reason else '\u2014'}",
        "",
        f"*Event:*\n```\n{e(json.dumps(event, indent=2, default=str)[:1000])}\n```",
        "",
        f"Allow: `{base}?d=allow`",
        f"Deny:  `{base}?d=deny`",
        "",
        f"Token: `{e(token)}`",
    ]
    return "\n".join(lines)


def notify_ask(token: str, tool: str, event: dict, rule_name: str | None,
               reason: str | None) -> str:
    """Send the ask notification; return the message status string.

    Channel precedence: Telegram > Slack > file fallback.
    """
    approval_host = os.environ.get(
        "AGENTGATE_APPROVAL_HOST",
        f"127.0.0.1:{os.environ.get('AGENTGATE_APPROVAL_PORT', '8765')}"
    )
    scheme = os.environ.get("AGENTGATE_APPROVAL_SCHEME", "http")

    # Telegram first (user preference).
    tg_token = os.environ.get("AGENTGATE_TELEGRAM_BOT_TOKEN")
    tg_chat = os.environ.get("AGENTGATE_TELEGRAM_CHAT_ID")
    if tg_token and tg_chat:
        text = build_telegram_message(token, tool, event, rule_name, reason,
                                       approval_host, scheme)
        ok, msg = post_to_telegram(tg_token, tg_chat, text)
        return f"telegram:{'ok' if ok else msg}"

    # Slack fallback.
    webhook = os.environ.get("AGENTGATE_SLACK_WEBHOOK")
    if webhook:
        payload = build_ask_message(token, tool, event, rule_name, reason,
                                     approval_host, scheme)
        ok, msg = post_to_slack(webhook, payload)
        return f"slack:{'ok' if ok else msg}"

    # File fallback so smoke tests can verify the message was generated.
    fallback = Path(os.environ.get("AGENTGATE_ASK_FALLBACK")
                    or (Path(tempfile.gettempdir()) / "agentgate-asks.jsonl"))
    fallback.parent.mkdir(parents=True, exist_ok=True)
    with open(fallback, "a") as f:
        f.write(json.dumps({
            "token": token, "tool": tool, "event": event,
            "rule_name": rule_name, "reason": reason,
            "approval_url": f"{scheme}://{approval_host}/approve/{token}",
        }) + "\n")
    return f"file:{fallback}"