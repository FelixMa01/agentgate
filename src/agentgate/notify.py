"""Slack notification — send a message with an Approve/Deny link via
incoming webhook URL or a plain webhook + approval server URL.

Configuration via env vars (set by install-hook or export'd manually):
  AGENTGATE_SLACK_WEBHOOK  — Slack incoming webhook URL (e.g. https://hooks.slack.com/...)
  AGENTGATE_APPROVAL_HOST  — public host:port of the approval server (e.g. localhost:8765)
  AGENTGATE_APPROVAL_SCHEME — http | https (default http)

Falls back to writing the message to a local file if no webhook is configured
(handy for first-run smoke tests without setting up Slack).
"""
from __future__ import annotations
import json
import os
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


def build_ask_message(token: str, tool: str, event: dict, rule_name: str | None,
                      reason: str | None, approval_host: str,
                      scheme: str = "http") -> dict[str, Any]:
    """Build a Slack message body (Block Kit) with Approve / Deny buttons."""
    base = f"{scheme}://{approval_host}/approve/{token}"
    return {
        "text": f"🛡️ AgentGate ask: {tool}",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text",
                                          "text": f"🛡️ AgentGate — approval requested"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Tool:*\n`{tool}`"},
                {"type": "mrkdwn", "text": f"*Rule:*\n{rule_name or '(default)'}"},
                {"type": "mrkdwn", "text": f"*Reason:*\n{reason or '—'}"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn",
                                          "text": f"*Event:*\n```{json.dumps(event, indent=2, default=str)[:1500]}```"}},
            {"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "✅ Allow"},
                 "style": "primary", "url": f"{base}?d=allow"},
                {"type": "button", "text": {"type": "plain_text", "text": "✗ Deny"},
                 "style": "danger",  "url": f"{base}?d=deny"},
            ]},
            {"type": "context", "elements": [
                {"type": "mrkdwn", "text": f"Token: `{token}` (auto-expires in 10 min)"},
            ]},
        ],
    }


def notify_ask(token: str, tool: str, event: dict, rule_name: str | None,
               reason: str | None) -> str:
    """Send the ask notification; return the message status string."""
    webhook = os.environ.get("AGENTGATE_SLACK_WEBHOOK")
    approval_host = os.environ.get(
        "AGENTGATE_APPROVAL_HOST",
        f"127.0.0.1:{os.environ.get('AGENTGATE_APPROVAL_PORT', '8765')}"
    )
    scheme = os.environ.get("AGENTGATE_APPROVAL_SCHEME", "http")

    payload = build_ask_message(token, tool, event, rule_name, reason,
                                approval_host, scheme)

    if webhook:
        ok, msg = post_to_slack(webhook, payload)
        return f"slack:{'ok' if ok else msg}"
    # Fallback: write to file so smoke tests can verify the message was generated.
    Path("/tmp/agentgate-asks.jsonl").parent.mkdir(parents=True, exist_ok=True)
    with open("/tmp/agentgate-asks.jsonl", "a") as f:
        f.write(json.dumps(payload) + "\n")
    return f"file:/tmp/agentgate-asks.jsonl"