"""Webhook delivery: notify external URLs when specific audit events occur.

Config file: `$AGENTGATE_WEBHOOKS` or `~/.agentgate/webhooks.yaml`.
Schema:
  webhooks:
    - name: slack-denies
      url: https://hooks.slack.com/services/XXX
      on:
        action: deny
        source: claude-code
      template: "denied: {{rule_name}} ({{rule_id}})"
    - name: log-all
      url: https://example.com/log
      on:
        action: [allow, ask, deny]

Delivery is best-effort: failures are logged to audit (`source="webhook"`)
and retried with exponential backoff (max 3).
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_PATH = Path.home() / ".agentgate" / "webhooks.yaml"


@dataclass
class Webhook:
    name: str
    url: str
    on: dict[str, Any] = field(default_factory=dict)
    template: str = ""


def load_webhooks(path: str | Path | None = None) -> list[Webhook]:
    """Load webhooks from YAML. Returns empty list if file missing."""
    p = Path(path or os.environ.get("AGENTGATE_WEBHOOKS", DEFAULT_PATH))
    if not p.exists():
        return []
    raw = yaml.safe_load(p.read_text()) or {}
    out = []
    for wh in raw.get("webhooks", []):
        out.append(Webhook(
            name=wh["name"],
            url=wh["url"],
            on=wh.get("on", {}),
            template=wh.get("template", ""),
        ))
    return out


def _matches(event: dict[str, Any], filter_: dict[str, Any]) -> bool:
    """Return True if event passes the webhook filter."""
    for key, want in filter_.items():
        got = event.get(key)
        if isinstance(want, list):
            if got not in want:
                return False
        else:
            if got != want:
                return False
    return True


def deliver(event: dict[str, Any], webhooks: list[Webhook] | None = None,
            timeout: float = 5.0) -> list[tuple[str, bool, str]]:
    """Deliver `event` to each matching webhook. Returns list of (name, ok, msg)."""
    whs = webhooks if webhooks is not None else load_webhooks()
    results: list[tuple[str, bool, str]] = []
    for wh in whs:
        if not _matches(event, wh.on):
            continue
        if wh.template:
            body = wh.template.format(**{
                k: event.get(k, "") for k in (
                    "rule_id", "rule_name", "action", "source", "agent", "reason",
                )
            })
        else:
            body = json.dumps(event)
        payload = json.dumps({"webhook": wh.name, "event": event, "message": body}).encode()
        attempt = 0
        last_err = ""
        while attempt < 3:
            attempt += 1
            try:
                req = urllib.request.Request(
                    wh.url, data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if 200 <= resp.status < 300:
                        results.append((wh.name, True, "ok"))
                        break
                    last_err = f"HTTP {resp.status}"
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_err = str(exc)
            time.sleep(0.2 * (2 ** attempt))
        else:
            results.append((wh.name, False, last_err))
    return results


def save_webhooks(webhooks: list[Webhook], path: str | Path | None = None) -> None:
    p = Path(path or os.environ.get("AGENTGATE_WEBHOOKS", DEFAULT_PATH))
    p.parent.mkdir(parents=True, exist_ok=True)
    out = {
        "webhooks": [
            {"name": w.name, "url": w.url, "on": w.on, "template": w.template}
            for w in webhooks
        ]
    }
    p.write_text(yaml.safe_dump(out, sort_keys=False))
