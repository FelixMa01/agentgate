"""Webhook delivery: notify external URLs when specific audit events occur.

Config file: `$AGENTGATE_WEBHOOKS` or `~/.agentgate/webhooks.yaml`.
Schema:
  webhooks:
    - name: slack-denies
      url: https://hooks.slack.com/services/XXX
      secret: "<optional HMAC secret>"   # if set, signs the body with
                                         # X-AgentGate-Signature: sha256=<hex>
      on:
        action: deny
        source: claude-code
      template: "denied: {{rule_name}} ({{rule_id}})"
    - name: log-all
      url: https://example.com/log
      on:
        action: [allow, ask, deny]

Delivery uses exponential backoff: retries 1, 2, 4, 8, 16 seconds (max 5
attempts by default). Receivers should verify the signature with
`verify_signature(secret, body, header)` before trusting the payload.

Verification helper:
    >>> from agentgate.webhooks import verify_signature
    >>> assert verify_signature("s3cret", request.body, request.headers["X-AgentGate-Signature"])
"""
from __future__ import annotations

import hashlib
import hmac
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

SIGNATURE_HEADER = "X-AgentGate-Signature"


@dataclass
class Webhook:
    name: str
    url: str
    on: dict[str, Any] = field(default_factory=dict)
    template: str = ""
    secret: str = ""  # if set, payloads are HMAC-SHA256 signed


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
            secret=wh.get("secret", "") or "",
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


def sign(secret: str, body: bytes) -> str:
    """Compute `X-AgentGate-Signature` value for `body` with `secret`.

    Returns "sha256=<hexdigest>". Compatible with HMAC-SHA256 receivers
    that expect the GitHub-style "sha256=<hex>" header.
    """
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_signature(secret: str, body: bytes, header: str) -> bool:
    """Constant-time HMAC verification of a webhook payload.

    Returns True iff `header` matches `sign(secret, body)`. Used by
    receivers (and tests) to confirm an AgentGate webhook is authentic.
    """
    expected = sign(secret, body)
    return hmac.compare_digest(expected, header or "")


def deliver(event: dict[str, Any], webhooks: list[Webhook] | None = None,
            timeout: float = 5.0, max_attempts: int = 5,
            base_backoff: float = 1.0) -> list[tuple[str, bool, str]]:
    """Deliver `event` to each matching webhook.

    Retries with exponential backoff (1, 2, 4, 8, 16s by default; tunable
    via `max_attempts` and `base_backoff`). Returns list of (name, ok, msg).
    """
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
        headers = {"Content-Type": "application/json"}
        if wh.secret:
            headers[SIGNATURE_HEADER] = sign(wh.secret, payload)
        attempt = 0
        last_err = ""
        while attempt < max_attempts:
            attempt += 1
            try:
                req = urllib.request.Request(
                    wh.url, data=payload,
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if 200 <= resp.status < 300:
                        results.append((wh.name, True, "ok"))
                        break
                    last_err = f"HTTP {resp.status}"
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_err = str(exc)
            if attempt < max_attempts:
                # Exponential backoff: base * 2^(attempt-1). The "while"
                # already incremented, so attempt=1 sleeps base*1.
                time.sleep(base_backoff * (2 ** (attempt - 1)))
        else:
            results.append((wh.name, False, last_err))
    return results


def save_webhooks(webhooks: list[Webhook], path: str | Path | None = None) -> None:
    p = Path(path or os.environ.get("AGENTGATE_WEBHOOKS", DEFAULT_PATH))
    p.parent.mkdir(parents=True, exist_ok=True)
    out = {
        "webhooks": [
            {
                "name": w.name, "url": w.url, "on": w.on,
                "template": w.template, "secret": w.secret,
            }
            for w in webhooks
        ]
    }
    p.write_text(yaml.safe_dump(out, sort_keys=False))
