"""Hosted mode — opt-in team features.

AgentGate v0.5.0 ships two opt-in features for teams:

1. **Remote policy** — `agentgate pull-policy <url>` pulls a policy from a
   central endpoint (e.g. your team's policy repo). Caches it locally so
   the agent still runs if the central endpoint is offline.

2. **Remote audit** — `agentgate push-events <url>` uploads audit events
   to a central endpoint. Each row ships as `{token, ts, source, action, ...}`.
   The endpoint can de-dupe by row id.

Both work over plain HTTP. Authentication via `Authorization: Bearer <token>`
env var. Run with no flag and you get a clear error message.

Configuration:
  AGENTGATE_HOSTED_URL=https://agentgate.yourteam.com
  AGENTGATE_HOSTED_TOKEN=...           # bearer token
"""
from __future__ import annotations
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def _hosted_headers() -> dict[str, str]:
    """Build request headers for hosted endpoints."""
    headers = {"User-Agent": f"agentgate/0.5"}
    token = os.environ.get("AGENTGATE_HOSTED_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def pull_policy(url: str | None = None, cache: Path | None = None) -> str:
    """Download a policy from the hosted endpoint, cache it, return the path.

    If no URL is given, uses AGENTGATE_HOSTED_URL/policy.yaml.
    """
    if not url:
        base = os.environ.get("AGENTGATE_HOSTED_URL", "").rstrip("/")
        if not base:
            raise RuntimeError(
                "no URL: pass it as arg or set AGENTGATE_HOSTED_URL"
            )
        url = f"{base}/policy.yaml"
    req = urllib.request.Request(url, headers=_hosted_headers())
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"network: {e.reason}")
    if cache is None:
        cache = Path("policy.hosted.yaml")
    cache.write_text(body)
    return str(cache)


def push_events(db_path: str, url: str | None = None) -> int:
    """Upload audit events newer than what the remote has seen.

    The remote returns the highest id it has; we send rows with id > that.
    Returns the number of events sent.
    """
    from .audit import Audit
    audit = Audit(db_path)
    if not url:
        base = os.environ.get("AGENTGATE_HOSTED_URL", "").rstrip("/")
        if not base:
            raise RuntimeError(
                "no URL: pass it as arg or set AGENTGATE_HOSTED_URL"
            )
        url = f"{base}/api/events"
    # Find cursor.
    last_id_url = f"{url}?cursor=last_id"
    req = urllib.request.Request(last_id_url, headers=_hosted_headers())
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            last_id = int(json.loads(resp.read()).get("last_id", 0))
    except Exception:
        last_id = 0
    # Get new rows.
    rows = audit.since(last_id)
    if not rows:
        return 0
    # event_json is a serialized string in the DB; decode it for upload so the
    # remote endpoint gets a structured payload.
    out_rows: list[dict] = []
    for r in rows:
        out = dict(r)
        if r.get("event_json"):
            try:
                out["event"] = json.loads(r["event_json"])
            except Exception:
                out["event"] = {"raw": r["event_json"]}
        out_rows.append(out)
    payload = json.dumps({"events": out_rows}).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={**_hosted_headers(), "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"upload HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"upload network: {e.reason}")
    return len(rows)