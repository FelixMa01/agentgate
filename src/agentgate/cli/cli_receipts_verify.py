"""`agentgate receipts verify` — verify Ed25519 audit receipts."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import click

from ..receipts import RECEIPTS_DIR, verify_receipt
from . import console


@click.command("receipts-verify")
@click.argument("db_path", type=click.Path(exists=True, path_type=Path))
@click.option("--key", "key_id", default="primary", show_default=True,
              help="Key id under ~/.agentgate/receipts/")
@click.option("--json-output", is_flag=True, help="Emit JSON instead of text")
def receipts_verify(db_path: Path, key_id: str, json_output: bool):
    """Verify every row's Ed25519 receipt signature in an audit db."""
    pub = RECEIPTS_DIR / f"{key_id}.ed25519.pub.pem"
    if not pub.exists():
        raise SystemExit(f"Public key not found: {pub}")
    conn = sqlite3.connect(str(db_path))
    rows = conn.execute(
        "SELECT id, ts, source, agent, action, event_json, reason, chain_hash, "
        "prev_chain_hash, receipt_signature FROM events ORDER BY id ASC"
    ).fetchall()
    verified = 0
    unsigned = 0
    broken = []
    for r in rows:
        rid, _ts, _source, _agent, action, event_json, _reason, chain_hash, _prev_hash, sig = r
        if not sig:
            unsigned += 1
            continue
        try:
            event = json.loads(event_json)
        except Exception:
            event = {"_raw": event_json}
        prev_sig = None
        if rid > 1:
            prev_row = conn.execute(
                "SELECT receipt_signature FROM events WHERE id = ?", (rid - 1,)
            ).fetchone()
            prev_sig = prev_row[0] if prev_row else None
        envelope = {
            "key_id": key_id,
            "payload": {
                "prev_signature": prev_sig,
                "chain_hash": chain_hash,
                "action": action,
                "event": event,
            },
            "signature": sig,
        }
        if verify_receipt(envelope, pub):
            verified += 1
        else:
            broken.append(rid)

    summary = {
        "total": len(rows),
        "verified": verified,
        "unsigned": unsigned,
        "broken": broken,
    }
    if json_output:
        click.echo(json.dumps(summary, indent=2))
    else:
        console.print(f"Total events: {len(rows)}")
        console.print(f"Verified:     {verified}")
        console.print(f"Unsigned:     {unsigned}")
        console.print(f"Broken sigs:  {len(broken)} {broken[:5] if broken else ''}")
    if broken:
        raise SystemExit(2)
