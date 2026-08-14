"""`agentgate ask-test` — smoke test the ASK round-trip."""

from __future__ import annotations

import json
import threading
import time

import click

from ..approval import STORE
from ..audit import Audit
from ..policy import Action, load_policy
from . import console
from ._common import resolve_db, resolve_policy


@click.command(name="ask-test")
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
@click.option("--db", required=True, type=click.Path())
@click.option("--event-json", required=True, help="JSON event to evaluate (will be forced to ask).")
@click.option(
    "--approve-after",
    default=2.0,
    type=float,
    help="Seconds to wait before resolving the ask automatically.",
)
def ask_test(policy: str, db: str, event_json: str, approve_after: float) -> None:
    """Smoke-test: evaluate an event as ASK, then auto-resolve it from this process."""
    pol = load_policy(str(resolve_policy(policy)))
    audit = Audit(str(resolve_db(db)))
    event = json.loads(event_json)
    rule = pol.rules[0] if pol.rules else None
    audit.record(
        source="ask-test",
        agent="local",
        action=Action.ASK,
        event=event,
        rule_id=rule.id if rule else "manual",
        rule_name=rule.name if rule else "Manual ASK",
        reason="ask-test manual trigger",
    )
    ask = STORE.request(event, event.get("tool", "?"), "ask-test")
    console.print(f"[cyan]\u2192[/] Created ask token [bold]{ask.token}[/]")
    console.print(f"  resolution will be 'allow' after {approve_after}s")

    def _resolve_later():
        time.sleep(approve_after)
        STORE.resolve(ask.token, "allow")

    threading.Thread(target=_resolve_later, daemon=True).start()
    decision = STORE.wait(ask.token, timeout=approve_after + 5)
    console.print(f"[green]\u2713[/] Resolved: {decision}")
    audit.record(
        source="ask-test",
        agent="local",
        action=Action(decision),
        event={**event, "_resolved": decision},
        rule_id="ask-test",
        rule_name="Manual ASK",
        reason="ask-test resolution",
    )
