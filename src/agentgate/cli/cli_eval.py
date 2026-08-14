"""`agentgate eval` — evaluate an event and (optionally) record it."""
from __future__ import annotations
import json

import click

from ..audit import Audit
from ..policy import load_policy
from . import console
from ._common import resolve_db, resolve_policy


@click.command()
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
@click.option("--db", required=True, type=click.Path())
@click.option("--source", default="manual", help="Event source label.")
@click.option("--agent", default=None, help="Agent identifier.")
@click.option("--event-json", "event_json", default="{}", help="JSON event payload to evaluate.")
@click.option("--json", "as_json", is_flag=True, help="Emit a JSON line instead of Rich output.")
@click.option("--dry-run", is_flag=True, help="Evaluate without writing to the audit DB.")
def eval(
    policy: str,
    db: str,
    source: str,
    agent: str | None,
    event_json: str,
    as_json: bool,
    dry_run: bool,
) -> None:
    """Evaluate an event against the policy and (optionally) record the decision."""
    pol = load_policy(str(resolve_policy(policy)))
    audit = Audit(str(resolve_db(db)))
    try:
        event = json.loads(event_json)
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON: {e}")
    action, rule = pol.evaluate(event)
    if not dry_run:
        audit.record(
            source=source,
            agent=agent,
            action=action,
            event=event,
            rule_id=rule.id if rule else None,
            rule_name=rule.name if rule else None,
            reason=rule.reason if rule else None,
        )
    if as_json:
        click.echo(json.dumps({
            "action": action.value,
            "rule_id": rule.id if rule else None,
            "rule_name": rule.name if rule else None,
            "reason": rule.reason if rule else None,
            "dry_run": dry_run,
        }))
        return
    icon = {"allow": "\u2713", "deny": "\u2717", "ask": "?", "log": "\u00b7"}[action.value]
    color = {"allow": "green", "deny": "red", "ask": "yellow", "log": "dim"}[action.value]
    console.print(f"[{color}]{icon} {action.value.upper()}[/]", end="")
    if rule:
        console.print(f"  [bold]{rule.name}[/]  ({rule.id})")
        if rule.reason:
            console.print(f"   reason: {rule.reason}")
    else:
        console.print("  [dim](default policy)[/]")
    if dry_run:
        console.print("  [dim](dry-run: not recorded)[/]")