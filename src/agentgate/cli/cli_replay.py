"""`agentgate replay` — re-evaluate a stored audit event against a (possibly new) policy."""
from __future__ import annotations
import json

import click

from ..audit import Audit
from ..policy import load_policy
from . import console
from ._common import resolve_policy


@click.command()
@click.option("--db", required=True, type=click.Path())
@click.option("--audit-id", "audit_id", required=True, type=int,
              help="Audit row id to replay.")
@click.option("--policy", "-p", required=True, type=click.Path(exists=True),
              help="Policy to re-evaluate against (defaults to the one used at record-time if omitted).")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of Rich output.")
def replay(db: str, audit_id: int, policy: str, as_json: bool) -> None:
    """Re-evaluate a stored audit event against a (possibly new) policy.

    Useful for policy migrations: replay every historical event under the new
    rules and see which decisions would change.
    """
    audit = Audit(db)
    row = audit.get(audit_id)
    if row is None:
        raise click.ClickException(f"audit id {audit_id} not found")
    pol = load_policy(str(resolve_policy(policy)))
    new_action, new_rule = pol.evaluate(row["event"])
    old_action = row["action"]
    changed = new_action != old_action
    if as_json:
        click.echo(json.dumps({
            "audit_id": audit_id,
            "old_action": old_action.value if hasattr(old_action, "value") else str(old_action),
            "new_action": new_action.value,
            "changed": changed,
            "old_rule_id": row.get("rule_id"),
            "new_rule_id": new_rule.id if new_rule else None,
        }))
        return
    icon = {"allow": "\u2713", "deny": "\u2717", "ask": "?", "log": "\u00b7"}[new_action.value]
    color = {"allow": "green", "deny": "red", "ask": "yellow", "log": "dim"}[new_action.value]
    console.print(f"audit id [bold]{audit_id}[/]:")
    console.print(f"  recorded: {old_action} ({row.get('rule_id')})")
    console.print(f"  [{color}]{icon} {new_action.value.upper()}[/] ({new_rule.id if new_rule else 'none'})")
    if changed:
        console.print("  [yellow]\u26a0 decision CHANGED under the new policy[/]")
    else:
        console.print("  [dim]decision unchanged[/]")