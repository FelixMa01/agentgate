"""`agentgate audit` — show recent audit log entries."""
from __future__ import annotations
from datetime import datetime

import click
from rich.table import Table

from ..audit import Audit
from ..policy import Action
from . import console


@click.command()
@click.option("--db", required=True, type=click.Path())
@click.option("--limit", default=20, type=int)
@click.option("--action", "action_filter", default=None,
              type=click.Choice([a.value for a in Action]))
def audit(db: str, limit: int, action_filter: str | None) -> None:
    """Show recent audit log entries."""
    audit = Audit(db)
    rows = audit.recent(limit=limit, action=Action(action_filter) if action_filter else None)
    if not rows:
        console.print("[dim]No events recorded yet.[/]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("ts", style="dim")
    table.add_column("src")
    table.add_column("action")
    table.add_column("rule")
    table.add_column("reason")
    for r in rows:
        ts = datetime.fromtimestamp(r["ts"]).strftime("%H:%M:%S")
        table.add_row(
            ts,
            r["source"],
            r["action"].upper(),
            r["rule_id"] or "\u2014",
            (r["reason"] or "")[:50],
        )
    console.print(table)
    stats = audit.stats()
    summary = ", ".join(f"{k}={v}" for k, v in stats.items())
    console.print(f"\n[dim]Totals: {summary}[/]")