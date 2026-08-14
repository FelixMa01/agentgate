"""`agentgate stats` — aggregate audit statistics."""
from __future__ import annotations
import json

import click
from rich.table import Table

from ..audit import Audit
from . import console


@click.command()
@click.option("--db", required=True, type=click.Path())
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a Rich table.")
def stats(db: str, as_json: bool) -> None:
    """Show aggregate audit statistics."""
    audit = Audit(db)
    s = audit.stats()
    if as_json:
        click.echo(json.dumps(s, indent=2, sort_keys=True))
        return
    table = Table(show_header=True)
    table.add_column("action")
    table.add_column("count", justify="right")
    for k in ("allow", "deny", "ask", "log"):
        table.add_row(k.upper(), str(s.get(k, 0)))
    console.print(table)


# Subcommand alias for `stats --json` invocation scripts.
stats_json = stats