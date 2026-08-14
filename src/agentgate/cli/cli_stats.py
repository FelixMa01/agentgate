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
@click.option("--by-source", "by_source", is_flag=True, help="Group counts by source.")
@click.option("--by-rule", "by_rule", is_flag=True, help="Group counts by rule_id.")
def stats(db: str, as_json: bool, by_source: bool, by_rule: bool) -> None:
    """Show aggregate audit statistics."""
    audit = Audit(db)
    if by_source:
        s = audit.by_source()
    elif by_rule:
        s = audit.by_rule()
    else:
        s = audit.stats()
    if as_json:
        click.echo(json.dumps(s, indent=2, sort_keys=True))
        return
    table = Table(show_header=True)
    table.add_column("key")
    table.add_column("count", justify="right")
    for k, v in s.items():
        table.add_row(str(k), str(v))
    console.print(table)


# Subcommand alias for `stats --json` invocation scripts.
stats_json = stats
