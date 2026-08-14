"""`agentgate audit verify` — verify the hash chain in the audit DB."""
from __future__ import annotations

import click

from ..audit import Audit
from .cli_audit import cli_audit


@cli_audit.command(name="verify")
@click.option("--db", required=True, type=click.Path(), help="Path to the audit SQLite DB.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def audit_verify(db: str, as_json: bool) -> None:
    """Verify the hash chain in the audit DB.

    Returns exit code 0 if the chain is intact, 1 if any row has been tampered.
    """
    a = Audit(db)
    result = a.verify_chain()
    if as_json:
        import json as _json
        click.echo(_json.dumps(result, indent=2))
        return
    if result["valid"]:
        click.echo(f"OK — chain valid across {result['checked']} rows")
    else:
        click.echo(f"BROKEN — first tampered row id={result['first_broken_id']} ({result['checked']} rows checked)")
        raise click.exceptions.Exit(1)
