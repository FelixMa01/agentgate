"""`agentgate dashboard` — start the audit dashboard HTTP server."""
from __future__ import annotations
import click

from ..dashboard import serve
from . import console
from ._common import port_in_use, resolve_db, suggest_port


@click.command()
@click.option("--db", required=True, type=click.Path())
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8766, type=int)
def dashboard(db: str, host: str, port: int) -> None:
    """Start the AgentGate audit dashboard HTTP server."""
    db_path = str(resolve_db(db))
    if port_in_use(port):
        suggested = suggest_port(port)
        raise click.ClickException(
            f"port {port} is already in use. Try `--port {suggested}` instead."
        )
    console.print(f"[cyan]\u2192[/] AgentGate dashboard on http://{host}:{port}")
    serve(db_path, host, port)