"""`agentgate approval-server` — start the HTTP /approve server."""
from __future__ import annotations
import click

from ..approval_server import serve
from . import console
from ._common import port_in_use, suggest_port


@click.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8765, type=int)
def approval_server(host: str, port: int) -> None:
    """Start the approval HTTP server (handles Slack Approve/Deny clicks)."""
    if port_in_use(port):
        suggested = suggest_port(port)
        raise click.ClickException(
            f"port {port} is already in use. Try `--port {suggested}` instead."
        )
    console.print(f"[cyan]\u2192[/] AgentGate approval server on http://{host}:{port}")
    serve(host, port)