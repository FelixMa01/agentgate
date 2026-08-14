"""`agentgate mcp` — start the MCP stdio server."""
from __future__ import annotations

import os
import sys

import click

from ..mcp_server import serve_stdio


@click.command("mcp")
@click.option("--policy", "policy_path", default=None,
              help="Path to policy.yaml (or set AGENTGATE_POLICY).")
@click.option("--db", "db_path", default=None,
              help="Path to audit.db (or set AGENTGATE_DB).")
def mcp_cmd(policy_path: str | None, db_path: str | None) -> None:
    """Run AgentGate as an MCP server over stdio (JSON-RPC 2.0)."""
    if policy_path:
        os.environ["AGENTGATE_POLICY"] = policy_path
    if db_path:
        os.environ["AGENTGATE_DB"] = db_path
    if not os.environ.get("AGENTGATE_POLICY") or not os.environ.get("AGENTGATE_DB"):
        click.echo(
            "agentgate mcp requires --policy and --db (or AGENTGATE_POLICY + AGENTGATE_DB).",
            err=True,
        )
        sys.exit(2)
    serve_stdio()
