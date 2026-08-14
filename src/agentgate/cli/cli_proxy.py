"""`agentgate proxy` — start the mitmproxy egress add-on."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import click

from . import console
from ._common import port_in_use, resolve_db, resolve_policy, suggest_port


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


@click.command()
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
@click.option("--db", required=True, type=click.Path())
@click.option("--listen-host", default="127.0.0.1")
@click.option("--listen-port", default=8080, type=int)
@click.option("--mode", default="regular", type=click.Choice(["regular", "transparent", "socks5"]))
def proxy(policy: str, db: str, listen_host: str, listen_port: int, mode: str) -> None:
    """Start the AgentGate HTTP egress proxy (mitmproxy add-on)."""
    if port_in_use(listen_port):
        suggested = suggest_port(listen_port)
        raise click.ClickException(
            f"port {listen_port} is already in use. Try `--listen-port {suggested}` instead."
        )
    policy_abs = str(resolve_policy(policy))
    db_abs = str(resolve_db(db))
    addon_path = _project_root() / "src" / "agentgate" / "proxy_addon.py"
    if not addon_path.exists():
        raise click.ClickException(f"add-on not found: {addon_path}")
    env = {
        **os.environ,
        "AGENTGATE_POLICY": policy_abs,
        "AGENTGATE_DB": db_abs,
    }
    cmd = [
        "mitmdump",
        "--mode",
        mode,
        "--listen-host",
        listen_host,
        "--listen-port",
        str(listen_port),
        "--set",
        "block_global=false",
        "--scripts",
        str(addon_path),
        "--showhost",
    ]
    console.print(
        f"[cyan]\u2192[/] Starting AgentGate proxy on {listen_host}:{listen_port} ({mode} mode)"
    )
    console.print(f"  policy: [dim]{policy_abs}[/]")
    console.print(f"  db:     [dim]{db_abs}[/]")
    console.print(f"  add-on: [dim]{addon_path}[/]\n")
    console.print("[dim]In another terminal:[/]")
    console.print(f"  export HTTP_PROXY=http://{listen_host}:{listen_port}")
    console.print(f"  export HTTPS_PROXY=http://{listen_host}:{listen_port}")
    console.print("  curl https://api.github.com\n")
    try:
        subprocess.run(cmd, env=env, check=True)
    except KeyboardInterrupt:
        console.print("\n[yellow]\u00b7[/] Proxy stopped")
    except FileNotFoundError:
        raise click.ClickException(
            "mitmdump not found. Run `uv sync` to install it, or activate the venv."
        )
