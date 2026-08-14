"""`agentgate doctor` — check that the install can actually run."""

from __future__ import annotations

import os
import shutil
import socket
import sys
from pathlib import Path

import click

from .. import __version__
from ..policy import load_policy
from . import console


@click.command()
@click.option(
    "--policy", "-p", default=None, help="Optional policy.yaml to validate as part of the check."
)
def doctor(policy: str | None) -> None:
    """Check Python version, deps, optional tools, and policy health.

    Useful as the first thing a new user runs after install.
    """
    console.print(f"[bold]AgentGate v{__version__} — doctor[/bold]")
    console.print()

    # Python version
    v = sys.version_info
    py_ok = v >= (3, 12)
    console.print(
        f"  python     {sys.version.split()[0]}  "
        + ("[green]\u2713[/]" if py_ok else "[red]\u2717 need 3.12+[/]")
    )

    # Core dependencies
    for mod, label in [("click", "click"), ("yaml", "pyyaml"), ("rich", "rich")]:
        try:
            __import__(mod)
            console.print(f"  {label:11s} [green]\u2713[/]")
        except ImportError:
            console.print(f"  {label:11s} [red]\u2717 missing — run `uv sync`[/]")

    # Optional: mitmproxy for `agentgate proxy`
    try:
        import mitmproxy

        console.print("  mitmproxy   [green]\u2713[/]")
    except ImportError:
        console.print("  mitmproxy   [yellow]\u00b7 missing — `agentgate proxy` won't work[/]")

    # Shell tools
    for tool in ("git", "mitmdump"):
        path = shutil.which(tool)
        if path:
            console.print(f"  {tool:11s} {path}  [green]\u2713[/]")
        else:
            console.print(f"  {tool:11s} [yellow]\u00b7 not on PATH[/]")

    # Slack/Telegram notification config
    if os.environ.get("AGENTGATE_SLACK_WEBHOOK"):
        console.print("  slack       [green]\u2713 webhook configured[/]")
    else:
        console.print("  slack       [dim]\u00b7 no webhook (will fall back to file)[/]")
    if os.environ.get("AGENTGATE_TELEGRAM_BOT_TOKEN") and os.environ.get(
        "AGENTGATE_TELEGRAM_CHAT_ID"
    ):
        console.print("  telegram    [green]\u2713 bot + chat configured[/]")
    else:
        console.print("  telegram    [dim]\u00b7 no bot (will fall back to slack/file)[/]")

    # Hosted
    if os.environ.get("AGENTGATE_HOSTED_URL"):
        console.print(
            "  hosted      [green]\u2713 {}[/]".format(os.environ["AGENTGATE_HOSTED_URL"])
        )
    else:
        console.print("  hosted      [dim]\u00b7 not configured (standalone mode)[/]")

    # Port availability
    for label, port in [("dashboard", 8766), ("approval", 8765), ("proxy", 8080)]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            free = s.connect_ex(("127.0.0.1", port)) != 0
        icon = "[green]\u2713 free[/]" if free else "[yellow]\u00b7 busy[/]"
        console.print(f"  port {port:5d}  ({label})  {icon}")

    # Policy validation
    if policy:
        try:
            pol = load_policy(policy)
            console.print(
                f"  policy      [green]\u2713 {len(pol.rules)} rules, "
                f"default={pol.default_action.value}[/]"
            )
            if pol.network:
                if pol.allowed_domains:
                    console.print(
                        f"               [dim]{len(pol.allowed_domains)} allowed domains[/]"
                    )
                if pol.denied_domains:
                    console.print(
                        f"               [dim]{len(pol.denied_domains)} denied domains[/]"
                    )
            if not pol.metadata:
                console.print(
                    "               [yellow]\u00b7 no metadata block "
                    "(consider adding author + last_reviewed)[/]"
                )
        except Exception as e:
            console.print(f"  policy      [red]\u2717 invalid: {e}[/]")
    else:
        console.print("  policy      [dim]\u00b7 not checked (pass --policy to validate)[/]")

    console.print()
    console.print(
        "[green]All checks passed.[/]"
        if py_ok
        else "[red]Fix the \u2717 items above and re-run `agentgate doctor`.[/]"
    )
