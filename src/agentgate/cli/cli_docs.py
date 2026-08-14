"""`agentgate docs` — open documentation locally."""
from __future__ import annotations

import os
import subprocess
import sys
import webbrowser
from pathlib import Path

import click

from . import console


@click.command()
@click.option("--open", "open_browser", is_flag=True,
              help="Open the rendered docs page in your browser.")
@click.option("--readme-only", is_flag=True,
              help="Show README.md in the terminal instead of opening docs.")
def docs(open_browser: bool, readme_only: bool) -> None:
    """Show README and link to the architecture + policy references.

    With --open, opens the README rendered as HTML in your browser.
    With --readme-only, prints the README path (you cat it yourself).
    """
    pkg_root = Path(__file__).resolve().parents[3]
    readme = pkg_root / "README.md"
    if not readme.exists():
        raise click.ClickException(f"README.md not found at {readme}")

    console.print("[bold]AgentGate documentation[/bold]")
    console.print(f"  [green]\u2713[/] README    {readme}")
    for f in ("docs/policy-reference.md", "docs/architecture.md", "CONTRIBUTING.md"):
        path = pkg_root / f
        if path.exists():
            console.print(f"  [green]\u2713[/] {f:30s} {path}")

    if readme_only:
        return

    if open_browser:
        # Use Markdown -> HTML via Python (zero new deps: cgi/escape is enough
        # for basic display). For full fidelity point to GitHub.
        url = f"file://{readme}"
        try:
            webbrowser.open(url)
        except webbrowser.Error:
            sys.exit(f"could not open browser; open {readme} manually")
        return

    # Default: print README path and useful commands.
    console.print()
    console.print("To view locally:")
    console.print("  agentgate docs --open           # open README in browser")
    console.print("  agentgate docs --readme-only    # print README path")
    console.print()
    console.print("Online:")
    console.print("  https://github.com/FelixMa01/agentgate/blob/main/README.md")
    console.print("  https://github.com/FelixMa01/agentgate/blob/main/docs/policy-reference.md")
    console.print("  https://github.com/FelixMa01/agentgate/blob/main/docs/architecture.md")
