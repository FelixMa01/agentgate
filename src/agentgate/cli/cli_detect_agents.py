"""Auto-detect which AI agent is installed and wire up the matching hook.

Detection looks at well-known config paths in $HOME:

  Claude Code     ~/.claude/hooks.json
  Cursor          ~/.cursor/hooks.json
  Continue.dev    ~/.continue/hooks/agentgate.py
  Aider           ~/.aider.conf.yml
  GitHub Actions  $REPO/.github/workflows/*.yml
"""
from __future__ import annotations

import os
from pathlib import Path

import click

from . import console

AGENT_MARKERS = [
    ("claude-code",     "~/.claude/"),
    ("cursor",          "~/.cursor/"),
    ("continue-dev",    "~/.continue/"),
    ("aider",           "~/.aider.conf.yml"),
    ("github-actions",  "~/.config/gh/hosts.yml"),  # proxy for gh CLI installed
]


@click.command(name="detect-agents")
def detect_agents() -> None:
    """List installed AI coding agents on this host."""
    found = []
    for name, marker in AGENT_MARKERS:
        p = Path(os.path.expanduser(marker))
        if p.exists():
            found.append((name, str(p)))
    if not found:
        console.print("[yellow]No AI coding agents detected.[/]")
        console.print("Run `agentgate install-hook` (or `--agent cursor` / `continue` / `aider`).")
        return
    console.print(f"[green]\u2713[/] Detected {len(found)} agent(s):")
    for name, path in found:
        console.print(f"  [cyan]{name}[/cyan]: {path}")
    console.print()
    console.print("Run [bold]agentgate install-hook --agent <name>[/bold] to wire AgentGate.")
