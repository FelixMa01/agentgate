"""`agentgate doctor` — quick health check + setup recommendations."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import click

from . import console

_HOME = Path.home()


_CHECKS = [
    # (id, description, check_fn -> (passed: bool, detail: str))
    ("claude-installed", "Claude Code CLI on PATH",
     lambda: shutil.which("claude") is not None),
    ("claude-dir", "~/.claude directory exists",
     lambda: (_HOME / ".claude").exists()),
    ("node", "Node.js >= 18 (for Cursor/Continue)",
     lambda: shutil.which("node") is not None),
    ("docker", "Docker (for MCP isolation)", lambda: shutil.which("docker") is not None),
    ("gnupg", "GnuPG (for signing audit receipts)", lambda: shutil.which("gpg") is not None),
    ("agentgate-cfg", "AgentGate config present",
     lambda: any((_HOME / p).exists() for p in [".agentgate.yaml", ".agentgate.yml"])
     or os.environ.get("AGENTGATE_POLICY") is not None),
    ("agentgate-home", "~/.agentgate writable",
     lambda: _mkdir_ok(_HOME / ".agentgate")),
]


def _mkdir_ok(p: Path) -> bool:
    try:
        p.mkdir(parents=True, exist_ok=True)
        return p.is_dir()
    except Exception:
        return False


@click.command("doctor")
def doctor():
    """Print a checklist of pre-requisites for AgentGate."""
    rows = []
    for cid, desc, fn in _CHECKS:
        try:
            ok = bool(fn())
            detail = "✓" if ok else "✗"
        except Exception as exc:
            ok = False
            detail = f"error: {exc}"
        rows.append((cid, desc, ok, detail))
    width = max(len(desc) for _, desc, _, _ in rows) + 2
    fails = 0
    for cid, desc, ok, _detail in rows:
        mark = "[green]✓[/]" if ok else "[red]✗[/]"
        console.print(f"  {mark} {desc.ljust(width)}  [{cid}]")
        if not ok:
            fails += 1
    console.print("")
    if fails:
        console.print(f"[yellow]{fails} check(s) failed — install or configure above.[/]")
    else:
        console.print("[green]All checks passed.[/]")
    if fails:
        sys.exit(1)
