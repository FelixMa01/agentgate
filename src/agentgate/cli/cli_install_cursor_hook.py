"""`agentgate install-cursor-hook` — Cursor beforeShellExecution wiring."""
from __future__ import annotations
import json
from pathlib import Path
from shlex import quote as shlex_quote

import click

from . import console
from ._common import resolve_db, resolve_policy


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


@click.command(name="install-cursor-hook")
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
@click.option("--db", required=True, type=click.Path())
@click.option("--target", "target_dir", default=".")
def install_cursor_hook(policy: str, db: str, target_dir: str) -> None:
    """Install AgentGate as a Cursor beforeShellExecution script.

    Writes .cursor/hooks.json pointing at `python -m agentgate.cursor_hook`
    using the project venv's python.
    """
    policy_abs = str(resolve_policy(policy))
    db_abs = str(resolve_db(db))
    target = Path(target_dir).resolve()
    cursor_dir = target / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)
    py = _project_root() / ".venv" / "bin" / "python"
    cmd = (
        f"AGENTGATE_POLICY={shlex_quote(policy_abs)} "
        f"AGENTGATE_DB={shlex_quote(db_abs)} "
        f"{shlex_quote(str(py))} -m agentgate.cursor_hook"
    )
    hooks_cfg = {
        "version": 1,
        "hooks": {
            "beforeShellExecution": [{"command": cmd}],
            "beforeFileEdit":       [{"command": cmd}],
            "beforeFileRead":       [{"command": cmd}],
        },
    }
    cfg_path = cursor_dir / "hooks.json"
    cfg_path.write_text(json.dumps(hooks_cfg, indent=2))
    console.print(f"[green]\u2713[/] Wrote {cfg_path}")
    console.print(f"  policy: {policy_abs}")
    console.print(f"  audit:  {db_abs}")
    console.print("[yellow]\u00b7[/] Restart Cursor to pick up the new hooks.")