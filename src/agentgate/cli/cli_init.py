"""`agentgate init` — scaffold a default policy and audit DB."""
from __future__ import annotations
from pathlib import Path

import click

from . import console
from ..audit import Audit
from ._common import DEFAULT_POLICY


@click.command()
@click.option("--dir", "dir_", default=".", help="Project directory to scaffold into.")
def init(dir_: str) -> None:
    """Scaffold a default policy file and audit database."""
    target = Path(dir_)
    target.mkdir(parents=True, exist_ok=True)
    policy_path = target / "policy.yaml"
    db_path = target / "audit.db"
    if not policy_path.exists():
        policy_path.write_text(DEFAULT_POLICY)
        console.print(f"[green]\u2713[/] Wrote {policy_path}")
    else:
        console.print(f"[yellow]\u00b7[/] {policy_path} already exists, skipped")
    # Touch DB
    Audit(str(db_path)).recent(limit=1)
    console.print(f"[green]\u2713[/] Initialized audit DB at {db_path}")