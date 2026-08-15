"""`agentgate install-codex-hook` — Codex CLI settings wiring."""

from __future__ import annotations

import json
from pathlib import Path
from shlex import quote as shlex_quote

import click

from . import console
from ._common import resolve_db, resolve_policy


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


@click.command(name="install-codex-hook")
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
@click.option("--db", required=True, type=click.Path())
@click.option("--target", "target_dir", default=".")
@click.option("--global", "global_install", is_flag=True,
              help="Install into ~/.codex/hooks.json instead of project-local")
def install_codex_hook(policy: str, db: str, target_dir: str, global_install: bool) -> None:
    """Install AgentGate as a Before hook for OpenAI Codex CLI.

    Writes ~/.codex/hooks.json (with --global) or
    <target>/.codex/hooks.json (project-local, default).
    """
    policy_abs = str(resolve_policy(policy))
    db_abs = str(resolve_db(db))
    if global_install:
        settings_path = Path.home() / ".codex" / "hooks.json"
    else:
        settings_path = Path(target_dir).resolve() / ".codex" / "hooks.json"
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    py = _project_root() / ".venv" / "bin" / "python"
    cmd = (
        f"AGENTGATE_POLICY={shlex_quote(policy_abs)} "
        f"AGENTGATE_DB={shlex_quote(db_abs)} "
        f"{shlex_quote(str(py))} -m agentgate.codex_hook"
    )

    existing = json.loads(settings_path.read_text()) if settings_path.exists() else {}
    hooks = existing.setdefault("hooks", {})
    before = hooks.setdefault("Before", [])
    before = [h for h in before if "AGENTGATE_POLICY" not in json.dumps(h)]
    before.append(
        {
            "matcher": ".*",
            "hooks": [
                {
                    "type": "command",
                    "command": cmd,
                    "statusMessage": "AgentGate evaluating\u2026",
                }
            ],
        }
    )
    hooks["Before"] = before
    existing["hooks"] = hooks
    settings_path.write_text(json.dumps(existing, indent=2) + "\n")
    console.print(f"[green]\u2713[/] Wrote Before hook to [bold]{settings_path}[/]")
    console.print(f"  policy: {policy_abs}")
    console.print(f"  audit:  {db_abs}")
    console.print("[yellow]\u00b7[/] Restart Codex CLI to pick up the new hooks.")
