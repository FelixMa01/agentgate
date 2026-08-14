"""`agentgate install-continue-hook` — Continue.dev settings wiring."""

from __future__ import annotations

import json
from pathlib import Path
from shlex import quote as shlex_quote

import click

from . import console
from ._common import resolve_db, resolve_policy


def _project_root() -> Path:
    # cli/cli_install_continue_hook.py → src/agentgate/cli → src/agentgate → src → repo root
    return Path(__file__).resolve().parents[3]


@click.command(name="install-continue-hook")
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
@click.option("--db", required=True, type=click.Path())
@click.option("--target", "target_dir", default=".")
def install_continue_hook(policy: str, db: str, target_dir: str) -> None:
    """Install AgentGate as a PreToolUse hook for Continue.dev.

    Writes .continue/settings.json. Because Continue.dev uses the same wire
    format as Claude Code, this is a thin wrapper around the existing hook
    entrypoint.
    """
    policy_abs = str(resolve_policy(policy))
    db_abs = str(resolve_db(db))
    target = Path(target_dir).resolve()
    continue_dir = target / ".continue"
    continue_dir.mkdir(parents=True, exist_ok=True)
    py = _project_root() / ".venv" / "bin" / "python"
    cmd = (
        f"AGENTGATE_POLICY={shlex_quote(policy_abs)} "
        f"AGENTGATE_DB={shlex_quote(db_abs)} "
        f"{shlex_quote(str(py))} -m agentgate.continue_hook"
    )
    settings_path = continue_dir / "settings.json"
    existing = json.loads(settings_path.read_text()) if settings_path.exists() else {}
    hooks = existing.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    pre = [h for h in pre if "AGENTGATE_POLICY" not in json.dumps(h)]
    pre.append(
        {
            "matcher": "Bash|Read|Write|Edit|WebFetch|Grep|Glob",
            "hooks": [
                {
                    "type": "command",
                    "command": cmd,
                    "statusMessage": "AgentGate evaluating\u2026",
                }
            ],
        }
    )
    hooks["PreToolUse"] = pre
    existing["hooks"] = hooks
    settings_path.write_text(json.dumps(existing, indent=2) + "\n")
    console.print(f"[green]\u2713[/] Wrote PreToolUse hook to [bold]{settings_path}[/]")
    console.print(f"  policy: {policy_abs}")
    console.print(f"  audit:  {db_abs}")
    console.print("[yellow]\u00b7[/] Restart Continue to pick up the new hooks.")
    console.print("[dim]\u00b7[/] Note: Continue.dev reads .claude/settings.local.json too,")
    console.print("  so running `agentgate install-hook` also works for Continue.")
