"""`agentgate install-hook` / `uninstall-hook` — Claude Code PreToolUse wiring."""

from __future__ import annotations

import json
from pathlib import Path

import click

from . import console


def _project_root() -> Path:
    # cli/cli_install_hook.py → src/agentgate/cli → src/agentgate → src → repo root
    return Path(__file__).resolve().parents[3]


def _settings_path(scope: str, target_dir: str) -> Path:
    if scope == "user":
        return Path.home() / ".claude" / "settings.json"
    return Path(target_dir).resolve() / ".claude" / "settings.local.json"


def _has_agentgate(hook_entry: dict) -> bool:
    return "AGENTGATE_POLICY" in json.dumps(hook_entry)


@click.command()
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
@click.option("--db", required=True, type=click.Path())
@click.option(
    "--target",
    "target_dir",
    default=".",
    help="Directory to write .claude/settings.local.json into.",
)
@click.option(
    "--scope",
    type=click.Choice(["project", "user"]),
    default="project",
    help="project = .claude/settings.local.json; user = ~/.claude/settings.json",
)
@click.option(
    "--matchers",
    default="Bash|Read|Write|Edit|WebFetch|Grep|Glob",
    help="Pipe-separated tool names the hook fires on (default: most common).",
)
def install_hook(policy: str, db: str, target_dir: str, scope: str, matchers: str) -> None:
    """Wire AgentGate as a PreToolUse hook for Claude Code."""
    repo_root = _project_root()
    hook_script = repo_root / "bin" / "agentgate-hook.py"
    if not hook_script.exists():
        raise click.ClickException(f"Hook script not found at {hook_script}")

    policy_abs = str(Path(policy).resolve())
    db_abs = str(Path(db).resolve())

    env = {"AGENTGATE_POLICY": policy_abs, "AGENTGATE_DB": db_abs}
    hook_entry = {
        "matcher": matchers,
        "hooks": [
            {
                "type": "command",
                "command": str(hook_script),
                "env": env,
                "statusMessage": "AgentGate evaluating\u2026",
            }
        ],
    }

    settings_path = _settings_path(scope, target_dir)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    existing = json.loads(settings_path.read_text()) if settings_path.exists() else {}
    hooks = existing.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    pre = [h for h in pre if not _has_agentgate(h)]
    pre.append(hook_entry)
    hooks["PreToolUse"] = pre
    existing["hooks"] = hooks
    settings_path.write_text(json.dumps(existing, indent=2) + "\n")
    console.print(f"[green]\u2713[/] Wrote PreToolUse hook to [bold]{settings_path}[/]")
    console.print(f"  matcher: [cyan]{matchers}[/]")
    console.print(f"  script:  [dim]{hook_script}[/]")
    console.print(f"  policy:  [dim]{policy_abs}[/]")
    console.print(f"  db:      [dim]{db_abs}[/]")
    console.print("\n[yellow]Note:[/] The hook script expects Python 3.12+ with")
    console.print("agentgate installed. Run [bold]uv sync[/] in the project root.")
    console.print("\n[dim]Test it:[/]")
    console.print(
        f'  echo \'{{"tool_name":"Bash","tool_input":{{"command":"rm -rf /etc"}}}}\' | '
        f"AGENTGATE_POLICY={policy_abs} AGENTGATE_DB={db_abs} {hook_script}"
    )


@click.command()
@click.option("--scope", type=click.Choice(["project", "user"]), default="project")
@click.option("--target", "target_dir", default=".")
def uninstall_hook(scope: str, target_dir: str) -> None:
    """Remove AgentGate PreToolUse hooks from Claude Code settings."""
    settings_path = _settings_path(scope, target_dir)
    if not settings_path.exists():
        console.print(f"[yellow]\u00b7[/] {settings_path} doesn't exist, nothing to remove.")
        return
    existing = json.loads(settings_path.read_text())
    pre = existing.get("hooks", {}).get("PreToolUse", [])
    kept = [h for h in pre if not _has_agentgate(h)]
    if not kept:
        existing.get("hooks", {}).pop("PreToolUse", None)
    else:
        existing["hooks"]["PreToolUse"] = kept
    settings_path.write_text(json.dumps(existing, indent=2) + "\n")
    console.print(f"[green]\u2713[/] Removed AgentGate hooks from [bold]{settings_path}[/]")
