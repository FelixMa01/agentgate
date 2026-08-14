"""AgentGate CLI — initialize, evaluate, audit, dashboard."""
from __future__ import annotations
from pathlib import Path
import json
import sys

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .audit import Audit
from .policy import Action, load_policy


DEFAULT_POLICY = """\
version: 1
default: allow

rules:
  - id: deny-rm-rf
    name: Block destructive rm
    match:
      tool: Bash
      command_glob: "rm -rf /*"
    action: deny
    reason: "Mass deletion outside repo"

  - id: deny-secrets-read
    name: Block reading secrets
    match:
      tool: Read
      file_glob: ["*.pem", ".env*", "*id_rsa*"]
    action: deny
    reason: "Secret files are off-limits"

  - id: ask-network-exfil
    name: Require approval for new domains
    match:
      tool: Bash
      command_glob: ["curl *", "wget *", "http*"]
    action: ask
    reason: "Outbound network from agent"

  - id: log-grep
    name: Log read-only search
    match:
      tool: Grep
    action: log
    reason: ""

network:
  allowed_domains:
    - github.com
    - "*.githubusercontent.com"
    - pypi.org
    - "*.pypi.org"
    - openai.com
    - "*.openai.com"
    - anthropic.com
    - "*.anthropic.com"
  denied_domains:
    - pastebin.com
    - transfer.sh
    - "*gist.github.com/leak*"
  require_https: true
"""


console = Console()


@click.group()
@click.version_option(__version__)
def main() -> None:
    """AgentGate — firewall for AI coding agents."""


@main.command()
@click.option("--dir", "dir_", default=".", help="Project directory to scaffold into.")
def init(dir_: str) -> None:
    """Scaffold a default policy file and audit database."""
    target = Path(dir_)
    target.mkdir(parents=True, exist_ok=True)
    policy_path = target / "policy.yaml"
    db_path = target / "audit.db"
    if not policy_path.exists():
        policy_path.write_text(DEFAULT_POLICY)
        console.print(f"[green]✓[/] Wrote {policy_path}")
    else:
        console.print(f"[yellow]·[/] {policy_path} already exists, skipped")
    # Touch DB
    Audit(db_path).recent(limit=1)
    console.print(f"[green]✓[/] Initialized audit DB at {db_path}")


@main.command()
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
@click.option("--db", required=True, type=click.Path())
@click.option("--source", default="manual", help="Event source label.")
@click.option("--agent", default=None, help="Agent identifier.")
@click.option("--event-json", "event_json", default="{}", help="JSON event payload to evaluate.")
def eval(
    policy: str,
    db: str,
    source: str,
    agent: str | None,
    event_json: str,
) -> None:
    """Evaluate an event against the policy and record the decision."""
    pol = load_policy(policy)
    audit = Audit(db)
    try:
        event = json.loads(event_json)
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON: {e}")
    action, rule = pol.evaluate(event)
    audit.record(
        source=source,
        agent=agent,
        action=action,
        event=event,
        rule_id=rule.id if rule else None,
        rule_name=rule.name if rule else None,
        reason=rule.reason if rule else None,
    )
    icon = {"allow": "✓", "deny": "✗", "ask": "?", "log": "·"}[action.value]
    color = {"allow": "green", "deny": "red", "ask": "yellow", "log": "dim"}[action.value]
    console.print(f"[{color}]{icon} {action.value.upper()}[/]", end="")
    if rule:
        console.print(f"  [bold]{rule.name}[/]  ({rule.id})")
        if rule.reason:
            console.print(f"   reason: {rule.reason}")
    else:
        console.print("  [dim](default policy)[/]")


@main.command()
@click.option("--db", required=True, type=click.Path())
@click.option("--limit", default=20, type=int)
@click.option("--action", "action_filter", default=None,
              type=click.Choice([a.value for a in Action]))
def audit_cmd(db: str, limit: int, action_filter: str | None) -> None:
    """Show recent audit log entries."""
    audit = Audit(db)
    rows = audit.recent(limit=limit, action=Action(action_filter) if action_filter else None)
    if not rows:
        console.print("[dim]No events recorded yet.[/]")
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("ts", style="dim")
    table.add_column("src")
    table.add_column("action")
    table.add_column("rule")
    table.add_column("reason")
    for r in rows:
        from datetime import datetime
        ts = datetime.fromtimestamp(r["ts"]).strftime("%H:%M:%S")
        table.add_row(
            ts,
            r["source"],
            r["action"].upper(),
            r["rule_id"] or "—",
            (r["reason"] or "")[:50],
        )
    console.print(table)
    stats = audit.stats()
    summary = ", ".join(f"{k}={v}" for k, v in stats.items())
    console.print(f"\n[dim]Totals: {summary}[/]")


@main.command()
@click.option("--db", required=True, type=click.Path())
def stats(db: str) -> None:
    """Show aggregate audit statistics."""
    audit = Audit(db)
    s = audit.stats()
    table = Table(show_header=True)
    table.add_column("action")
    table.add_column("count", justify="right")
    for k in ("allow", "deny", "ask", "log"):
        table.add_row(k.upper(), str(s.get(k, 0)))
    console.print(table)


@main.command()
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
def validate(policy: str) -> None:
    """Validate a policy YAML file."""
    pol = load_policy(policy)
    console.print(f"[green]✓[/] Policy valid — {len(pol.rules)} rules, default={pol.default_action.value}")


@main.command()
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
@click.option("--db", required=True, type=click.Path())
@click.option("--target", "target_dir", default=".",
              help="Directory to write .claude/settings.local.json into.")
@click.option("--scope", type=click.Choice(["project", "user"]), default="project",
              help="project = .claude/settings.local.json; user = ~/.claude/settings.json")
@click.option("--matchers", default="Bash|Read|Write|Edit|WebFetch|Grep|Glob",
              help="Pipe-separated tool names the hook fires on (default: most common).")
def install_hook(policy: str, db: str, target_dir: str, scope: str, matchers: str) -> None:
    """Wire AgentGate as a PreToolUse hook for Claude Code.

    Writes (or merges) settings.json with a hook handler that points at
    bin/agentgate-hook.py, with AGENTGATE_POLICY / AGENTGATE_DB env vars set.
    """
    import json
    import shutil

    repo_root = Path(__file__).resolve().parents[2]
    hook_script = repo_root / "bin" / "agentgate-hook.py"
    if not hook_script.exists():
        raise click.ClickException(f"Hook script not found at {hook_script}")

    policy_abs = str(Path(policy).resolve())
    db_abs = str(Path(db).resolve())

    env = {
        "AGENTGATE_POLICY": policy_abs,
        "AGENTGATE_DB": db_abs,
    }

    hook_entry = {
        "matcher": matchers,
        "hooks": [
            {
                "type": "command",
                "command": str(hook_script),
                "env": env,
                "statusMessage": "AgentGate evaluating…",
            }
        ],
    }

    if scope == "user":
        settings_path = Path.home() / ".claude" / "settings.json"
    else:
        settings_path = Path(target_dir).resolve() / ".claude" / "settings.local.json"
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    if settings_path.exists():
        existing = json.loads(settings_path.read_text())
    else:
        existing = {}

    hooks = existing.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    # Replace existing AgentGate hooks (by env var fingerprint) to keep idempotent.
    pre = [h for h in pre if "AGENTGATE_POLICY" not in json.dumps(h)]
    pre.append(hook_entry)
    hooks["PreToolUse"] = pre
    existing["hooks"] = hooks

    settings_path.write_text(json.dumps(existing, indent=2) + "\n")
    console.print(f"[green]✓[/] Wrote PreToolUse hook to [bold]{settings_path}[/]")
    console.print(f"  matcher: [cyan]{matchers}[/]")
    console.print(f"  script:  [dim]{hook_script}[/]")
    console.print(f"  policy:  [dim]{policy_abs}[/]")
    console.print(f"  db:      [dim]{db_abs}[/]")
    console.print("\n[yellow]Note:[/] The hook script expects Python 3.12+ with")
    console.print("agentgate installed. Run [bold]uv sync[/] in the project root.")
    console.print("\n[dim]Test it:[/]")
    console.print(f'  echo \'{{"tool_name":"Bash","tool_input":{{"command":"rm -rf /etc"}}}}\\\' | AGENTGATE_POLICY={policy_abs} AGENTGATE_DB={db_abs} {hook_script}')


@main.command()
@click.option("--scope", type=click.Choice(["project", "user"]), default="project")
@click.option("--target", "target_dir", default=".")
def uninstall_hook(scope: str, target_dir: str) -> None:
    """Remove AgentGate PreToolUse hooks from Claude Code settings."""
    import json

    if scope == "user":
        settings_path = Path.home() / ".claude" / "settings.json"
    else:
        settings_path = Path(target_dir).resolve() / ".claude" / "settings.local.json"

    if not settings_path.exists():
        console.print(f"[yellow]·[/] {settings_path} doesn't exist, nothing to remove.")
        return

    existing = json.loads(settings_path.read_text())
    pre = existing.get("hooks", {}).get("PreToolUse", [])
    kept = [h for h in pre if "AGENTGATE_POLICY" not in json.dumps(h)]
    if not kept:
        existing.get("hooks", {}).pop("PreToolUse", None)
    else:
        existing["hooks"]["PreToolUse"] = kept
    settings_path.write_text(json.dumps(existing, indent=2) + "\n")
    console.print(f"[green]✓[/] Removed AgentGate hooks from [bold]{settings_path}[/]")


# Alias to avoid keyword conflict
audit_cmd.name = "audit"


if __name__ == "__main__":
    main()