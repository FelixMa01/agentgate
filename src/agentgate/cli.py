"""AgentGate CLI — initialize, evaluate, audit, dashboard."""
from __future__ import annotations
import os
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


@main.command()
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
@click.option("--db", required=True, type=click.Path())
@click.option("--listen-host", default="127.0.0.1")
@click.option("--listen-port", default=8080, type=int)
@click.option("--mode", default="regular",
              type=click.Choice(["regular", "transparent", "socks5"]))
def proxy(policy: str, db: str, listen_host: str, listen_port: int, mode: str) -> None:
    """Start the AgentGate HTTP egress proxy (mitmproxy add-on).

    Set HTTP_PROXY=http://127.0.0.1:8080 and HTTPS_PROXY=... to route traffic
    through this proxy. Every request is evaluated against policy.network
    and recorded in the audit DB.
    """
    import subprocess

    addon_path = Path(__file__).resolve().parents[1] / "src" / "agentgate" / "proxy_addon.py"
    if not addon_path.exists():
        raise click.ClickException(f"add-on not found: {addon_path}")

    env = {
        **os.environ,
        "AGENTGATE_POLICY": str(Path(policy).resolve()),
        "AGENTGATE_DB": str(Path(db).resolve()),
    }

    cmd = [
        "mitmdump",
        "--mode", mode,
        "--listen-host", listen_host,
        "--listen-port", str(listen_port),
        "--set", "block_global=false",
        "--scripts", str(addon_path),
        "--showhost",
    ]
    console.print(f"[cyan]→[/] Starting AgentGate proxy on {listen_host}:{listen_port} ({mode} mode)")
    console.print(f"  policy: [dim]{policy}[/]")
    console.print(f"  db:     [dim]{db}[/]")
    console.print(f"  add-on: [dim]{addon_path}[/]\n")
    console.print("[dim]In another terminal:[/]")
    console.print(f"  export HTTP_PROXY=http://{listen_host}:{listen_port}")
    console.print(f"  export HTTPS_PROXY=http://{listen_host}:{listen_port}")
    console.print(f"  curl https://api.github.com\n")
    try:
        subprocess.run(cmd, env=env, check=True)
    except KeyboardInterrupt:
        console.print("\n[yellow]·[/] Proxy stopped")
    except FileNotFoundError:
        raise click.ClickException(
            "mitmdump not found. Run `uv sync` to install it, or activate the venv."
        )


@main.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8765, type=int)
def approval_server(host: str, port: int) -> None:
    """Start the approval HTTP server (handles Slack Approve/Deny clicks)."""
    from .approval_server import serve
    console.print(f"[cyan]→[/] AgentGate approval server on http://{host}:{port}")
    serve(host, port)


@main.command(name="ask-test")
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
@click.option("--db", required=True, type=click.Path())
@click.option("--event-json", required=True, help="JSON event to evaluate (will be forced to ask).")
@click.option("--approve-after", default=2.0, type=float,
              help="Seconds to wait before resolving the ask automatically.")
def ask_test(policy: str, db: str, event_json: str, approve_after: float) -> None:
    """Smoke-test: evaluate an event as ASK, then auto-resolve it from this process.

    Useful for verifying the Slack + approval roundtrip without spinning up the server.
    """
    import threading
    import time as _time
    pol = load_policy(policy)
    audit = Audit(db)
    event = json.loads(event_json)
    # Bypass policy and force ask on the first matching rule's structure
    rule = pol.rules[0] if pol.rules else None
    audit.record(source="ask-test", agent="local",
                 action=Action.ASK, event=event,
                 rule_id=rule.id if rule else "manual",
                 rule_name=rule.name if rule else "Manual ASK",
                 reason="ask-test manual trigger")
    # Simulate notify
    from .approval import STORE
    ask = STORE.request(event, event.get("tool", "?"), "ask-test")
    console.print(f"[cyan]→[/] Created ask token [bold]{ask.token}[/]")
    console.print(f"  resolution will be 'allow' after {approve_after}s")
    def _resolve_later():
        _time.sleep(approve_after)
        STORE.resolve(ask.token, "allow")
    threading.Thread(target=_resolve_later, daemon=True).start()
    decision = STORE.wait(ask.token, timeout=approve_after + 5)
    console.print(f"[green]✓[/] Resolved: {decision}")
    audit.record(source="ask-test", agent="local",
                 action=Action(decision), event={**event, "_resolved": decision},
                 rule_id="ask-test", rule_name="Manual ASK",
                 reason="ask-test resolution")


@main.command()
@click.option("--db", required=True, type=click.Path())
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8766, type=int)
def dashboard(db: str, host: str, port: int) -> None:
    """Start the AgentGate audit dashboard HTTP server."""
    from .dashboard import serve
    console.print(f"[cyan]→[/] AgentGate dashboard on http://{host}:{port}")
    serve(db, host, port)


# Alias to avoid keyword conflict
audit_cmd.name = "audit"


if __name__ == "__main__":
    main()