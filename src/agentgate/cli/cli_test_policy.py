"""`agentgate policy test` — simulate events against a policy without side effects.

Usage:
    agentgate policy test policy.yaml event.json
    agentgate policy test policy.yaml --tool Bash --command "rm -rf /"
    echo '{"tool":"Bash","command":"..."}' | agentgate policy test policy.yaml -
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .. import policy as policy_mod


@click.group(name="policy")
def policy_group() -> None:
    """Inspect and test policies."""


@policy_group.command(name="test")
@click.argument("policy_path", type=click.Path(exists=True))
@click.argument("event", required=False)
@click.option("--tool", help="Tool name (e.g. Bash, Read, WebFetch).")
@click.option("--command", help="Command string (for Bash/tool=cli tools).")
@click.option("--url", help="URL (for WebFetch).")
@click.option("--path", "path_", help="File path (for Read/Write/Edit).")
@click.option("--agent", default="cli", help="Agent name (default: cli).")
@click.option("--source", default="cli", help="Event source (default: cli).")
@click.option("--explain", is_flag=True, help="Show why each rule matched/missed.")
def test_cmd(
    policy_path: str,
    event: str,
    tool: str | None,
    command: str | None,
    url: str | None,
    path_: str | None,
    agent: str,
    source: str,
    explain: bool,
) -> None:
    """Simulate an event against POLICY_PATH without side effects."""
    p = policy_mod.load_policy(policy_path)

    if event is None or event == "-":
        # try stdin if it's piped, else expect --tool/--command
        if sys.stdin.isatty():
            ev = {}
        else:
            raw = sys.stdin.read().strip()
            ev = json.loads(raw) if raw else {}
        if not (tool or command or url or path_) and not ev:
            raise click.UsageError("Provide EVENT (file or stdin JSON) OR --tool/--command/--url/--path")
    elif Path(event).exists():
        ev = json.loads(Path(event).read_text())
    else:
        ev = json.loads(event)

    if tool:
        ev["tool"] = tool
    if command:
        ev["command"] = command
    if url:
        ev["url"] = url
    if path_:
        ev["path"] = path_
    ev.setdefault("agent", agent)
    ev.setdefault("source", source)

    if explain:
        result = p.evaluate_explain(ev)
        click.echo(json.dumps(result, indent=2))
    else:
        action, rule = p.evaluate(ev)
        click.echo(action.value)
        if rule is not None:
            click.echo(f"# matched rule #{rule.id}: {rule.name} — {rule.reason or ''}", err=True)


test_cmd.help = "Simulate an event against a policy without side effects."
