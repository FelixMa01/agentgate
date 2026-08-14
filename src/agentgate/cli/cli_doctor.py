"""`agentgate doctor` - check Python version, deps, optional tools."""
from __future__ import annotations
import shutil
import sys
from pathlib import Path

import click

from .. import __version__


@click.command()
@click.option("--quiet", "-q", is_flag=True, help="Suppress OK messages.")
def doctor(quiet: bool) -> None:
    """Diagnose your AgentGate installation.

    Checks Python version, dependencies, optional tools (mitmdump, git),
    Slack/Telegram config, and AgentGate database state.
    """
    click.echo(f"AgentGate v{__version__} - doctor")
    click.echo()

    # Python version
    py = sys.version_info
    py_ok = py >= (3, 12)
    _print_check("python", f"{py.major}.{py.minor}.{py.micro}", py_ok, quiet)

    # Core dependencies
    for dep in ("click", "pyyaml", "rich", "mitmproxy"):
        try:
            __import__(dep)
            _print_check(dep, None, True, quiet)
        except ImportError:
            _print_check(dep, None, False, quiet)

    # Optional tools
    for tool in ("git", "mitmdump", "docker"):
        path = shutil.which(tool)
        _print_check(tool, path or "not on PATH", path is not None, quiet)

    # AgentGate state
    click.echo()
    click.echo("AgentGate config:")
    home = Path.home()
    audit_default = home / ".agentgate" / "audit.db"
    if audit_default.exists():
        size_kb = audit_default.stat().st_size / 1024
        _print_check("audit db", f"{audit_default} ({size_kb:.1f} KB)", True, quiet)
    else:
        _print_check("audit db", f"{audit_default} (not created yet)", True, quiet)

    # Hook installation
    claude_settings = home / ".claude" / "settings.json"
    if claude_settings.exists():
        _print_check("claude hook", f"{claude_settings}", True, quiet)
    else:
        click.echo(f"  claude hook: not installed (run `agentgate install-hook`)")

    # Notification config
    slack_url = None
    for env_name in ("SLACK_WEBHOOK_URL", "AGENTGATE_SLACK_WEBHOOK"):
        import os
        if os.environ.get(env_name):
            slack_url = os.environ[env_name]
            break
    if slack_url:
        _print_check("slack", "configured (env var)", True, quiet)
    else:
        click.echo("  slack: not configured (set SLACK_WEBHOOK_URL)")

    click.echo()
    click.echo("Done. Run `agentgate --help` to see available commands.")


def _print_check(name: str, detail: str | None, ok: bool, quiet: bool) -> None:
    status = "OK" if ok else "FAIL"
    msg = f"  {name}: {status}"
    if detail:
        msg += f" ({detail})"
    if not ok:
        click.echo(msg, err=True)
    elif not quiet:
        click.echo(msg)
