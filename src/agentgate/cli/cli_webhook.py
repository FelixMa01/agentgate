"""`agentgate webhook` — manage webhook subscriptions and test delivery."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from ..webhooks import (
    DEFAULT_PATH,
    Webhook,
    deliver,
    load_webhooks,
    save_webhooks,
)


@click.group("webhook")
def webhook() -> None:
    """Manage webhook subscriptions."""


@webhook.command("list")
@click.option("--config", "config_path", type=click.Path(), default=None)
def webhook_list(config_path: str | None) -> None:
    """List configured webhooks."""
    whs = load_webhooks(config_path)
    if not whs:
        click.echo("No webhooks configured.")
        return
    for w in whs:
        click.echo(f"  {w.name}: {w.url}")
        if w.on:
            click.echo(f"    filter: {w.on}")
        if w.template:
            click.echo(f"    template: {w.template!r}")


@webhook.command("add")
@click.argument("name")
@click.argument("url")
@click.option("--action", multiple=True, help="Filter on action (allow/ask/deny).")
@click.option("--source", multiple=True, help="Filter on source.")
@click.option("--template", default="", help="Custom message template.")
@click.option("--config", "config_path", type=click.Path(), default=None)
def webhook_add(name: str, url: str, action: tuple[str, ...],
                source: tuple[str, ...], template: str,
                config_path: str | None) -> None:
    """Add a new webhook."""
    whs = load_webhooks(config_path)
    on: dict[str, object] = {}
    if action:
        on["action"] = list(action)
    if source:
        on["source"] = list(source)
    whs.append(Webhook(name=name, url=url, on=on, template=template))
    save_webhooks(whs, config_path)
    click.echo(f"Added webhook '{name}'.")


@webhook.command("remove")
@click.argument("name")
@click.option("--config", "config_path", type=click.Path(), default=None)
def webhook_remove(name: str, config_path: str | None) -> None:
    """Remove a webhook by name."""
    whs = load_webhooks(config_path)
    before = len(whs)
    whs = [w for w in whs if w.name != name]
    if len(whs) == before:
        click.echo(f"No webhook named '{name}'.", err=True)
        sys.exit(1)
    save_webhooks(whs, config_path)
    click.echo(f"Removed webhook '{name}'.")


@webhook.command("test")
@click.option("--config", "config_path", type=click.Path(), default=None)
@click.option("--url", default=None, help="Override: send a test to a single URL.")
def webhook_test(config_path: str | None, url: str | None) -> None:
    """Send a test event to all matching webhooks."""
    event = {
        "action": "deny",
        "source": "claude-code",
        "agent": "test-agent",
        "rule_id": "test-rule",
        "rule_name": "Test rule",
        "reason": "manual webhook test",
    }
    if url:
        whs = [Webhook(name="cli-test", url=url, on={}, template="test: {rule_name}")]
    else:
        whs = load_webhooks(config_path)
    results = deliver(event, webhooks=whs)
    if not results:
        click.echo("No matching webhooks (or none configured).")
        return
    for name, ok, msg in results:
        click.echo(f"  {name}: {'OK' if ok else 'FAIL'} ({msg})")


if __name__ == "__main__":
    webhook()
