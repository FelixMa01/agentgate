"""`agentgate alerts` — evaluate alert rules against the audit DB."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import click

from ..audit import Audit
from . import console


@click.command()
@click.option("--db", required=True, type=click.Path(), help="SQLite audit DB path.")
@click.option("--rules", required=True, type=click.Path(), help="Alert rules YAML.")
@click.option("--once/--watch", default=True,
              help="Run once and exit, or watch the DB for new events.")
@click.option("--interval", default=30, help="Watch interval in seconds.")
def alerts(db: str, rules: str, once: bool, interval: int) -> None:
    """Evaluate alert rules against the audit DB.

    Example rules file:
        rules:
          - name: spike-of-denies
            window_minutes: 5
            threshold: 10
            action: deny
            message: "{{count}} denies in {{window}} minutes"
    """
    try:
        import yaml
    except ImportError:
        raise click.ClickException("PyYAML not installed")

    raw = yaml.safe_load(Path(rules).read_text())
    alert_rules = raw.get("rules", [])
    if not alert_rules:
        raise click.ClickException("rules file has no rules: section")

    audit = Audit(db)
    triggered = 0
    while True:
        for rule in alert_rules:
            window = rule.get("window_minutes", 60) * 60
            threshold = rule.get("threshold", 1)
            action = rule.get("action")
            since_ts = int(time.time()) - window
            events = audit.since_within(since_ts, action=action)
            count = len(events)
            if count >= threshold:
                msg_template = rule.get("message", f"alert {rule['name']} fired")
                msg = (msg_template
                       .replace("{{count}}", str(count))
                       .replace("{{window}}", str(window // 60)))
                triggered += 1
                console.print(f"[red]\u26a0 {rule['name']}[/red]: {msg}")
        if once:
            break
        time.sleep(interval)
    console.print(f"[green]\u2713[/green] {triggered} alerts fired")
