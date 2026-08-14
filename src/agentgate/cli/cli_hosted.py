"""`agentgate pull-policy` / `agentgate push-events` — hosted team mode."""

from __future__ import annotations

import click

from .. import hosted
from . import console


@click.command("pull-policy")
@click.option("--url", default=None, help="Override AGENTGATE_HOSTED_URL.")
@click.option(
    "--out", default="policy.hosted.yaml", help="Local file to write the pulled policy to."
)
def pull_policy(url: str | None, out: str) -> None:
    """Download a policy from the hosted endpoint."""
    try:
        path = hosted.pull_policy(url=url, cache=__import__("pathlib").Path(out))
    except RuntimeError as e:
        raise click.ClickException(str(e))
    console.print(f"[green]\u2713[/] Policy cached at {path}")


@click.command("push-events")
@click.option("--db", required=True, type=click.Path())
@click.option("--url", default=None, help="Override AGENTGATE_HOSTED_URL.")
def push_events(db: str, url: str | None) -> None:
    """Upload audit events to the hosted endpoint."""
    try:
        n = hosted.push_events(db, url=url)
    except RuntimeError as e:
        raise click.ClickException(str(e))
    console.print(f"[green]\u2713[/] Uploaded {n} event(s)")
