"""`agentgate validate` — check a policy YAML for syntactic correctness."""
from __future__ import annotations
import click

from ..policy import load_policy
from . import console
from ._common import friendly_yaml_error, resolve_policy
import yaml as _yaml


@click.command()
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
def validate(policy: str) -> None:
    """Validate a policy YAML file."""
    p = resolve_policy(policy)
    try:
        pol = load_policy(str(p))
    except _yaml.YAMLError as e:
        raise click.ClickException(friendly_yaml_error(p, e))
    console.print(f"[green]\u2713[/] Policy valid \u2014 {len(pol.rules)} rules, default={pol.default_action.value}")
    if pol.network:
        if pol.allowed_domains:
            console.print(f"  network: {len(pol.allowed_domains)} allowed domains")
        if pol.denied_domains:
            console.print(f"  network: {len(pol.denied_domains)} denied domains")
        if pol.require_https:
            console.print("  network: HTTPS required")
    meta = pol.metadata or {}
    if meta:
        for k in ("author", "name", "version", "last_reviewed"):
            if k in meta:
                console.print(f"  metadata.{k}: {meta[k]}")
        if "description" in meta:
            console.print(f"  metadata.description: {meta['description'].strip().splitlines()[0]}")
    else:
        console.print("  [yellow]\u00b7[/] no metadata block (consider adding author + version + last_reviewed)")