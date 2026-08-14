"""`agentgate lint` - check a policy.yaml for common mistakes."""
from __future__ import annotations

import sys
from pathlib import Path

import click

from .. import __version__
from ..policy import load_policy


@click.command()
@click.option("--policy", "-p", required=True, type=click.Path(exists=True), help="Policy YAML to lint.")
@click.option("--quiet", "-q", is_flag=True, help="Only show errors.")
def lint(policy: str, quiet: bool) -> None:
    """Check a policy YAML for duplicate IDs, empty match, missing reasons, etc.

    Exit code 0 = no issues, 1 = errors found, 2 = invalid YAML / file error.
    """
    try:
        policy_obj = load_policy(policy)
    except Exception as exc:
        click.echo(f"error: failed to load policy: {exc}", err=True)
        sys.exit(2)

    warnings, errors = [], []
    seen_ids: set[str] = set()
    for _i, rule in enumerate(policy_obj.rules):
        if rule.id in seen_ids:
            errors.append(f"duplicate rule id: {rule.id!r}")
        seen_ids.add(rule.id)

        if not rule.match:
            errors.append(f"rule {rule.id!r}: empty match")

        if rule.action.value == "deny" and not rule.reason:
            errors.append(f"rule {rule.id!r}: deny action without reason")



    # Default-action validation
    default = getattr(policy_obj, "default_action", None)
    if default is None or default.value not in ("allow", "deny"):
        errors.append(f"invalid default action: {default!r}")

    if not quiet:
        click.echo(f"Linting {policy}")
        click.echo(f"  {len(policy_obj.rules)} rules, default={default.value if default else None!r}, network={getattr(policy_obj, 'network', False)!r}")

    for w in warnings:
        if not quiet:
            click.echo(f"  warning: {w}")
    for e in errors:
        click.echo(f"  error: {e}")

    if errors:
        click.echo(f"\n{len(errors)} error(s), {len(warnings)} warning(s)", err=True)
        sys.exit(1)
    if warnings:
        click.echo(f"\n{len(warnings)} warning(s)")
    elif not quiet:
        click.echo("\nOK - no issues")
