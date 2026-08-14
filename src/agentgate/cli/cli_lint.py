"""`agentgate lint` — policy sanity checks beyond syntax."""

from __future__ import annotations

import click
import yaml as _yaml

from ..policy import Action, load_policy
from . import console
from ._common import friendly_yaml_error, resolve_policy


@click.command()
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
@click.option("--strict", is_flag=True, help="Treat warnings as errors.")
def lint(policy: str, strict: bool) -> None:
    """Lint a policy.yaml — find duplicate IDs, missing fields, dead rules, etc."""
    p = resolve_policy(policy)
    try:
        pol = load_policy(str(p))
    except _yaml.YAMLError as e:
        raise click.ClickException(friendly_yaml_error(p, e))

    errors: list[str] = []
    warnings: list[str] = []

    # 1. Duplicate rule IDs.
    seen: dict[str, int] = {}
    for _i, r in enumerate(pol.rules):
        seen[r.id] = seen.get(r.id, 0) + 1
    dupes = [rid for rid, n in seen.items() if n > 1]
    if dupes:
        errors.append(f"duplicate rule IDs: {dupes}")

    # 2. Missing 'reason' on deny rules.
    for r in pol.rules:
        if r.action == Action.DENY and not r.reason:
            warnings.append(f"rule '{r.id}' has action=deny but no reason")

    # 3. Dead rules — no match key OR empty match.
    for r in pol.rules:
        if not r.match:
            errors.append(f"rule '{r.id}' has empty match")

    # 4. Bad action values.
    for r in pol.rules:
        if r.action not in Action:
            errors.append(f"rule '{r.id}' has invalid action: {r.action}")

    # 5. Glob/regex key without a real field.
    for r in pol.rules:
        for k in r.match:
            if k.endswith("_regex") or k.endswith("_glob"):
                # Strip suffix and check if event schema has that key.
                base = k.removesuffix("_regex").removesuffix("_glob")
                if not base:
                    warnings.append(f"rule '{r.id}' match key '{k}' has no base field")

    # 6. Empty network policy in strict mode.
    if strict and pol.network and not pol.allowed_domains and not pol.denied_domains:
        warnings.append("strict mode: network block present but empty (denies nothing)")

    # 7. No metadata in strict mode.
    if strict and not pol.metadata:
        warnings.append("strict mode: no metadata block (compliance audit)")

    # Output
    console.print(f"[bold]Linting[/bold] {p}")
    console.print(
        f"  {len(pol.rules)} rules, default={pol.default_action.value}, network={bool(pol.network)}"
    )

    if not errors and not warnings:
        console.print("  [green]\u2713 no issues[/]")
        return

    for w in warnings:
        console.print(f"  [yellow]\u26a0[/] {w}")
    for e in errors:
        console.print(f"  [red]\u2717[/] {e}")

    if errors:
        raise click.ClickException(f"{len(errors)} error(s) found")
    if strict and warnings:
        raise click.ClickException(f"strict mode: {len(warnings)} warning(s) treated as errors")
