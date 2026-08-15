"""`agentgate policy use / list / show / add / remove` — multi-env management."""

from __future__ import annotations

import click

from ..environments import CONFIG_PATH, Environment, EnvironmentStore
from . import console


@click.group(name="env")
def env_group() -> None:
    """Manage named policy environments (dev / staging / prod)."""


@env_group.command(name="list")
def env_list() -> None:
    """List configured environments."""
    store = EnvironmentStore.load()
    if not store.environments:
        console.print(f"[yellow]No environments configured[/] ({CONFIG_PATH})")
        return
    active = store.active_name()
    for name, env in store.environments.items():
        marker = " * " if name == active else "   "
        marker_color = "green" if name == active else "dim"
        console.print(
            f"[{marker_color}]{marker}[/][bold]{name:<14}[/] "
            f"policy={env.policy}  db={env.db}  mode={env.mode}"
        )


@env_group.command(name="show")
@click.argument("name")
def env_show(name: str) -> None:
    """Show one environment's config."""
    store = EnvironmentStore.load()
    try:
        env = store.get(name)
    except KeyError as e:
        raise click.ClickException(str(e))
    console.print(f"[bold]{name}[/]")
    for k, v in env.to_dict().items():
        console.print(f"  {k:<20} {v}")


@env_group.command(name="add")
@click.argument("name")
@click.option("--policy", "-p", required=True)
@click.option("--db", required=True)
@click.option("--mode", default="enforce", show_default=True)
@click.option("--require-approval/--no-require-approval", default=False)
@click.option("--notes", default="")
def env_add(name: str, policy: str, db: str, mode: str,
            require_approval: bool, notes: str) -> None:
    """Add or update a named environment."""
    store = EnvironmentStore.load()
    store.set(Environment(
        name=name, policy=policy, db=db,
        mode=mode, require_approval=require_approval, notes=notes,
    ))
    store.save()
    console.print(f"[green]\u2713[/] added environment [bold]{name}[/]")


@env_group.command(name="remove")
@click.argument("name")
def env_remove(name: str) -> None:
    """Remove a named environment."""
    store = EnvironmentStore.load()
    if name not in store.environments:
        raise click.ClickException(f"unknown environment {name!r}")
    store.unset(name)
    store.save()
    console.print(f"[green]\u2713[/] removed environment [bold]{name}[/]")


@env_group.command(name="use")
@click.argument("name")
def env_use(name: str) -> None:
    """Activate an environment. Prints shell exports to eval."""
    store = EnvironmentStore.load()
    try:
        env = store.use(name)
    except KeyError as e:
        raise click.ClickException(str(e))
    console.print(f"[green]\u2713[/] active environment: [bold]{name}[/]")
    console.print("[yellow]\u00b7[/] eval these in your shell (or source "
                 "~/.agentgate/active.env):")
    console.print(f"  export AGENTGATE_POLICY=\"{env.policy}\"")
    console.print(f"  export AGENTGATE_DB=\"{env.db}\"")
    console.print(f"  export AGENTGATE_MODE=\"{env.mode}\"")


@env_group.command(name="active")
def env_active() -> None:
    """Print the currently active environment name (or none)."""
    store = EnvironmentStore.load()
    name = store.active_name()
    if not name:
        raise click.ClickException("no active environment; run `agentgate env use <name>`")
    console.print(name)
