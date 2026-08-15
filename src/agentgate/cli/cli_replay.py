"""`agentgate replay` — replay a trace against a new policy."""

from __future__ import annotations

import sys

import click
import yaml

from ..trace import format_divergences, replay
from . import console


@click.command("replay")
@click.argument("trace_path", type=click.Path(exists=True, path_type=str))
@click.argument("policy_path", type=click.Path(exists=True, path_type=str))
@click.option("--strict", is_flag=True,
              help="Exit non-zero on any divergence (default: only print).")
def replay_cmd(trace_path: str, policy_path: str, strict: bool):
    """Replay a recorded trace.jsonl against POLICY_PATH."""
    from ..policy import load_policy
    with open(policy_path) as f:
        yaml.safe_load(f)
    policy = load_policy(policy_path)
    divs = replay(trace_path, policy)
    console.print(format_divergences(divs))
    if divs and strict:
        sys.exit(2)
