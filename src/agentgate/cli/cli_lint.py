"""`agentgate lint` — static policy linter."""

from __future__ import annotations

import json
import sys

import click
import yaml

from ..lint import LintSeverity, format_report, lint_policy
from . import console


@click.command("lint")
@click.argument("policy_path", required=False, type=click.Path(exists=True, path_type=str))
@click.option("-p", "--policy", "policy_opt", type=click.Path(exists=True, path_type=str),
              help="Path to policy.yaml (alternative to positional arg).")
@click.option("--json-output", is_flag=True, help="Emit JSON instead of text")
@click.option("--strict", is_flag=True, help="Exit non-zero on warnings too")
def lint(policy_path: str | None, policy_opt: str | None, json_output: bool, strict: bool):
    """Lint a policy.yaml for common authoring mistakes."""
    path = policy_opt or policy_path
    if not path:
        raise SystemExit("usage: agentgate lint <policy.yaml>")
    with open(path) as f:
        policy = yaml.safe_load(f)
    if not isinstance(policy, dict):
        raise SystemExit(f"policy must be a YAML mapping, got {type(policy).__name__}")
    findings = lint_policy(policy)
    if json_output:
        click.echo(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        console.print(format_report(findings))
    has_error = any(f.severity == LintSeverity.ERROR for f in findings)
    has_warn = any(f.severity == LintSeverity.WARNING for f in findings)
    if has_error:
        sys.exit(2)
    if strict and has_warn:
        sys.exit(1)
