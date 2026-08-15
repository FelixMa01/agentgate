"""`agentgate coverage` — policy coverage report."""

from __future__ import annotations

from pathlib import Path

import click

from ..coverage import analyze, format_report
from . import console


@click.command(name="coverage")
@click.option("--policy", "-p", required=True, type=click.Path(exists=True))
@click.option("--db", type=click.Path())
@click.option("--fixtures", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True)
@click.option("--fail-under", type=float, default=None,
              help="Exit 1 if coverage% is below this threshold.")
def coverage_cmd(policy: str, db: str | None, fixtures: str | None,
                 as_json: bool, fail_under: float | None) -> None:
    """Show which policy rules fire against your audit log (or fixtures).

    Useful for finding dead rules AND uncovered tools — both common
    policy hygiene issues.
    """
    report = analyze(policy, db_path=db, fixtures=fixtures)
    if as_json:
        import json as _json
        click.echo(_json.dumps({
            "coverage_pct": report.coverage_pct,
            "rules_total": report.rules_total,
            "rules_matched": report.rules_matched,
            "rules_dead": report.rules_dead,
            "tools_uncovered": report.tools_uncovered,
            "rule_hit_counts": report.rule_hit_counts,
        }, indent=2))
    else:
        console.print(format_report(report), end="")
    if fail_under is not None and report.coverage_pct < fail_under:
        raise click.exceptions.Exit(1)
