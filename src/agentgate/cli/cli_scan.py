"""`agentgate scan` — static security scanner for AI agent configs."""

from __future__ import annotations

import json
from pathlib import Path

import click

from ..scanner import Scanner, Severity, report_json, report_text
from . import console

_DEFAULT_ROOTS = [
    Path.home() / ".claude",
    Path.home() / ".cursor",
    Path.home() / ".continue",
    Path.home() / ".config" / "Code" / "User",
    Path.home() / ".gemini",
    Path.home() / ".codex",
]


@click.command("scan")
@click.argument("paths", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option("--report", "fmt", type=click.Choice(["text", "json", "graded"]), default="text",
              show_default=True)
@click.option("--min-severity", type=click.Choice([s.value for s in Severity]), default="low",
              show_default=True)
@click.option("--scan-defaults/--no-scan-defaults", default=True,
              help="Scan ~/.claude, ~/.cursor, etc. when no paths given.")
def scan_cmd(paths, fmt, min_severity, scan_defaults):
    """Scan AI-agent config dirs for risky patterns."""
    targets = list(paths)
    if not targets and scan_defaults:
        targets = [p for p in _DEFAULT_ROOTS if p.exists()]
    if not targets:
        console.print("[yellow]No targets found. Pass paths or create ~/.claude etc.[/]")
        return

    min_sev = Severity(min_severity)
    sev_order = list(Severity)
    min_idx = sev_order.index(min_sev)

    scanner = Scanner()
    all_findings = []
    for root in targets:
        all_findings.extend(scanner.scan_path(root))

    filtered = [f for f in all_findings if sev_order.index(f.severity) <= min_idx]

    if fmt == "json":
        console.print(report_json(filtered))
    elif fmt == "graded":
        from ..scanner import grade
        letter, score = grade(filtered)
        console.print(f"Grade {letter} ({score}/100) — {len(filtered)} findings")
        for f in filtered:
            console.print(f"  [{f.severity.value.upper():<8}] {f.rule_id}  {f.path}:{f.line}")
    else:
        console.print(report_text(filtered))

    # Exit non-zero on any critical so CI can gate on it.
    if any(f.severity == Severity.CRITICAL for f in filtered):
        raise SystemExit(2)
