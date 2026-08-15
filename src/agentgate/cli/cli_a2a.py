"""`agentgate a2a scan` — inspect an A2A JSON-RPC payload."""

from __future__ import annotations

import json
import sys

import click

from ..a2a import A2AInspector, has_critical
from . import console


@click.command("a2a-scan")
@click.argument("payload_path", type=click.Path(exists=True, path_type=str))
@click.option("--strict", is_flag=True,
              help="Exit non-zero on any WARNING or CRITICAL finding.")
@click.option("--json-output", is_flag=True, help="Emit JSON instead of text")
def a2a_scan(payload_path: str, strict: bool, json_output: bool):
    """Scan an A2A payload file for prompt-injection / data-exfil / unsafe tools."""
    with open(payload_path, "rb") as f:
        raw = f.read()
    findings = A2AInspector().inspect(raw)
    if json_output:
        console.print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        if not findings:
            console.print("✓ No A2A findings.")
            return
        for f in findings:
            sev = f.severity.value.upper()
            console.print(f"  [{sev}] {f.location}: {f.message}")
            if f.evidence:
                console.print(f"    evidence: {f.evidence[:100]}")
    if strict and findings:
        sys.exit(2)
    if has_critical(findings):
        sys.exit(2)
