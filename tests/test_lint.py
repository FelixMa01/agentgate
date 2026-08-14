"""Tests for `agentgate lint`."""
import subprocess
import sys
from pathlib import Path

import pytest


def test_lint_clean_policy():
    result = subprocess.run(
        [sys.executable, "-m", "agentgate.cli.__init__", "lint",
         "-p", "examples/policy-secure.yaml"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "no issues" in result.stdout


def test_lint_dup_rule_id(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("""
version: 1
default: allow
rules:
  - id: dup
    match: {tool: Bash}
    action: deny
  - id: dup
    match: {tool: Read}
    action: deny
""")
    result = subprocess.run(
        [sys.executable, "-m", "agentgate.cli.__init__", "lint", "-p", str(p)],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode != 0
    assert "duplicate" in result.stdout.lower()


def test_lint_deny_no_reason(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("""
version: 1
default: allow
rules:
  - id: bare-deny
    match: {tool: Bash}
    action: deny
""")
    result = subprocess.run(
        [sys.executable, "-m", "agentgate.cli.__init__", "lint", "-p", str(p)],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0  # warning only
    assert "no reason" in result.stdout


def test_lint_strict_turns_warnings_into_errors(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("""
version: 1
default: allow
rules:
  - id: bare-deny
    match: {tool: Bash}
    action: deny
""")
    result = subprocess.run(
        [sys.executable, "-m", "agentgate.cli.__init__", "lint",
         "-p", str(p), "--strict"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode != 0
    assert "warning" in result.stdout.lower()


def test_lint_empty_match(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("""
version: 1
default: allow
rules:
  - id: empty
    match: {}
    action: deny
""")
    result = subprocess.run(
        [sys.executable, "-m", "agentgate.cli.__init__", "lint", "-p", str(p)],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode != 0
    assert "empty match" in result.stdout