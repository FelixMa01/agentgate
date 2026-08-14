"""Tests for `agentgate lint`."""
import pytest
from click.testing import CliRunner

from agentgate.cli.__init__ import main


def test_lint_clean_policy():
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "-p", "examples/policy-secure.yaml"])
    assert result.exit_code == 0, result.output
    assert "no issues" in result.output or "OK" in result.output


def test_lint_duplicate_id(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("""
version: 1
default: allow
rules:
  - id: dup
    match: {tool: Bash}
    action: deny
    reason: x
  - id: dup
    match: {tool: Read}
    action: allow
""")
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "-p", str(p)])
    assert result.exit_code != 0
    assert "duplicate" in result.output


def test_lint_empty_match(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("""
version: 1
default: allow
rules:
  - id: empty
    match: {}
    action: deny
    reason: x
""")
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "-p", str(p)])
    assert result.exit_code != 0
    assert "empty match" in result.output


def test_lint_no_reason(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("""
version: 1
default: allow
rules:
  - id: r
    match: {tool: Bash}
    action: deny
""")
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "-p", str(p)])
    assert result.exit_code != 0
    assert "reason" in result.output


def test_lint_invalid_yaml(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("::not::yaml::[")
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "-p", str(p)])
    assert result.exit_code != 0
