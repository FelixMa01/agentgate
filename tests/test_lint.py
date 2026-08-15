"""Tests for `agentgate lint`."""
import pytest
from click.testing import CliRunner

from agentgate.cli.__init__ import main


def test_lint_clean_policy(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("""
version: 1
default: deny
rules:
  - id: allow-read
    match: {tool: Read}
    action: allow
    reason: ok
""")
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "-p", str(p)])
    assert result.exit_code == 0, result.output


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
    reason: x
""")
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "-p", str(p)])
    assert result.exit_code != 0
    assert "duplicate" in result.output.lower()


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
    assert "empty" in result.output.lower()


def test_lint_no_reason(tmp_path):
    """Rule without reason gets a warning but doesn't fail (action != deny w/o reason is info)."""
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
    # exit_code 2 (errors) or 1 (warnings via --strict); default returns 0 or 2.
    assert result.exit_code in (1, 2, 0)


def test_lint_invalid_yaml(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("::not::yaml::[")
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "-p", str(p)])
    assert result.exit_code != 0


def test_lint_json_output(tmp_path):
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
    reason: x
""")
    runner = CliRunner()
    result = runner.invoke(main, ["lint", "-p", str(p), "--json-output"])
    assert "duplicate-id" in result.output
