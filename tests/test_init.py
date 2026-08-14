"""Tests for `agentgate init`."""
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentgate.cli.cli_init import PRESETS, init_cmd


def test_presets_have_required_keys():
    for _name, cfg in PRESETS.items():
        assert "description" in cfg
        assert "rules" in cfg
        assert len(cfg["rules"]) > 0
        for rule in cfg["rules"]:
            assert "id" in rule
            assert "match" in rule
            assert "action" in rule


def test_init_writes_balanced_policy(tmp_path):
    out = tmp_path / "agentgate.yaml"
    runner = CliRunner()
    result = runner.invoke(init_cmd, ["--preset", "balanced", "-y", "-o", str(out), "--force"])
    assert result.exit_code == 0, result.output
    assert out.exists()
    content = out.read_text()
    assert "version: 1" in content
    assert "ask-bash" in content
    assert "deny-network" in content


def test_init_writes_readonly_policy(tmp_path):
    out = tmp_path / "agentgate.yaml"
    runner = CliRunner()
    result = runner.invoke(init_cmd, ["--preset", "readonly", "-y", "-o", str(out), "--force"])
    assert result.exit_code == 0, result.output
    content = out.read_text()
    assert "default_action: deny" in content
    assert "deny-writes" in content


def test_init_writes_strict_policy(tmp_path):
    out = tmp_path / "agentgate.yaml"
    runner = CliRunner()
    result = runner.invoke(init_cmd, ["--preset", "strict", "-y", "-o", str(out), "--force"])
    assert result.exit_code == 0, result.output
    content = out.read_text()
    assert "deny-everything" in content


def test_init_refuses_overwrite_without_force(tmp_path):
    out = tmp_path / "agentgate.yaml"
    sentinel = "existing: stuff" + chr(10)
    out.write_text(sentinel)
    runner = CliRunner()
    result = runner.invoke(init_cmd, ["--preset", "balanced", "-y", "-o", str(out)])
    assert result.exit_code == 1
    assert out.read_text() == sentinel


def test_init_force_overwrites(tmp_path):
    out = tmp_path / "agentgate.yaml"
    out.write_text("old" + chr(10))
    runner = CliRunner()
    result = runner.invoke(init_cmd, ["--preset", "readonly", "-y", "-o", str(out), "--force"])
    assert result.exit_code == 0
    assert "version: 1" in out.read_text()


def test_init_generated_policy_is_valid_yaml(tmp_path):
    import yaml
    out = tmp_path / "agentgate.yaml"
    runner = CliRunner()
    runner.invoke(init_cmd, ["--preset", "balanced", "-y", "-o", str(out), "--force"])
    parsed = yaml.safe_load(out.read_text())
    assert parsed["version"] == 1
    assert "rules" in parsed
    assert all("id" in r for r in parsed["rules"])


def test_init_generated_policy_can_be_loaded(tmp_path):
    from agentgate.policy import load_policy
    out = tmp_path / "agentgate.yaml"
    runner = CliRunner()
    runner.invoke(init_cmd, ["--preset", "balanced", "-y", "-o", str(out), "--force"])
    policy = load_policy(out)
    assert policy.default_action in ("allow", "ask", "deny")
    assert len(policy.rules) > 0


def test_init_help():
    runner = CliRunner()
    result = runner.invoke(init_cmd, ["--help"])
    assert result.exit_code == 0
    assert "--preset" in result.output
