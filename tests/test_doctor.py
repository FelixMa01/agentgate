"""Tests for `agentgate doctor`."""

import subprocess
import sys


def test_doctor_runs():
    """Run `agentgate doctor` as a real subprocess."""
    result = subprocess.run(
        [sys.executable, "-m", "agentgate.cli.__init__", "doctor"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "doctor" in result.stdout.lower()
    assert "python" in result.stdout.lower()


def test_doctor_with_policy(tmp_path):
    """Passing --policy validates it."""
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "version: 1\ndefault: allow\nrules:\n  - id: r1\n    match: {tool: Bash}\n    action: deny\n"
    )
    result = subprocess.run(
        [sys.executable, "-m", "agentgate.cli.__init__", "doctor", "-p", str(policy)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "1 rules" in result.stdout
