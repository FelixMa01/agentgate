"""Tests for `agentgate doctor`."""
from click.testing import CliRunner

from agentgate.cli.__init__ import main


def test_doctor_runs():
    """Run `agentgate doctor`."""
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "doctor" in result.output.lower()
    assert "python" in result.output.lower()
