"""Tests for `agentgate doctor`."""
from click.testing import CliRunner

from agentgate.cli.__init__ import main


def test_doctor_runs():
    """Run `agentgate doctor`."""
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    # exit_code 0 if all pass, 1 if some fail; both fine.
    assert result.exit_code in (0, 1), result.output
    out = result.output.lower()
    assert "passed" in out or "check(s)" in out
