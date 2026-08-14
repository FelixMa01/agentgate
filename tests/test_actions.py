"""Tests for the GitHub Actions adapter."""

import subprocess

from agentgate.actions_annotate import _emit_annotation, _git_diff


def test_git_diff_finds_added_lines(tmp_path):
    """Set up a tiny git repo with one staged file + an unstaged edit."""
    repo = tmp_path
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=repo, check=True)
    (repo / "x.py").write_text("print('hello')\n")
    subprocess.run(["git", "add", "x.py"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True)
    (repo / "x.py").write_text("print('hello')\nprint('world')\n")
    (repo / "new.txt").write_text("new\n")
    diff = _git_diff(str(repo))
    paths = sorted({d["path"] for d in diff})
    assert "x.py" in paths
    assert "new.txt" in paths
    # The new line should be there
    x_added = [d for d in diff if d["path"] == "x.py"]
    assert any("print('world')" in d["content"] for d in x_added)


def test_git_diff_empty_when_no_changes(tmp_path):
    repo = tmp_path
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=repo, check=True)
    (repo / "x.py").write_text("ok\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True)
    diff = _git_diff(str(repo))
    assert diff == []


def test_emit_annotation_format(capsys):
    _emit_annotation("a.py", 5, "error", "Denied: rm")
    captured = capsys.readouterr()
    assert "::error file=a.py,line=5,title=AgentGate::Denied: rm" in captured.out
