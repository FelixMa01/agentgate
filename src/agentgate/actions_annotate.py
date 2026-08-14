"""GitHub Actions adapter — annotate PR diffs from a CI run.

This isn't a PreToolUse-style hook (GitHub Actions can't intercept what an
agent does inside a CI step). Instead, it runs as a post-step:

  1. The agent (e.g. Anthropic's `claude-code-action` or `anthropic-action`)
     modifies files in the workspace during CI.
  2. After the agent exits, this adapter computes the diff and walks every
     changed line through the AgentGate policy.
  3. Any deny/ask decisions become GitHub annotations (`::error file=…
     line=…::AgentGate: …`) and PR review comments.

Usage (in `.github/workflows/agent.yml`):

    - name: Run coding agent
      uses: anthropics/claude-code-action@…
    - name: AgentGate review
      run: |
        pip install agentgate-firewall
        AGENTGATE_POLICY=./policy.yaml AGENTGATE_DB=./audit.db \\
        python -m agentgate.actions_annotate

This makes a CI-visible, auditable gate on every agent-driven PR.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
from pathlib import Path


def _git_diff(workspace: str = ".") -> list[dict]:
    """Return a list of {path, line, content} dicts for every changed line.

    Uses `git add -A` to capture untracked files, then `git diff --cached HEAD`
    so we see both staged and unstaged (now staged) changes.
    """
    cwd = Path(workspace).resolve()
    subprocess.run(["git", "add", "-A"], cwd=cwd, capture_output=True)
    cmd = ["git", "diff", "--unified=0", "HEAD"]
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        return []
    out: list[dict] = []
    current_file: str | None = None
    current_line = 0
    for raw in proc.stdout.splitlines():
        if raw.startswith("+++"):
            # +++ b/path/to/file — extract path
            tokens = raw.split()
            if len(tokens) >= 2:
                current_file = tokens[1].lstrip("b/")
        elif raw.startswith("@@"):
            # @@ -a,b +c,d @@ — extract the +c,d start
            try:
                plus = raw.split(" +", 1)[1].split(" ", 1)[0]
                current_line = int(plus.split(",")[0])
            except (IndexError, ValueError):
                current_line = 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            out.append(
                {
                    "path": current_file,
                    "line": current_line,
                    "content": raw[1:],
                }
            )
            current_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            # Deletion — don't increment line for additions.
            pass
        elif raw.startswith(" "):
            current_line += 1
    return out


def _emit_annotation(path: str, line: int, level: str, message: str) -> None:
    """Emit a GitHub Actions workflow command for an annotation."""
    # Workflow command format: ::error file=…,line=…,title=…::message
    print(f"::{level} file={path},line={line},title=AgentGate::{message}", flush=True)


def _post_review_comment(repo_root: str, body: str) -> None:
    """If `gh` is available and GH_TOKEN is set, post a single PR review comment.

    Best-effort: failures are logged but never raise.
    """
    gh_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not gh_token:
        return
    with contextlib.suppress(Exception):
        subprocess.run(
            ["gh", "pr", "comment", "--body", body],
            cwd=repo_root,
            check=False,
            env={**os.environ, "GH_TOKEN": gh_token},
            capture_output=True,
            timeout=15,
        )


def main() -> int:
    policy_path = os.environ.get("AGENTGATE_POLICY")
    db_path = os.environ.get("AGENTGATE_DB")
    workspace = os.environ.get("AGENTGATE_WORKSPACE", ".")
    if not policy_path or not db_path:
        print("::warning::AGENTGATE_POLICY and AGENTGATE_DB must be set", flush=True)
        return 0  # fail open

    from .audit import Audit
    from .policy import load_policy

    pol = load_policy(policy_path)
    audit = Audit(db_path)
    diff_lines = _git_diff(workspace)
    if not diff_lines:
        print("::notice::No diff lines to review", flush=True)
        return 0

    denies: list[str] = []
    asks: list[str] = []
    for item in diff_lines:
        path = item["path"]
        if not path:
            continue
        # Treat each added line as a potential Write/Edit action.
        event = {"tool": "Write", "file_path": path, "agent": "github-actions"}
        action, rule = pol.evaluate(event)
        audit.record(
            source="github-actions",
            agent="github-actions",
            action=action,
            event={**event, "_line": item["line"], "_content_preview": item["content"][:200]},
            rule_id=rule.id if rule else None,
            rule_name=rule.name if rule else None,
            reason=rule.reason if rule else None,
        )
        from .policy import Action

        if action == Action.DENY and rule:
            msg = f"DENY \u2014 {rule.name}: {rule.reason}"
            _emit_annotation(path, item["line"], "error", msg)
            denies.append(f"- `{path}:{item['line']}` \u2014 **{rule.name}**: {rule.reason}")
        elif action == Action.ASK and rule:
            msg = f"ASK \u2014 {rule.name}: {rule.reason}"
            _emit_annotation(path, item["line"], "warning", msg)
            asks.append(f"- `{path}:{item['line']}` \u2014 **{rule.name}**: {rule.reason}")

    # Post a single PR review comment summarising the gate decision.
    if denies or asks:
        sections = []
        if denies:
            sections.append("### \u2717 Denied\n" + "\n".join(denies))
        if asks:
            sections.append("### ? Asks\n" + "\n".join(asks))
        comment = "## \U0001f6e1\ufe0f AgentGate review\n\n" + "\n\n".join(sections)
        _post_review_comment(workspace, comment)

    if denies:
        print(f"::error::AgentGate denied {len(denies)} change(s)", flush=True)
        return 1  # fail the CI step
    print(f"::notice::AgentGate reviewed {len(diff_lines)} lines \u2014 OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
