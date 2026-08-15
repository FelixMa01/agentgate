"""`agentgate init` — generate a starter policy.yaml + config interactively.

Walks the user through:
- Policy strictness (readonly / balanced / strict)
- Whether to add common safe patterns (allow git, deny rm -rf)
- Where to place the file (default ./agentgate.yaml)
- Whether to enable observability + audit
- Whether to set AGENTGATE_MODE default

Writes a YAML the user can edit. Non-interactive when --preset is given.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import click
import yaml

PRESETS: dict[str, dict[str, Any]] = {
    "readonly": {
        "description": "Block all writes + network; allow only reads.",
        "rules": [
            {"id": "allow-reads", "match": {"tool": ["Read", "Glob", "Grep"]}, "action": "allow",
             "reason": "Read-only inspection"},
            {"id": "deny-writes", "match": {"tool": ["Write", "Edit", "NotebookEdit"]}, "action": "deny",
             "reason": "Writes blocked"},
            {"id": "deny-network", "match": {"tool": ["WebFetch", "Curl"]}, "action": "deny",
             "reason": "Network blocked"},
            {"id": "deny-bash", "match": {"tool": "Bash"}, "action": "deny",
             "reason": "Shell blocked in readonly mode"},
        ],
    },
    "balanced": {
        "description": "Allow reads + safe bash; ask on writes; deny network.",
        "rules": [
            {"id": "allow-reads", "match": {"tool": ["Read", "Glob", "Grep"]}, "action": "allow",
             "reason": "Read-only inspection"},
            {"id": "allow-git-status",
             "match": {"tool": "Bash", "command_glob": "git status*"},
             "action": "allow", "reason": "Safe git read"},
            {"id": "allow-git-diff",
             "match": {"tool": "Bash", "command_glob": "git diff*"},
             "action": "allow", "reason": "Safe git read"},
            {"id": "deny-network", "match": {"tool": ["WebFetch", "Curl"]}, "action": "deny",
             "reason": "Network blocked"},
            {"id": "deny-rm",
             "match": {"tool": "Bash", "command_regex": r"rm\s+(-.*\s+)?(/\s*$|~\s*$|\.\s*$|\*\s*$)"},
             "action": "deny", "reason": "Destructive rm blocked"},
            {"id": "ask-bash", "match": {"tool": "Bash"}, "action": "ask",
             "reason": "Shell command needs approval"},
            {"id": "ask-write", "match": {"tool": ["Write", "Edit"]}, "action": "ask",
             "reason": "File modification needs approval"},
        ],
    },
    "strict": {
        "description": "Deny everything except explicitly allowed tools.",
        "rules": [
            {"id": "allow-reads", "match": {"tool": ["Read"]}, "action": "allow",
             "reason": "Read-only inspection"},
            {"id": "deny-everything",
             "match": {"tool": ["Bash", "Write", "Edit", "WebFetch", "Curl", "Glob", "Grep"]},
             "action": "deny", "reason": "Strict mode denies by default"},
        ],
    },
}


def _prompt_choice(question: str, choices: list[str], default: int = 0) -> int:
    """Show numbered choices, return the selected index."""
    for i, c in enumerate(choices):
        marker = " (default)" if i == default else ""
        click.echo(f"  [{i}] {c}{marker}")
    while True:
        ans = click.prompt(question, default=str(default), show_default=False)
        try:
            idx = int(ans)
            if 0 <= idx < len(choices):
                return idx
        except ValueError:
            pass
        click.echo(f"Enter a number 0..{len(choices) - 1}")


def _prompt_yes_no(question: str, default: bool = False) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    ans = click.prompt(f"{question} {suffix}", default="y" if default else "n", show_default=False)
    return ans.strip().lower() in ("y", "yes", "1", "true")


def build_policy(preset: str, ask_network: bool = True) -> dict[str, Any]:
    """Build a policy dict from a preset name."""
    cfg = {
        "version": 1,
        "default_action": "deny" if preset in ("strict", "readonly") else "ask",
        "rules": list(PRESETS[preset]["rules"]),
    }
    if preset != "readonly" and ask_network:
        # Network is already denied by deny-network rule.
        pass
    return cfg


@click.command("init")
@click.option("--preset", type=click.Choice(list(PRESETS)), default=None,
              help="Use a preset without interactive prompts.")
@click.option("--template", "tpl", default=None,
              help="Use a named policy template (yolo/enterprise/airgapped/ci-cd/pair-programming).")
@click.option("--output", "-o", type=click.Path(), default="agentgate.yaml",
              show_default=True, help="Where to write the policy file.")
@click.option("--force", is_flag=True, help="Overwrite existing policy file.")
@click.option("--yes", "-y", is_flag=True, help="Accept all defaults (non-interactive).")
def init_cmd(preset: str | None, tpl: str | None, output: str, force: bool, yes: bool) -> None:
    ask_network = True  # default for non-interactive paths
    """Generate a starter policy.yaml."""
    out = Path(output)

    if preset is None and not yes:
        click.echo("AgentGate init — let's build a starter policy.")
        click.echo("")
        click.echo("Pick a strictness preset:")
        idx = _prompt_choice("Choice", [PRESETS[k]["description"] for k in PRESETS])
        preset = list(PRESETS)[idx]
        click.echo(f"  -> Using preset: {preset}\\n")

        ask_network = _prompt_yes_no("Deny all network calls (WebFetch/Curl)?", default=True)
    elif preset is None:
        preset = "balanced"
        ask_network = True
    if "ask_network" not in dir():
        ask_network = True

    cfg = build_policy(preset, ask_network=ask_network)

    if tpl:
        from ..templates import render_template
        cfg_yaml = render_template(tpl, path=str(out))
        if out.exists() and not force and not _prompt_yes_no(f"{out} exists. Overwrite?", default=False):
            click.echo("Aborted.")
            sys.exit(1)
        out.write_text(cfg_yaml)
        click.echo(f"Wrote policy to {out} (template: {tpl})")
        click.echo("")
        click.echo("Next steps:")
        click.echo(f"  1. Edit {out} to add your own rules.")
        click.echo(f"  2. Lint it:  agentgate lint {out}")
        click.echo(f"  3. Install hooks:  agentgate install-hook --policy {out}")
        return

    if out.exists() and not force and not _prompt_yes_no(f"{out} exists. Overwrite?", default=False):
            click.echo("Aborted.")
            sys.exit(1)

    out.write_text(yaml.safe_dump(cfg, sort_keys=False))
    click.echo(f"Wrote policy to {out}")
    click.echo("")
    click.echo("Next steps:")
    click.echo(f"  1. Edit {out} to add your own rules.")
    click.echo(f"  2. Test it:  agentgate policy test {out} --tool Bash --command 'ls'")
    click.echo(f"  3. Install hooks:  agentgate install-hook --policy {out}")
