"""AgentGate CLI — top-level group and shared console.

Subcommand modules use plain `@click.command()` (not `@main.command()`)
to avoid circular imports at module load time. We register them here.
"""

from __future__ import annotations

import click
from rich.console import Console

from .. import __version__

console = Console()


@click.group()
@click.version_option(__version__, prog_name="agentgate")
def main() -> None:
    """AgentGate — firewall for AI coding agents."""


# Import subcommand objects (each is a click.Command) and register them.
from .cli_alerts import alerts
from .cli_approval_server import approval_server
from .cli_ask_test import ask_test
from .cli_audit import cli_audit
from .cli_audit_verify import audit_verify
from .cli_dashboard import dashboard
from .cli_detect_agents import detect_agents
from .cli_docs import docs
from .cli_doctor import doctor
from .cli_eval import eval
from .cli_hosted import pull_policy, push_events
from .cli_init import init
from .cli_install_continue_hook import install_continue_hook
from .cli_install_cursor_hook import install_cursor_hook
from .cli_install_hook import install_hook, uninstall_hook
from .cli_lint import lint
from .cli_proxy import proxy
from .cli_replay import replay
from .cli_stats import stats
from .cli_test_policy import policy_group
from .cli_validate import validate

for _cmd in (
    init,
    eval,
    cli_audit,
    alerts,
    stats,
    validate,
    install_hook,
    uninstall_hook,
    install_cursor_hook,
    install_continue_hook,
    pull_policy,
    push_events,
    proxy,
    approval_server,
    ask_test,
    dashboard,
    detect_agents,
    replay,
    doctor,
    lint,
    docs,
    policy_group,
):
    main.add_command(_cmd)


if __name__ == "__main__":
    main()
