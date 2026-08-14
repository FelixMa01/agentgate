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
from .cli_init import init  # noqa: E402
from .cli_eval import eval  # noqa: E402
from .cli_audit import audit  # noqa: E402
from .cli_stats import stats  # noqa: E402
from .cli_validate import validate  # noqa: E402
from .cli_install_hook import install_hook, uninstall_hook  # noqa: E402
from .cli_install_cursor_hook import install_cursor_hook  # noqa: E402
from .cli_proxy import proxy  # noqa: E402
from .cli_approval_server import approval_server  # noqa: E402
from .cli_ask_test import ask_test  # noqa: E402
from .cli_dashboard import dashboard  # noqa: E402
from .cli_replay import replay  # noqa: E402

for _cmd in (
    init, eval, audit, stats, validate, install_hook, uninstall_hook,
    install_cursor_hook, proxy, approval_server, ask_test, dashboard, replay,
):
    main.add_command(_cmd)


if __name__ == "__main__":
    main()