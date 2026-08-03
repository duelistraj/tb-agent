"""Console entry point."""

import sys

from tether_agent.cli import main as cli_main


def main() -> None:
    cli_main()


def deprecated_main() -> None:
    print(
        "Warning: 'tether-agent' is deprecated and will be removed in tb-agent 0.6.0. "
        "Use 'tb-agent' instead.",
        file=sys.stderr,
    )
    cli_main()
