from __future__ import annotations

from importlib.metadata import distribution

import pytest

from tether_agent import __version__
from tether_agent.cli import run_cli


def test_version_uses_canonical_executable_name(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit, match="0"):
        run_cli(["--version"])

    assert capsys.readouterr().out == f"tb-agent {__version__}\n"


def test_distribution_exposes_only_canonical_executable() -> None:
    scripts = {
        entry_point.name: entry_point.value
        for entry_point in distribution("tb-agent").entry_points
        if entry_point.group == "console_scripts"
    }

    assert scripts == {"tb-agent": "tether_agent.main:main"}
