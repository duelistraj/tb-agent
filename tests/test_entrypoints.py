from __future__ import annotations

import pytest

from tether_agent import __version__
from tether_agent.cli import run_cli
from tether_agent.main import deprecated_main


def test_version_uses_canonical_executable_name(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit, match="0"):
        run_cli(["--version"])

    assert capsys.readouterr().out == f"tb-agent {__version__}\n"


def test_deprecated_entrypoint_warns_and_forwards(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    invoked: list[bool] = []
    monkeypatch.setattr("tether_agent.main.cli_main", lambda: invoked.append(True))

    deprecated_main()

    captured = capsys.readouterr()
    assert invoked == [True]
    assert captured.out == ""
    assert "'tether-agent' is deprecated" in captured.err
    assert "Use 'tb-agent' instead" in captured.err
