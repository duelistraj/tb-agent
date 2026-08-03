from pathlib import Path

import pytest

from tether_agent.codex_skill import (
    install_skill,
    skill_status,
    uninstall_skill,
)


def test_bundled_codex_skill_installs_without_credentials(tmp_path: Path) -> None:
    environment = {"TETHER_AGENT_CODEX_SKILLS_HOME": str(tmp_path / "skills")}

    destination = install_skill(environ=environment)

    content = (destination / "SKILL.md").read_text(encoding="utf-8")
    assert "tb-agent init --path ." in content
    assert "Codex MCP" in content
    assert "persistent board-task execution" in content
    assert "Never request, read, print, store" in content
    assert "tb_pat_" not in content
    assert "tb_iat_" not in content
    assert skill_status(environ=environment) == ("installed", destination)

    assert uninstall_skill(environ=environment) == destination
    assert skill_status(environ=environment) == ("not installed", destination)


def test_codex_skill_refuses_to_replace_unmanaged_content(tmp_path: Path) -> None:
    environment = {"TETHER_AGENT_CODEX_SKILLS_HOME": str(tmp_path / "skills")}
    destination = tmp_path / "skills" / "tether-brain-task-execution"
    destination.mkdir(parents=True)
    (destination / "SKILL.md").write_text("user content", encoding="utf-8")

    with pytest.raises(RuntimeError, match="non-tb-agent"):
        install_skill(environ=environment)

    assert (destination / "SKILL.md").read_text(encoding="utf-8") == "user content"


def test_codex_skill_refuses_symlinked_destination(tmp_path: Path) -> None:
    environment = {"TETHER_AGENT_CODEX_SKILLS_HOME": str(tmp_path / "skills")}
    target = tmp_path / "elsewhere"
    target.mkdir()
    destination = tmp_path / "skills" / "tether-brain-task-execution"
    destination.parent.mkdir()
    destination.symlink_to(target, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symlinked"):
        install_skill(environ=environment)
