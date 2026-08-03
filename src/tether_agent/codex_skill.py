"""Install the bundled Tether Brain workflow into Codex's user skill directory."""

from __future__ import annotations

import os
import shutil
from importlib import resources
from pathlib import Path
from uuid import uuid4

from tether_agent import __version__
from tether_agent.secure_files import ensure_private_directory

SKILL_NAME = "tether-brain-task-execution"
# Existing installations use this marker. Keep recognizing it across the CLI rename.
MARKER_NAME = ".tether-agent-managed"


def skill_home(
    *, environ: dict[str, str] | None = None, home: Path | None = None
) -> Path:
    values = os.environ if environ is None else environ
    override = values.get("TETHER_AGENT_CODEX_SKILLS_HOME")
    if override:
        return Path(override).expanduser().resolve(strict=False)
    user_home = Path.home() if home is None else home
    return user_home / ".agents" / "skills"


def skill_path(
    *, environ: dict[str, str] | None = None, home: Path | None = None
) -> Path:
    return skill_home(environ=environ, home=home) / SKILL_NAME


def _bundled_skill():
    return resources.files("tether_agent").joinpath("skills", SKILL_NAME)


def _managed(destination: Path) -> bool:
    marker = destination / MARKER_NAME
    return marker.is_file() and not marker.is_symlink()


def install_skill(
    *, environ: dict[str, str] | None = None, home: Path | None = None
) -> Path:
    destination = skill_path(environ=environ, home=home)
    parent = destination.parent
    ensure_private_directory(parent)
    if destination.is_symlink():
        raise RuntimeError(f"Refusing to replace symlinked Codex skill: {destination}")
    if destination.exists() and not _managed(destination):
        raise RuntimeError(
            f"A non-tb-agent skill already exists at {destination}. Move it first."
        )
    temporary = parent / f".{SKILL_NAME}-{uuid4().hex}"
    backup = parent / f".{SKILL_NAME}-backup-{uuid4().hex}"
    try:
        with resources.as_file(_bundled_skill()) as source:
            shutil.copytree(source, temporary)
        (temporary / MARKER_NAME).write_text(
            f"managed-by=tb-agent\nversion={__version__}\n",
            encoding="utf-8",
        )
        if destination.exists():
            destination.replace(backup)
        temporary.replace(destination)
    except BaseException:
        if backup.exists() and not destination.exists():
            backup.replace(destination)
        raise
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
        shutil.rmtree(backup, ignore_errors=True)
    return destination


def skill_status(
    *, environ: dict[str, str] | None = None, home: Path | None = None
) -> tuple[str, Path]:
    destination = skill_path(environ=environ, home=home)
    if destination.is_symlink():
        return "unsafe symlink", destination
    if not destination.exists():
        return "not installed", destination
    if not _managed(destination):
        return "installed but not managed by tb-agent", destination
    return "installed", destination


def uninstall_skill(
    *, environ: dict[str, str] | None = None, home: Path | None = None
) -> Path:
    destination = skill_path(environ=environ, home=home)
    if destination.is_symlink() or not _managed(destination):
        if not destination.exists() and not destination.is_symlink():
            return destination
        raise RuntimeError(f"Refusing to remove unmanaged Codex skill: {destination}")
    shutil.rmtree(destination)
    return destination
