"""Platform-aware, profile-scoped filesystem locations."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# This is a persistent on-disk compatibility boundary, not the executable name.
APPLICATION_DIRECTORY = "tether-agent"
DEFAULT_PROFILE = "default"
PROFILE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def validate_profile_name(value: str) -> str:
    if not PROFILE_PATTERN.fullmatch(value):
        raise ValueError(
            "Profile names must start with a letter or number and contain only "
            "letters, numbers, dots, underscores, or hyphens"
        )
    return value


def _config_root(*, environ: dict[str, str], platform: str, home: Path) -> Path:
    override = environ.get("TETHER_AGENT_CONFIG_HOME")
    if override:
        return Path(override).expanduser()
    if platform == "darwin":
        return home / "Library" / "Application Support" / APPLICATION_DIRECTORY
    if platform == "win32":
        return (
            Path(environ.get("APPDATA", home / "AppData" / "Roaming"))
            / APPLICATION_DIRECTORY
        )
    return (
        Path(environ.get("XDG_CONFIG_HOME", home / ".config")) / APPLICATION_DIRECTORY
    )


def _state_root(*, environ: dict[str, str], platform: str, home: Path) -> Path:
    override = environ.get("TETHER_AGENT_STATE_HOME")
    if override:
        return Path(override).expanduser()
    if platform == "darwin":
        return home / "Library" / "Application Support" / APPLICATION_DIRECTORY
    if platform == "win32":
        return (
            Path(environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
            / APPLICATION_DIRECTORY
        )
    return (
        Path(environ.get("XDG_STATE_HOME", home / ".local" / "state"))
        / APPLICATION_DIRECTORY
    )


@dataclass(frozen=True, slots=True)
class ProfilePaths:
    profile: str
    config_dir: Path
    state_dir: Path

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.toml"

    @property
    def state_file(self) -> Path:
        return self.state_dir / "state.sqlite3"

    @property
    def daemon_lock(self) -> Path:
        return self.state_dir / "daemon.lock"

    @property
    def mutation_lock(self) -> Path:
        return self.state_dir / "mutation.lock"

    @property
    def credential_lock(self) -> Path:
        return self.state_dir / "credential.lock"

    @property
    def log_file(self) -> Path:
        return self.state_dir / "daemon.log"

    @classmethod
    def resolve(
        cls,
        profile: str = DEFAULT_PROFILE,
        *,
        environ: dict[str, str] | None = None,
        platform: str | None = None,
        home: Path | None = None,
    ) -> ProfilePaths:
        normalized = validate_profile_name(profile)
        values = dict(os.environ if environ is None else environ)
        current_platform = sys.platform if platform is None else platform
        user_home = Path.home() if home is None else home
        config_root = _config_root(
            environ=values,
            platform=current_platform,
            home=user_home,
        ).resolve(strict=False)
        state_root = _state_root(
            environ=values,
            platform=current_platform,
            home=user_home,
        ).resolve(strict=False)
        return cls(
            profile=normalized,
            config_dir=config_root / "profiles" / normalized,
            state_dir=state_root / "profiles" / normalized,
        )
