"""Validated legacy environment and profile-backed daemon configuration."""

from __future__ import annotations

import json
import os
import tomllib
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from tether_agent.paths import ProfilePaths
from tether_agent.secure_files import atomic_write, validate_private_file

if TYPE_CHECKING:
    from tether_agent.state import StateStore


CONFIG_FORMAT_VERSION = 1
MUTABLE_ENV_KEYS = frozenset(
    {
        "TETHER_AGENT_ACCESS_TOKEN",
        "TETHER_AGENT_AGENT_PROFILE_ID",
        "TETHER_AGENT_ALLOW_NETWORK",
        "TETHER_AGENT_CONFIG_REVISION",
        "TETHER_AGENT_INSTALLATION_ID",
        "TETHER_AGENT_INSTALLATION_NAME",
        "TETHER_AGENT_MAX_CONCURRENT_RUNS",
        "TETHER_AGENT_OAUTH_CLIENT_ID",
        "TETHER_AGENT_OAUTH_REFRESH_TOKEN",
        "TETHER_AGENT_POLL_SECONDS",
        "TETHER_AGENT_PROJECT_MAPPINGS",
        "TETHER_AGENT_PROTOCOL_VERSION",
        "TETHER_AGENT_RUNTIME_ADAPTERS",
        "TETHER_AGENT_SANDBOX",
        "TETHER_AGENT_SERVER_URL",
        "TETHER_AGENT_STATE_PATH",
        "TETHER_AGENT_WORKTREES",
    }
)


class ProjectMapping(BaseModel):
    project_id: UUID
    local_path: Path
    access: Literal["read", "write"] = "write"
    worktree_root: Path | None = None
    remote_name: str | None = None
    remote_url: str | None = None

    @field_validator("local_path")
    @classmethod
    def absolute_repository_path(cls, value: Path) -> Path:
        return value.expanduser().resolve(strict=False)

    @field_validator("worktree_root")
    @classmethod
    def absolute_worktree_root(cls, value: Path | None) -> Path | None:
        if value is None:
            return None
        return value.expanduser().resolve(strict=False)

    def security_revision(self) -> str:
        material = "\0".join(
            (
                str(self.project_id),
                str(self.local_path.resolve(strict=False)),
                self.access,
                str(self.worktree_root.resolve(strict=False))
                if self.worktree_root is not None
                else "",
                self.remote_name or "",
                self.remote_url or "",
            )
        )
        return sha256(material.encode()).hexdigest()


class CommandRuntimeModel(BaseModel):
    id: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    supported_reasoning_efforts: list[str] = Field(default_factory=list)
    default_reasoning_effort: str | None = None
    is_default: bool = False

    @model_validator(mode="after")
    def valid_reasoning_default(self) -> CommandRuntimeModel:
        if (
            self.default_reasoning_effort is not None
            and self.default_reasoning_effort not in self.supported_reasoning_efforts
        ):
            raise ValueError(
                "The default reasoning effort must be supported by the model"
            )
        if self.supported_reasoning_efforts and self.default_reasoning_effort is None:
            raise ValueError(
                "Models with reasoning options require an explicit default effort"
            )
        return self


class RuntimeAdapterSettings(BaseModel):
    runtime_kind: Literal["codex_cli", "claude_code", "agy"]
    executable: str | None = None
    models: list[CommandRuntimeModel] = Field(default_factory=list)

    @model_validator(mode="after")
    def command_runtime_catalog(self) -> RuntimeAdapterSettings:
        if self.runtime_kind == "codex_cli":
            return self
        if not self.models:
            raise ValueError(
                f"{self.runtime_kind} requires an explicit local model catalog"
            )
        if sum(model.is_default for model in self.models) != 1:
            raise ValueError(f"{self.runtime_kind} requires exactly one default model")
        return self


class WorktreePolicy(BaseModel):
    review_retention: Literal["until_accepted", "manual"] = "until_accepted"
    accepted_retention_hours: int = Field(default=24, ge=0, le=720)
    failed_retention_hours: int = Field(default=72, ge=1, le=720)
    cancelled_retention_hours: int = Field(default=24, ge=1, le=720)
    handoff_retention_days: int = Field(default=7, ge=1, le=365)
    max_total_bytes: int = Field(
        default=20 * 1024 * 1024 * 1024,
        ge=1024 * 1024 * 1024,
    )


class ProfileConfig(BaseModel):
    format_version: Literal[1] = CONFIG_FORMAT_VERSION
    revision: int = Field(default=1, ge=1)
    server_url: str = "http://127.0.0.1:8000"
    installation_name: str = Field(
        default="Local agent daemon",
        min_length=1,
        max_length=100,
    )
    protocol_version: str = "1"
    poll_seconds: float = Field(default=5.0, ge=1.0, le=60.0)
    max_concurrent_runs: int = Field(default=1, ge=1, le=4)
    sandbox: Literal["read_only", "workspace_write"] = "workspace_write"
    allow_network: bool = False
    runtime_adapters: list[RuntimeAdapterSettings] = Field(
        default_factory=lambda: [RuntimeAdapterSettings(runtime_kind="codex_cli")]
    )
    project_mappings: list[ProjectMapping] = Field(default_factory=list)
    worktrees: WorktreePolicy = Field(default_factory=WorktreePolicy)

    @field_validator("server_url")
    @classmethod
    def normalized_server_url(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        if not normalized.startswith(("http://", "https://")):
            raise ValueError("Server URL must use HTTP or HTTPS")
        parsed = urlsplit(normalized)
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError(
                "Server URL must include a host and no embedded credentials"
            )
        if parsed.path not in {"", "/"}:
            raise ValueError("Server URL must be an origin without an API path")
        if parsed.query or parsed.fragment:
            raise ValueError("Server URL must not include a query or fragment")
        return normalized

    @model_validator(mode="after")
    def phase_one_configuration(self) -> ProfileConfig:
        if [item.runtime_kind for item in self.runtime_adapters] != ["codex_cli"]:
            raise ValueError("Phase 1 profiles support only the codex_cli runtime")
        project_ids = [item.project_id for item in self.project_mappings]
        local_paths = [item.local_path for item in self.project_mappings]
        if len(project_ids) != len(set(project_ids)):
            raise ValueError("Project mappings must use unique project IDs")
        if len(local_paths) != len(set(local_paths)):
            raise ValueError("Project mappings must use unique repository paths")
        return self


class DaemonSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TETHER_AGENT_",
        env_file=".env",
        extra="ignore",
    )

    server_url: str = "http://127.0.0.1:8000"
    access_token: str
    oauth_client_id: str | None = None
    oauth_refresh_token: str | None = None
    credential_type: Literal["pat", "oauth_installation", "legacy_oauth"] = "pat"
    access_token_expires_at: datetime | None = None
    credential_generation: int = Field(default=0, ge=0)
    installation_id: UUID | None = None
    agent_profile_id: UUID | None = None
    installation_name: str = "Local agent daemon"
    state_path: Path = Path(".tether-agent/state.sqlite3")
    config_revision: int = Field(default=0, ge=0)
    poll_seconds: float = Field(default=5.0, ge=1.0, le=60.0)
    max_concurrent_runs: int = Field(default=1, ge=1, le=4)
    protocol_version: str = "1"
    sandbox: Literal["read_only", "workspace_write"] = "workspace_write"
    allow_network: bool = False
    runtime_adapters: list[RuntimeAdapterSettings] = Field(
        default_factory=lambda: [RuntimeAdapterSettings(runtime_kind="codex_cli")]
    )
    project_mappings: list[ProjectMapping] = Field(default_factory=list)
    worktrees: WorktreePolicy = Field(default_factory=WorktreePolicy)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: EnvSettingsSource,
        dotenv_settings: DotEnvSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        del settings_cls
        return (
            env_settings,
            dotenv_settings,
            init_settings,
            file_secret_settings,
        )

    @field_validator("server_url")
    @classmethod
    def normalized_server_url(cls, value: str) -> str:
        return value.rstrip("/")

    @model_validator(mode="after")
    def complete_configuration(self) -> DaemonSettings:
        if (self.oauth_client_id is None) != (self.oauth_refresh_token is None):
            raise ValueError(
                "OAuth client ID and refresh token must be configured together"
            )
        runtime_kinds = [runtime.runtime_kind for runtime in self.runtime_adapters]
        if len(runtime_kinds) != len(set(runtime_kinds)):
            raise ValueError("Runtime adapters must be unique")
        if not runtime_kinds:
            raise ValueError("Configure at least one runtime adapter")
        project_ids = [mapping.project_id for mapping in self.project_mappings]
        local_paths = [mapping.local_path for mapping in self.project_mappings]
        if len(project_ids) != len(set(project_ids)):
            raise ValueError("Project mappings must be unique")
        if len(local_paths) != len(set(local_paths)):
            raise ValueError("Project repository paths must be unique")
        return self


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def serialize_profile_config(config: ProfileConfig) -> bytes:
    lines = [
        f"format_version = {config.format_version}",
        f"revision = {config.revision}",
        f"server_url = {_toml_string(config.server_url)}",
        f"installation_name = {_toml_string(config.installation_name)}",
        f"protocol_version = {_toml_string(config.protocol_version)}",
        f"poll_seconds = {config.poll_seconds}",
        f"max_concurrent_runs = {config.max_concurrent_runs}",
        f"sandbox = {_toml_string(config.sandbox)}",
        f"allow_network = {str(config.allow_network).lower()}",
        "",
    ]
    for runtime in config.runtime_adapters:
        lines.extend(
            (
                "[[runtime_adapters]]",
                f"runtime_kind = {_toml_string(runtime.runtime_kind)}",
            )
        )
        if runtime.executable is not None:
            lines.append(f"executable = {_toml_string(runtime.executable)}")
        for model in runtime.models:
            lines.extend(
                (
                    "[[runtime_adapters.models]]",
                    f"id = {_toml_string(model.id)}",
                    f"display_name = {_toml_string(model.display_name)}",
                    "supported_reasoning_efforts = ["
                    + ", ".join(
                        _toml_string(item) for item in model.supported_reasoning_efforts
                    )
                    + "]",
                )
            )
            if model.default_reasoning_effort is not None:
                lines.append(
                    "default_reasoning_effort = "
                    + _toml_string(model.default_reasoning_effort)
                )
            lines.append(f"is_default = {str(model.is_default).lower()}")
        lines.append("")
    for mapping in config.project_mappings:
        lines.extend(
            (
                "[[project_mappings]]",
                f"project_id = {_toml_string(str(mapping.project_id))}",
                f"local_path = {_toml_string(str(mapping.local_path))}",
                f"access = {_toml_string(mapping.access)}",
            )
        )
        if mapping.worktree_root is not None:
            lines.append(f"worktree_root = {_toml_string(str(mapping.worktree_root))}")
        if mapping.remote_url is not None:
            lines.append(f"remote_url = {_toml_string(mapping.remote_url)}")
        if mapping.remote_name is not None:
            lines.append(f"remote_name = {_toml_string(mapping.remote_name)}")
        lines.append("")
    worktrees = config.worktrees
    lines.extend(
        (
            "[worktrees]",
            f"review_retention = {_toml_string(worktrees.review_retention)}",
            f"accepted_retention_hours = {worktrees.accepted_retention_hours}",
            f"failed_retention_hours = {worktrees.failed_retention_hours}",
            f"cancelled_retention_hours = {worktrees.cancelled_retention_hours}",
            f"handoff_retention_days = {worktrees.handoff_retention_days}",
            f"max_total_bytes = {worktrees.max_total_bytes}",
            "",
        )
    )
    return "\n".join(lines).encode()


def load_profile_config(path: Path) -> ProfileConfig:
    validate_private_file(path, allow_missing=False)
    with path.open("rb") as stream:
        raw = tomllib.load(stream)
    config = ProfileConfig.model_validate(raw)
    for raw_mapping, mapping in zip(
        raw.get("project_mappings", []),
        config.project_mappings,
        strict=True,
    ):
        raw_path = Path(raw_mapping["local_path"]).expanduser()
        if (
            not raw_path.is_absolute()
            or raw_path.resolve(strict=False) != mapping.local_path
        ):
            raise ValueError(
                "Stored project mappings must use canonical absolute repository paths"
            )
    return config


def write_profile_config(path: Path, config: ProfileConfig) -> None:
    atomic_write(path, serialize_profile_config(config))


def _validate_mapping_repositories(settings: DaemonSettings) -> DaemonSettings:
    from tether_agent.repositories import inspect_repository

    for mapping in settings.project_mappings:
        repository = inspect_repository(
            mapping.local_path,
            remote=mapping.remote_url,
            remote_name=mapping.remote_name,
            allow_no_remote=mapping.remote_url is None,
        )
        if repository.root != mapping.local_path:
            raise ValueError(
                f"Project mapping is not the canonical Git root: {mapping.project_id}"
            )
    return settings


def load_effective_settings(
    paths: ProfilePaths,
    store: StateStore | None = None,
) -> DaemonSettings:
    if paths.config_file.exists():
        config = load_profile_config(paths.config_file)
        state = store
        if state is None:
            from tether_agent.state import StateStore

            state = StateStore(paths.state_file)
        credential = state.credential()
        environment_pat = "TETHER_AGENT_ACCESS_TOKEN" in configured_environment_keys()
        values: dict[str, Any] = {
            **config.model_dump(exclude={"format_version", "revision"}),
            "access_token": (
                credential.access_token
                if credential is not None
                else state.get_secret("pat")
            ),
            "credential_type": (
                "pat"
                if environment_pat
                else credential.credential_type
                if credential is not None
                else "pat"
            ),
            "access_token_expires_at": (
                credential.access_expires_at
                if credential is not None and not environment_pat
                else None
            ),
            "credential_generation": (
                credential.generation
                if credential is not None and not environment_pat
                else 0
            ),
            "installation_id": state.get_setting("installation_id"),
            "agent_profile_id": state.get_setting("agent_profile_id"),
            "state_path": paths.state_file,
            "config_revision": config.revision,
        }
        return _validate_mapping_repositories(DaemonSettings(**values))
    return _validate_mapping_repositories(DaemonSettings())


def configured_environment_keys(
    *,
    environ: dict[str, str] | None = None,
    dotenv_path: Path | None = None,
) -> frozenset[str]:
    values = os.environ if environ is None else environ
    keys = {key for key in MUTABLE_ENV_KEYS if key in values}
    candidate = Path(".env") if dotenv_path is None else dotenv_path
    if candidate.is_file():
        for raw_line in candidate.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key = line.split("=", 1)[0].strip()
            if key.startswith("export "):
                key = key.removeprefix("export ").strip()
            if key in MUTABLE_ENV_KEYS:
                keys.add(key)
    return frozenset(keys)


def assert_mutation_not_shadowed(
    *,
    relevant_keys: frozenset[str],
    environ: dict[str, str] | None = None,
    dotenv_path: Path | None = None,
) -> None:
    shadowing = sorted(
        configured_environment_keys(environ=environ, dotenv_path=dotenv_path)
        & relevant_keys
    )
    if shadowing:
        joined = ", ".join(shadowing)
        raise RuntimeError(
            "Stored configuration is shadowed by environment settings: "
            f"{joined}. Run 'tb-agent migrate env', then remove or unset "
            "the overrides before changing this profile."
        )
