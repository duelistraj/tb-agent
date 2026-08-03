"""Atomic migration from the legacy TETHER_AGENT_* environment workflow."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from tether_agent.config import (
    DaemonSettings,
    ProfileConfig,
    ProjectMapping,
    load_profile_config,
    write_profile_config,
)
from tether_agent.daemon import AgentDaemon
from tether_agent.locking import LockUnavailable, ProfileLock
from tether_agent.paths import ProfilePaths
from tether_agent.repositories import inspect_repository
from tether_agent.secure_files import atomic_write, ensure_private_directory
from tether_agent.state import StateStore


def _migration_config(settings: DaemonSettings, revision: int) -> ProfileConfig:
    mappings: list[ProjectMapping] = []
    for mapping in settings.project_mappings:
        repository = inspect_repository(
            mapping.local_path,
            remote=mapping.remote_url,
            allow_no_remote=True,
        )
        mappings.append(
            mapping.model_copy(
                update={
                    "local_path": repository.root,
                    "remote_url": repository.remote_url,
                }
            )
        )
    return ProfileConfig(
        revision=max(1, revision),
        server_url=settings.server_url,
        installation_name=settings.installation_name,
        protocol_version=settings.protocol_version,
        poll_seconds=settings.poll_seconds,
        sandbox=settings.sandbox,
        allow_network=settings.allow_network,
        runtime_adapters=settings.runtime_adapters,
        project_mappings=mappings,
        worktrees=settings.worktrees,
    )


async def _refresh_identity(paths: ProfilePaths) -> dict:
    store = StateStore(paths.state_file)
    from tether_agent.config import load_effective_settings

    daemon = AgentDaemon(load_effective_settings(paths, store), paths=paths)
    try:
        return await daemon.register_once()
    finally:
        await daemon.api.close()


def _same_migration(
    paths: ProfilePaths,
    config: ProfileConfig,
    pat: str,
    installation_id: str | None,
    agent_profile_id: str | None,
) -> bool:
    if not paths.config_file.exists() or not paths.state_file.exists():
        return False
    existing = load_profile_config(paths.config_file)
    expected = config.model_copy(update={"revision": existing.revision})
    if existing != expected:
        return False
    store = StateStore(paths.state_file)
    return (
        store.get_secret("pat") == pat
        and store.get_setting("installation_id") == installation_id
        and (
            agent_profile_id is None
            or store.get_setting("agent_profile_id") == agent_profile_id
        )
    )


def migrate_environment(paths: ProfilePaths, *, dry_run: bool) -> int:
    settings = DaemonSettings()
    if not settings.access_token.startswith("tb_pat_"):
        raise RuntimeError(
            "Phase 1 environment migration supports PAT-authenticated daemons only"
        )
    if settings.oauth_client_id is not None or settings.oauth_refresh_token is not None:
        raise RuntimeError(
            "OAuth daemon migration is not available in Phase 1. The existing "
            "environment installation can continue running unchanged."
        )
    source_path = settings.state_path.expanduser().resolve(strict=False)
    source_store = (
        StateStore(source_path, initialize=False) if source_path.exists() else None
    )
    installation_id = (
        str(settings.installation_id)
        if settings.installation_id is not None
        else source_store.get_setting("installation_id")
        if source_store is not None
        else None
    )
    agent_profile_id = (
        str(settings.agent_profile_id)
        if settings.agent_profile_id is not None
        else source_store.get_setting("agent_profile_id")
        if source_store is not None
        else None
    )
    source_revision = (
        source_store.configuration_revision() if source_store is not None else 1
    )
    config = _migration_config(settings, source_revision)

    print(f"Profile: {paths.profile}")
    print(f"Legacy state: {source_path}")
    print(f"Target configuration: {paths.config_file}")
    print(f"Target state: {paths.state_file}")
    print(f"Project mappings: {len(config.project_mappings)}")
    print(f"Installation identity: {installation_id or 'not registered'}")
    print(f"Agent Profile identity: {agent_profile_id or 'not reported'}")
    if dry_run:
        print("Dry run complete. No files were changed.")
        return 0

    if _same_migration(
        paths,
        config,
        settings.access_token,
        installation_id,
        agent_profile_id,
    ):
        print("Environment configuration is already migrated to this profile.")
        return 0

    if paths.config_file.exists() or (
        paths.state_file.exists() and source_path != paths.state_file
    ):
        raise RuntimeError(
            f"Profile '{paths.profile}' already contains different local state. "
            "Choose another profile or reconcile it before migrating."
        )

    mutation_lock = ProfileLock(paths.mutation_lock, label="environment migration")
    try:
        mutation_lock.acquire()
    except LockUnavailable as error:
        raise RuntimeError("Another command is changing this profile") from error

    maintenance_requested = False
    created_target_state = False
    previous_config: bytes | None = None
    state_backup: Path | None = None
    backup_directory = paths.state_dir / "backups"
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    try:
        daemon_running = ProfileLock.is_locked(paths.daemon_lock)
        if daemon_running:
            coordinator = source_store or StateStore(paths.state_file)
            revision = coordinator.request_maintenance()
            maintenance_requested = True
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if (
                    coordinator.maintenance_ack_revision() >= revision
                    and not coordinator.leased_run_ids()
                    and coordinator.active_run_id() is None
                ):
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError(
                    "The daemon did not enter maintenance mode before migration"
                )
        ensure_private_directory(backup_directory)
        if source_store is not None:
            state_backup = backup_directory / (
                f"legacy-state-{timestamp}-{uuid4().hex[:8]}.sqlite3"
            )
            source_store.backup(state_backup)
        if paths.config_file.exists():
            previous_config = paths.config_file.read_bytes()
            atomic_write(
                backup_directory / f"config-{timestamp}.toml",
                previous_config,
            )

        if source_store is not None and source_path != paths.state_file:
            source_store.backup(paths.state_file)
            created_target_state = True
        target_state_existed = paths.state_file.exists()
        target_store = StateStore(paths.state_file)
        if not target_state_existed:
            created_target_state = True
        target_store.clear_maintenance()
        target_store.set_secret("pat", settings.access_token)
        if installation_id is not None:
            target_store.set_setting("installation_id", installation_id)
        if agent_profile_id is not None:
            target_store.set_setting("agent_profile_id", agent_profile_id)
        write_profile_config(paths.config_file, config)
        target_store.set_configuration_revision(config.revision)

        if installation_id is not None and agent_profile_id is None:
            response = asyncio.run(_refresh_identity(paths))
            profiles = response.get("profiles") or []
            codex = next(
                (
                    profile
                    for profile in profiles
                    if profile.get("runtime_kind") == "codex_cli"
                ),
                None,
            )
            if response["status"] == "active" and codex is None:
                raise RuntimeError(
                    "The existing installation did not report its Codex Agent Profile"
                )
    except BaseException:
        if created_target_state:
            for suffix in ("", "-wal", "-shm"):
                Path(f"{paths.state_file}{suffix}").unlink(missing_ok=True)
        elif state_backup is not None and paths.state_file.exists():
            StateStore(paths.state_file).restore_backup(state_backup)
        if previous_config is None:
            paths.config_file.unlink(missing_ok=True)
        else:
            atomic_write(paths.config_file, previous_config)
        raise
    finally:
        if maintenance_requested:
            (source_store or StateStore(paths.state_file)).clear_maintenance()
        mutation_lock.release()

    print("Environment configuration migrated successfully.")
    print(
        "Remove or unset the migrated TETHER_AGENT_* overrides before using "
        "mutating profile commands. Shell startup files were not changed."
    )
    return 0
