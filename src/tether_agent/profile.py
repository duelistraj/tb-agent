"""Transactional profile mutations coordinated with a running daemon."""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

from tether_agent.config import (
    ProfileConfig,
    assert_mutation_not_shadowed,
    load_profile_config,
    write_profile_config,
)
from tether_agent.locking import LockUnavailable, ProfileLock
from tether_agent.paths import ProfilePaths
from tether_agent.secure_files import atomic_write
from tether_agent.state import StateStore

MAINTENANCE_TIMEOUT_SECONDS = 30.0


class ProfileManager:
    def __init__(self, paths: ProfilePaths) -> None:
        self.paths = paths
        self._store: StateStore | None = None

    @property
    def store(self) -> StateStore:
        if self._store is None:
            self._store = StateStore(self.paths.state_file)
        return self._store

    def exists(self) -> bool:
        return self.paths.config_file.exists()

    def config(self) -> ProfileConfig:
        return load_profile_config(self.paths.config_file)

    def _enter_maintenance(self) -> int | None:
        if not ProfileLock.is_locked(self.paths.daemon_lock):
            active_run = self.store.active_run_id()
            if active_run is not None:
                raise RuntimeError(
                    f"Execution {active_run} is still active. Start the daemon and "
                    "wait for the run to finish before changing this profile."
                )
            return None
        revision = self.store.request_maintenance()
        deadline = time.monotonic() + MAINTENANCE_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if (
                self.store.maintenance_ack_revision() >= revision
                and self.store.active_run_id() is None
            ):
                return revision
            time.sleep(0.1)
        self.store.clear_maintenance()
        raise RuntimeError(
            "The daemon did not enter maintenance mode. Wait for the active "
            "execution to finish and retry."
        )

    def mutate(
        self,
        change: Callable[[ProfileConfig], ProfileConfig],
        *,
        environment_keys: frozenset[str],
        dotenv_path: Path | None = None,
        state_change: Callable[[], None] | None = None,
    ) -> ProfileConfig:
        assert_mutation_not_shadowed(
            relevant_keys=environment_keys,
            dotenv_path=dotenv_path,
        )
        lock = ProfileLock(self.paths.mutation_lock, label="profile mutation")
        try:
            lock.acquire()
        except LockUnavailable as error:
            raise RuntimeError(
                f"Another command is changing profile '{self.paths.profile}'"
            ) from error
        previous_bytes: bytes | None = None
        maintenance_revision: int | None = None
        state_backup: Path | None = None
        try:
            maintenance_revision = self._enter_maintenance()
            previous = self.config()
            previous_bytes = self.paths.config_file.read_bytes()
            state_backup = self.paths.state_dir / f".rollback-{uuid4().hex}.sqlite3"
            self.store.backup(state_backup)
            proposed = change(previous)
            try:
                if state_change is not None:
                    state_change()
                    proposed = change(previous)
                updated = proposed.model_copy(
                    update={"revision": previous.revision + 1}
                )
                updated = ProfileConfig.model_validate(updated.model_dump())
                write_profile_config(self.paths.config_file, updated)
                self.store.set_configuration_revision(updated.revision)
                self.store.set_daemon_status("reload_requested")
            except BaseException:
                if previous_bytes is not None:
                    atomic_write(self.paths.config_file, previous_bytes)
                if state_backup is not None:
                    self.store.restore_backup(state_backup)
                raise
            return updated
        finally:
            if state_backup is not None:
                state_backup.unlink(missing_ok=True)
            if maintenance_revision is not None:
                self.store.clear_maintenance()
            lock.release()

    def mutate_live_configuration(
        self,
        change: Callable[[ProfileConfig], ProfileConfig],
        *,
        environment_keys: frozenset[str],
    ) -> ProfileConfig:
        """Atomically update a setting that is safe while workers are active."""
        assert_mutation_not_shadowed(relevant_keys=environment_keys)
        lock = ProfileLock(self.paths.mutation_lock, label="live profile mutation")
        try:
            lock.acquire()
        except LockUnavailable as error:
            raise RuntimeError(
                f"Another command is changing profile '{self.paths.profile}'"
            ) from error
        previous_bytes: bytes | None = None
        try:
            previous = self.config()
            previous_bytes = self.paths.config_file.read_bytes()
            proposed = change(previous).model_copy(
                update={"revision": previous.revision + 1}
            )
            updated = ProfileConfig.model_validate(proposed.model_dump())
            try:
                write_profile_config(self.paths.config_file, updated)
                self.store.set_configuration_revision(updated.revision)
                self.store.set_daemon_status("live_reload_requested")
            except BaseException:
                if previous_bytes is not None:
                    atomic_write(self.paths.config_file, previous_bytes)
                raise
            return updated
        finally:
            lock.release()
