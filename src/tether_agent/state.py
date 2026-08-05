"""Crash-safe, profile-local daemon state and credentials."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from tether_agent.secure_files import (
    FILE_MODE,
    ensure_private_directory,
    secure_descriptor,
    validate_private_file,
)

BUSY_TIMEOUT_MILLISECONDS = 5_000


@dataclass(frozen=True, slots=True)
class CredentialRecord:
    credential_type: str
    generation: int
    access_token: str
    access_expires_at: datetime
    refresh_token: str
    previous_refresh_token: str | None
    recovery_rotation_id: str | None
    oauth_client_id: str
    family_id: str
    last_successful_refresh: datetime | None
    revoked_at: datetime | None
    reauthentication_required: bool


@dataclass(frozen=True, slots=True)
class PortReservation:
    run_id: UUID
    worker_slot: int
    port_start: int
    port_end: int
    state: str
    revision: int


@dataclass(frozen=True, slots=True)
class ChangeSetRecord:
    run_id: UUID
    state: str
    repository_path: Path
    worktree_path: Path
    base_commit: str
    snapshot_commit: str | None
    snapshot_tree: str | None
    validation_revision: int
    change_set_revision: int
    validation_status: str
    accepted_revision: int | None
    accepted_snapshot_commit: str | None
    accepted_snapshot_tree: str | None


class StateStore:
    def __init__(self, path: Path, *, initialize: bool = True) -> None:
        self.path = path.expanduser()
        self._secure_on_close = initialize
        if not initialize:
            validate_private_file(self.path, allow_missing=False)
            return
        ensure_private_directory(self.path.parent)
        validate_private_file(self.path)
        if not self.path.exists():
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.path, flags, FILE_MODE)
            os.close(descriptor)
        self.path.chmod(FILE_MODE)
        self._initialize()
        self._secure_sidecars()

    @contextmanager
    def connection(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        validate_private_file(self.path, allow_missing=False)
        connection = sqlite3.connect(
            self.path,
            timeout=BUSY_TIMEOUT_MILLISECONDS / 1_000,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MILLISECONDS}")
        try:
            if immediate:
                connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
            if self._secure_on_close:
                self._secure_sidecars()

    def _secure_sidecars(self) -> None:
        if os.name == "nt":
            # Windows applies ACLs inherited from the private profile directory.
            # Opening SQLite WAL sidecars independently can fail while another
            # connection maps the shared-memory file, especially on Python 3.14.
            validate_private_file(self.path, allow_missing=False)
            return
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self.path}{suffix}")
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(candidate, flags)
            except FileNotFoundError:
                continue
            except OSError as error:
                if candidate.is_symlink():
                    raise PermissionError(
                        f"Refusing to use symlinked SQLite state file: {candidate}"
                    ) from error
                raise
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise PermissionError(
                        f"SQLite state path is not a regular file: {candidate}"
                    )
                if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                    raise PermissionError(
                        "SQLite state file is not owned by the current user: "
                        f"{candidate}"
                    )
                secure_descriptor(descriptor, candidate)
            finally:
                os.close(descriptor)

    def _initialize(self) -> None:
        with self.connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS secrets (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    lease_generation INTEGER,
                    lease_token TEXT,
                    worker_slot INTEGER,
                    thread_id TEXT,
                    state TEXT NOT NULL,
                    worktree_path TEXT,
                    pending_result TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS port_reservations (
                    run_id TEXT PRIMARY KEY,
                    worker_slot INTEGER NOT NULL,
                    port_start INTEGER NOT NULL,
                    port_end INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    released_at TEXT,
                    updated_at TEXT NOT NULL,
                    CHECK(worker_slot >= 0 AND worker_slot < 4),
                    CHECK(port_start >= 1024),
                    CHECK(port_end >= port_start)
                );
                CREATE TABLE IF NOT EXISTS change_sets (
                    run_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    repository_path TEXT NOT NULL,
                    worktree_path TEXT NOT NULL,
                    base_commit TEXT NOT NULL,
                    snapshot_commit TEXT,
                    snapshot_tree TEXT,
                    validation_revision INTEGER NOT NULL DEFAULT 0,
                    change_set_revision INTEGER NOT NULL DEFAULT 1,
                    validation_status TEXT NOT NULL DEFAULT 'not_run',
                    accepted_revision INTEGER,
                    accepted_snapshot_commit TEXT,
                    accepted_snapshot_tree TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    CHECK(validation_revision >= 0),
                    CHECK(change_set_revision >= 1)
                );
                CREATE TABLE IF NOT EXISTS validation_runs (
                    run_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    command_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    exit_code INTEGER,
                    log_path TEXT,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    PRIMARY KEY(run_id, revision),
                    FOREIGN KEY(run_id) REFERENCES change_sets(run_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS handoffs (
                    run_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    snapshot_commit TEXT NOT NULL,
                    snapshot_tree TEXT NOT NULL,
                    validation_revision INTEGER NOT NULL,
                    change_set_revision INTEGER NOT NULL,
                    checkout_path TEXT NOT NULL,
                    common_directory TEXT NOT NULL,
                    captured_head TEXT,
                    captured_branch TEXT,
                    captured_status TEXT,
                    captured_index_digest TEXT,
                    method TEXT,
                    applied_commit TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS worktrees (
                    run_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    repository_path TEXT NOT NULL,
                    path TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL,
                    pinned INTEGER NOT NULL DEFAULT 0,
                    dirty INTEGER NOT NULL DEFAULT 0,
                    retain_until TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(run_id, project_id)
                );
                CREATE TABLE IF NOT EXISTS credentials (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    credential_type TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    access_token TEXT NOT NULL,
                    access_expires_at TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    previous_refresh_token TEXT,
                    recovery_rotation_id TEXT,
                    oauth_client_id TEXT NOT NULL,
                    family_id TEXT NOT NULL,
                    last_successful_refresh TEXT,
                    revoked_at TEXT,
                    reauthentication_required INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS setup_sessions (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    session_handle TEXT NOT NULL,
                    code_verifier TEXT NOT NULL,
                    state_value TEXT NOT NULL,
                    nonce_value TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    token_endpoint TEXT NOT NULL,
                    credential_endpoint TEXT NOT NULL,
                    activation_endpoint TEXT NOT NULL,
                    audience TEXT NOT NULL,
                    authorization_url TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    intent TEXT NOT NULL DEFAULT 'reauthorize',
                    updated_at TEXT NOT NULL
                );
                """
            )
            worktree_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(worktrees)").fetchall()
            }
            if "repository_path" not in worktree_columns:
                connection.execute(
                    "ALTER TABLE worktrees ADD COLUMN repository_path TEXT"
                )
            run_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(runs)").fetchall()
            }
            if "pending_result" not in run_columns:
                connection.execute("ALTER TABLE runs ADD COLUMN pending_result TEXT")
            if "worker_slot" not in run_columns:
                connection.execute("ALTER TABLE runs ADD COLUMN worker_slot INTEGER")
            setup_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(setup_sessions)"
                ).fetchall()
            }
            if "authorization_url" not in setup_columns:
                connection.execute(
                    "ALTER TABLE setup_sessions ADD COLUMN authorization_url TEXT NOT NULL DEFAULT ''"
                )
            if "activation_endpoint" not in setup_columns:
                connection.execute(
                    "ALTER TABLE setup_sessions ADD COLUMN activation_endpoint TEXT NOT NULL DEFAULT ''"
                )
            if "audience" not in setup_columns:
                connection.execute(
                    "ALTER TABLE setup_sessions ADD COLUMN audience TEXT NOT NULL DEFAULT ''"
                )
            if "intent" not in setup_columns:
                connection.execute(
                    "ALTER TABLE setup_sessions ADD COLUMN intent TEXT NOT NULL DEFAULT 'reauthorize'"
                )
            primary_keys = [
                row["name"]
                for row in connection.execute("PRAGMA table_info(worktrees)").fetchall()
                if row["pk"]
            ]
            if primary_keys == ["run_id"]:
                connection.executescript(
                    """
                    CREATE TABLE worktrees_v2 (
                        run_id TEXT NOT NULL,
                        project_id TEXT NOT NULL,
                        repository_path TEXT NOT NULL,
                        path TEXT NOT NULL UNIQUE,
                        state TEXT NOT NULL,
                        pinned INTEGER NOT NULL DEFAULT 0,
                        dirty INTEGER NOT NULL DEFAULT 0,
                        retain_until TEXT,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY(run_id, project_id)
                    );
                    INSERT INTO worktrees_v2
                    SELECT
                        run_id,
                        project_id,
                        COALESCE(repository_path, ''),
                        path,
                        state,
                        pinned,
                        dirty,
                        retain_until,
                        updated_at
                    FROM worktrees;
                    DROP TABLE worktrees;
                    ALTER TABLE worktrees_v2 RENAME TO worktrees;
                    """
                )

    def backup(self, destination: Path) -> None:
        ensure_private_directory(destination.parent)
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(destination)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(destination, flags, FILE_MODE)
        os.close(descriptor)
        try:
            with (
                self.connection() as source,
                closing(sqlite3.connect(destination)) as target,
            ):
                source.backup(target)
                target.commit()
            destination.chmod(FILE_MODE)
        except BaseException:
            destination.unlink(missing_ok=True)
            raise

    def restore_backup(self, source: Path) -> None:
        validate_private_file(source, allow_missing=False)
        with (
            closing(sqlite3.connect(source)) as backup,
            closing(sqlite3.connect(self.path)) as target,
        ):
            backup.backup(target)
            target.commit()
        self._secure_sidecars()

    def get_setting(self, key: str) -> str | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return str(row["value"]) if row is not None else None

    def set_setting(self, key: str, value: str) -> None:
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO settings(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )

    def delete_setting(self, key: str) -> None:
        with self.connection(immediate=True) as connection:
            connection.execute("DELETE FROM settings WHERE key = ?", (key,))

    def get_secret(self, key: str) -> str | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT value FROM secrets WHERE key = ?", (key,)
            ).fetchone()
        return str(row["value"]) if row is not None else None

    def set_secret(self, key: str, value: str) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO secrets(key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (key, value, now),
            )

    def delete_secret(self, key: str) -> None:
        with self.connection(immediate=True) as connection:
            connection.execute("DELETE FROM secrets WHERE key = ?", (key,))

    def credential(self) -> CredentialRecord | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM credentials WHERE singleton = 1"
            ).fetchone()
        if row is None:
            return None
        return CredentialRecord(
            credential_type=str(row["credential_type"]),
            generation=int(row["generation"]),
            access_token=str(row["access_token"]),
            access_expires_at=datetime.fromisoformat(row["access_expires_at"]),
            refresh_token=str(row["refresh_token"]),
            previous_refresh_token=row["previous_refresh_token"],
            recovery_rotation_id=row["recovery_rotation_id"],
            oauth_client_id=str(row["oauth_client_id"]),
            family_id=str(row["family_id"]),
            last_successful_refresh=(
                datetime.fromisoformat(row["last_successful_refresh"])
                if row["last_successful_refresh"]
                else None
            ),
            revoked_at=(
                datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None
            ),
            reauthentication_required=bool(row["reauthentication_required"]),
        )

    def activate_installation_credential(
        self,
        *,
        access_token: str,
        refresh_token: str,
        expires_at: datetime,
        generation: int,
        oauth_client_id: str,
        family_id: str,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO credentials(
                    singleton, credential_type, generation, access_token,
                    access_expires_at, refresh_token, oauth_client_id, family_id,
                    last_successful_refresh, reauthentication_required, updated_at
                ) VALUES (1, 'oauth_installation', ?, ?, ?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    credential_type = excluded.credential_type,
                    generation = excluded.generation,
                    access_token = excluded.access_token,
                    access_expires_at = excluded.access_expires_at,
                    refresh_token = excluded.refresh_token,
                    previous_refresh_token = NULL,
                    recovery_rotation_id = NULL,
                    oauth_client_id = excluded.oauth_client_id,
                    family_id = excluded.family_id,
                    last_successful_refresh = excluded.last_successful_refresh,
                    revoked_at = NULL,
                    reauthentication_required = 0,
                    updated_at = excluded.updated_at
                """,
                (
                    generation,
                    access_token,
                    expires_at.isoformat(),
                    refresh_token,
                    oauth_client_id,
                    family_id,
                    now,
                    now,
                ),
            )
            connection.execute(
                "DELETE FROM settings WHERE key = 'credential_failure_code'"
            )
            connection.executemany(
                "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
                (
                    ("authentication_required", "false"),
                    ("credential_revoked", "false"),
                    ("installation_revoked", "false"),
                ),
            )

    def activate_replacement_credential(
        self,
        *,
        access_token: str,
        refresh_token: str,
        expires_at: datetime,
        generation: int,
        oauth_client_id: str,
        family_id: str,
        installation: dict,
    ) -> None:
        """Atomically detach revoked execution state and activate a new identity."""

        now = datetime.now(UTC).isoformat()
        profiles = installation.get("profiles") or []
        codex_profile = next(
            (
                profile
                for profile in profiles
                if profile.get("runtime_kind") == "codex_cli"
            ),
            None,
        )
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                UPDATE runs
                SET state = CASE
                        WHEN state IN ('review', 'completed', 'failed', 'cancelled')
                        THEN state
                        ELSE 'cancelled'
                    END,
                    lease_generation = NULL,
                    lease_token = NULL,
                    updated_at = ?
                """,
                (now,),
            )
            connection.execute(
                """
                UPDATE port_reservations
                SET state = 'released', released_at = ?, updated_at = ?
                WHERE state = 'active'
                  AND run_id IN (
                      SELECT run_id FROM runs WHERE state = 'cancelled'
                  )
                """,
                (now, now),
            )
            connection.execute("DELETE FROM secrets WHERE key = 'pat'")
            connection.execute(
                "DELETE FROM settings WHERE key IN "
                "('agent_profile_id', 'active_run_id', 'credential_id', "
                "'credential_failure_code')"
            )
            connection.execute(
                """
                INSERT INTO credentials(
                    singleton, credential_type, generation, access_token,
                    access_expires_at, refresh_token, oauth_client_id, family_id,
                    last_successful_refresh, reauthentication_required, updated_at
                ) VALUES (1, 'oauth_installation', ?, ?, ?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    credential_type = excluded.credential_type,
                    generation = excluded.generation,
                    access_token = excluded.access_token,
                    access_expires_at = excluded.access_expires_at,
                    refresh_token = excluded.refresh_token,
                    previous_refresh_token = NULL,
                    recovery_rotation_id = NULL,
                    oauth_client_id = excluded.oauth_client_id,
                    family_id = excluded.family_id,
                    last_successful_refresh = excluded.last_successful_refresh,
                    revoked_at = NULL,
                    reauthentication_required = 0,
                    updated_at = excluded.updated_at
                """,
                (
                    generation,
                    access_token,
                    expires_at.isoformat(),
                    refresh_token,
                    oauth_client_id,
                    family_id,
                    now,
                    now,
                ),
            )
            settings = {
                "installation_id": str(installation["id"]),
                "installation_status": str(installation["status"]),
                "authentication_required": "false",
                "credential_revoked": "false",
                "installation_revoked": "false",
                "last_credential_type": "oauth_installation",
            }
            if codex_profile is not None:
                settings["agent_profile_id"] = str(codex_profile["id"])
            connection.executemany(
                """
                INSERT INTO settings(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                settings.items(),
            )

    def prepare_credential_refresh(self, rotation_id: str) -> CredentialRecord:
        with self.connection(immediate=True) as connection:
            row = connection.execute(
                "SELECT * FROM credentials WHERE singleton = 1"
            ).fetchone()
            if row is None:
                raise RuntimeError("No OAuth installation credential is configured")
            existing_rotation = row["recovery_rotation_id"]
            if existing_rotation is None:
                connection.execute(
                    """
                    UPDATE credentials
                    SET previous_refresh_token = refresh_token,
                        recovery_rotation_id = ?,
                        updated_at = ?
                    WHERE singleton = 1
                    """,
                    (rotation_id, datetime.now(UTC).isoformat()),
                )
            elif existing_rotation != rotation_id:
                raise RuntimeError("A credential refresh recovery is already pending")
        record = self.credential()
        assert record is not None
        return record

    def finish_credential_refresh(
        self,
        *,
        expected_generation: int,
        access_token: str,
        refresh_token: str,
        expires_at: datetime,
        generation: int,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connection(immediate=True) as connection:
            cursor = connection.execute(
                """
                UPDATE credentials
                SET generation = ?, access_token = ?, access_expires_at = ?,
                    refresh_token = ?, last_successful_refresh = ?,
                    reauthentication_required = 0, updated_at = ?
                WHERE singleton = 1 AND generation = ?
                """,
                (
                    generation,
                    access_token,
                    expires_at.isoformat(),
                    refresh_token,
                    now,
                    now,
                    expected_generation,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("Credential generation changed during refresh")
            connection.execute(
                "DELETE FROM settings WHERE key = 'credential_failure_code'"
            )
            connection.executemany(
                "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
                (
                    ("authentication_required", "false"),
                    ("credential_revoked", "false"),
                    ("installation_revoked", "false"),
                ),
            )

    def clear_credential_recovery(self) -> None:
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                UPDATE credentials
                SET previous_refresh_token = NULL, recovery_rotation_id = NULL,
                    updated_at = ?
                WHERE singleton = 1
                """,
                (datetime.now(UTC).isoformat(),),
            )

    def require_reauthentication(
        self, *, failure_code: str, revoked: bool = False
    ) -> None:
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                UPDATE credentials
                SET reauthentication_required = 1,
                    revoked_at = CASE WHEN ? THEN ? ELSE revoked_at END,
                    updated_at = ?
                WHERE singleton = 1
                """,
                (
                    int(revoked),
                    datetime.now(UTC).isoformat(),
                    datetime.now(UTC).isoformat(),
                ),
            )
            connection.executemany(
                "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
                (
                    ("authentication_required", "true"),
                    ("credential_failure_code", failure_code),
                    ("credential_revoked", "true" if revoked else "false"),
                    ("installation_revoked", "true" if revoked else "false"),
                ),
            )

    def delete_credentials(self) -> None:
        with self.connection(immediate=True) as connection:
            connection.execute("DELETE FROM credentials WHERE singleton = 1")
            connection.execute(
                "DELETE FROM settings WHERE key = 'credential_failure_code'"
            )
            connection.executemany(
                "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
                (
                    ("credential_revoked", "false"),
                    ("installation_revoked", "false"),
                ),
            )

    def save_setup_session(self, values: dict[str, str]) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO setup_sessions(
                    singleton, session_handle, code_verifier, state_value,
                    nonce_value, redirect_uri, issuer, token_endpoint,
                    credential_endpoint, activation_endpoint, audience,
                    authorization_url, client_id, expires_at, mode, intent,
                    updated_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    values["session_handle"],
                    values["code_verifier"],
                    values["state_value"],
                    values["nonce_value"],
                    values["redirect_uri"],
                    values["issuer"],
                    values["token_endpoint"],
                    values["credential_endpoint"],
                    values["activation_endpoint"],
                    values["audience"],
                    values["authorization_url"],
                    values["client_id"],
                    values["expires_at"],
                    values["mode"],
                    values["intent"],
                    now,
                ),
            )

    def setup_session(self) -> dict[str, str] | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM setup_sessions WHERE singleton = 1"
            ).fetchone()
        return dict(row) if row is not None else None

    def clear_setup_session(self) -> None:
        with self.connection(immediate=True) as connection:
            connection.execute("DELETE FROM setup_sessions WHERE singleton = 1")

    def configuration_revision(self) -> int:
        raw = self.get_setting("config_revision")
        return int(raw) if raw is not None else 0

    def set_configuration_revision(self, revision: int) -> None:
        self.set_setting("config_revision", str(revision))

    def request_maintenance(self) -> int:
        revision = int(self.get_setting("maintenance_revision") or "0") + 1
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO settings(key, value) VALUES ('maintenance_revision', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(revision),),
            )
            connection.execute(
                """
                INSERT INTO settings(key, value) VALUES ('maintenance_requested', '1')
                ON CONFLICT(key) DO UPDATE SET value = '1'
                """
            )
        return revision

    def acknowledge_maintenance(self, revision: int) -> None:
        self.set_setting("maintenance_ack_revision", str(revision))

    def maintenance_requested(self) -> bool:
        return self.get_setting("maintenance_requested") == "1"

    def maintenance_revision(self) -> int:
        return int(self.get_setting("maintenance_revision") or "0")

    def maintenance_ack_revision(self) -> int:
        return int(self.get_setting("maintenance_ack_revision") or "0")

    def clear_maintenance(self) -> None:
        self.set_setting("maintenance_requested", "0")

    def set_active_run(self, run_id: UUID | None) -> None:
        if run_id is None:
            self.delete_setting("active_run_id")
        else:
            self.set_setting("active_run_id", str(run_id))

    def active_run_id(self) -> UUID | None:
        raw = self.get_setting("active_run_id")
        active = self.leased_run_ids()
        if raw:
            legacy = UUID(raw)
            if legacy in active:
                return legacy
            self.delete_setting("active_run_id")
        return active[0] if active else None

    def active_run_ids(self) -> list[UUID]:
        return self.leased_run_ids()

    @staticmethod
    def _change_set(row: sqlite3.Row) -> ChangeSetRecord:
        return ChangeSetRecord(
            run_id=UUID(str(row["run_id"])),
            state=str(row["state"]),
            repository_path=Path(str(row["repository_path"])),
            worktree_path=Path(str(row["worktree_path"])),
            base_commit=str(row["base_commit"]),
            snapshot_commit=row["snapshot_commit"],
            snapshot_tree=row["snapshot_tree"],
            validation_revision=int(row["validation_revision"]),
            change_set_revision=int(row["change_set_revision"]),
            validation_status=str(row["validation_status"]),
            accepted_revision=(
                int(row["accepted_revision"])
                if row["accepted_revision"] is not None
                else None
            ),
            accepted_snapshot_commit=row["accepted_snapshot_commit"],
            accepted_snapshot_tree=row["accepted_snapshot_tree"],
        )

    def change_set(self, run_id: UUID) -> ChangeSetRecord | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM change_sets WHERE run_id = ?", (str(run_id),)
            ).fetchone()
        return self._change_set(row) if row is not None else None

    def change_sets(self) -> list[ChangeSetRecord]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM change_sets ORDER BY created_at DESC, run_id"
            ).fetchall()
        return [self._change_set(row) for row in rows]

    def begin_change_set(
        self,
        *,
        run_id: UUID,
        repository_path: Path,
        worktree_path: Path,
        base_commit: str,
        legacy: bool = False,
    ) -> ChangeSetRecord:
        now = datetime.now(UTC).isoformat()
        state = "legacy_manual_review_required" if legacy else "executing"
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO change_sets(
                    run_id, state, repository_path, worktree_path, base_commit,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO NOTHING
                """,
                (
                    str(run_id),
                    state,
                    str(repository_path),
                    str(worktree_path),
                    base_commit,
                    now,
                    now,
                ),
            )
        record = self.change_set(run_id)
        assert record is not None
        if (
            record.repository_path != repository_path
            or record.worktree_path != worktree_path
            or record.base_commit != base_commit
        ):
            raise RuntimeError("Run change-set identity does not match local state")
        return record

    def transition_change_set(
        self,
        run_id: UUID,
        *,
        expected_states: frozenset[str],
        next_state: str,
        expected_revision: int | None = None,
        values: dict[str, object] | None = None,
        increment_revision: bool = False,
    ) -> ChangeSetRecord:
        updates = dict(values or {})
        now = datetime.now(UTC).isoformat()
        with self.connection(immediate=True) as connection:
            row = connection.execute(
                "SELECT * FROM change_sets WHERE run_id = ?", (str(run_id),)
            ).fetchone()
            if row is None:
                raise RuntimeError(f"Change set {run_id} does not exist")
            current = self._change_set(row)
            if expected_revision is not None and (
                current.change_set_revision != expected_revision
            ):
                raise RuntimeError("Change-set revision changed")
            if current.state == next_state and all(
                row[key] == value for key, value in updates.items()
            ):
                return current
            if current.state not in expected_states:
                raise RuntimeError(
                    f"Invalid change-set transition {current.state} -> {next_state}"
                )
            assignments = ["state = ?", "updated_at = ?"]
            parameters: list[object] = [next_state, now]
            allowed_columns = {
                "snapshot_commit",
                "snapshot_tree",
                "validation_revision",
                "validation_status",
                "accepted_revision",
                "accepted_snapshot_commit",
                "accepted_snapshot_tree",
            }
            for key, value in updates.items():
                if key not in allowed_columns:
                    raise ValueError(f"Unsupported change-set field: {key}")
                assignments.append(f"{key} = ?")
                parameters.append(value)
            if increment_revision:
                assignments.append("change_set_revision = change_set_revision + 1")
            parameters.append(str(run_id))
            connection.execute(
                f"UPDATE change_sets SET {', '.join(assignments)} WHERE run_id = ?",
                parameters,
            )
            updated = connection.execute(
                "SELECT * FROM change_sets WHERE run_id = ?", (str(run_id),)
            ).fetchone()
        assert updated is not None
        return self._change_set(updated)

    def begin_validation(self, run_id: UUID, command: list[str]) -> int:
        now = datetime.now(UTC).isoformat()
        with self.connection(immediate=True) as connection:
            row = connection.execute(
                "SELECT validation_revision, state FROM change_sets WHERE run_id = ?",
                (str(run_id),),
            ).fetchone()
            if row is None:
                raise RuntimeError(f"Change set {run_id} does not exist")
            if row["state"] not in {"snapshot_ready", "review_ready"}:
                raise RuntimeError("Only an immutable snapshot can be validated")
            revision = int(row["validation_revision"]) + 1
            connection.execute(
                """
                INSERT INTO validation_runs(
                    run_id, revision, command_json, state, started_at
                ) VALUES (?, ?, ?, 'running', ?)
                """,
                (str(run_id), revision, json.dumps(command), now),
            )
            connection.execute(
                """
                UPDATE change_sets
                SET state = 'validating', validation_revision = ?,
                    validation_status = 'running', updated_at = ?
                WHERE run_id = ?
                """,
                (revision, now, str(run_id)),
            )
        return revision

    def accept_change_set(
        self,
        *,
        run_id: UUID,
        snapshot_commit: str,
        snapshot_tree: str,
        validation_revision: int,
        change_set_revision: int,
    ) -> ChangeSetRecord:
        record = self.change_set(run_id)
        if record is None:
            raise RuntimeError(f"Change set {run_id} does not exist")
        expected = (
            record.snapshot_commit,
            record.snapshot_tree,
            record.validation_revision,
            record.change_set_revision,
        )
        accepted = (
            snapshot_commit,
            snapshot_tree,
            validation_revision,
            change_set_revision,
        )
        if expected != accepted:
            raise RuntimeError("Accepted change-set binding does not match local state")
        return self.transition_change_set(
            run_id,
            expected_states=frozenset({"review_ready"}),
            next_state="accepted",
            expected_revision=change_set_revision,
            values={
                "accepted_revision": change_set_revision,
                "accepted_snapshot_commit": snapshot_commit,
                "accepted_snapshot_tree": snapshot_tree,
            },
        )

    def finish_validation(
        self,
        run_id: UUID,
        *,
        revision: int,
        exit_code: int,
        log_path: Path,
    ) -> ChangeSetRecord:
        now = datetime.now(UTC).isoformat()
        status = "passed" if exit_code == 0 else "failed"
        with self.connection(immediate=True) as connection:
            row = connection.execute(
                "SELECT state, validation_revision FROM change_sets WHERE run_id = ?",
                (str(run_id),),
            ).fetchone()
            if row is None:
                raise RuntimeError(f"Change set {run_id} does not exist")
            if int(row["validation_revision"]) != revision:
                raise RuntimeError("Validation revision changed")
            validation = connection.execute(
                "SELECT state FROM validation_runs WHERE run_id = ? AND revision = ?",
                (str(run_id), revision),
            ).fetchone()
            if validation is None:
                raise RuntimeError("Validation run does not exist")
            if validation["state"] == status and row["state"] == "review_ready":
                record = connection.execute(
                    "SELECT * FROM change_sets WHERE run_id = ?", (str(run_id),)
                ).fetchone()
                assert record is not None
                return self._change_set(record)
            if row["state"] != "validating" or validation["state"] != "running":
                raise RuntimeError("Validation is not running")
            connection.execute(
                """
                UPDATE validation_runs
                SET state = ?, exit_code = ?, log_path = ?, finished_at = ?
                WHERE run_id = ? AND revision = ?
                """,
                (status, exit_code, str(log_path), now, str(run_id), revision),
            )
            connection.execute(
                """
                UPDATE change_sets
                SET state = 'review_ready', validation_status = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (status, now, str(run_id)),
            )
            record = connection.execute(
                "SELECT * FROM change_sets WHERE run_id = ?", (str(run_id),)
            ).fetchone()
        assert record is not None
        return self._change_set(record)

    def cancel_validation_start(self, run_id: UUID, revision: int) -> None:
        with self.connection(immediate=True) as connection:
            row = connection.execute(
                "SELECT state, validation_revision FROM change_sets WHERE run_id = ?",
                (str(run_id),),
            ).fetchone()
            if (
                row is None
                or row["state"] != "validating"
                or int(row["validation_revision"]) != revision
            ):
                raise RuntimeError("Validation start cannot be rolled back")
            previous = connection.execute(
                """
                SELECT state FROM validation_runs
                WHERE run_id = ? AND revision < ?
                ORDER BY revision DESC LIMIT 1
                """,
                (str(run_id), revision),
            ).fetchone()
            connection.execute(
                "DELETE FROM validation_runs WHERE run_id = ? AND revision = ?",
                (str(run_id), revision),
            )
            connection.execute(
                """
                UPDATE change_sets
                SET state = 'review_ready', validation_revision = ?,
                    validation_status = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (
                    revision - 1,
                    str(previous["state"]) if previous is not None else "not_run",
                    datetime.now(UTC).isoformat(),
                    str(run_id),
                ),
            )

    def handoff(self, run_id: UUID) -> sqlite3.Row | None:
        with self.connection() as connection:
            return connection.execute(
                "SELECT * FROM handoffs WHERE run_id = ?", (str(run_id),)
            ).fetchone()

    def begin_handoff(
        self,
        *,
        run_id: UUID,
        snapshot_commit: str,
        snapshot_tree: str,
        validation_revision: int,
        change_set_revision: int,
        checkout_path: Path,
        common_directory: Path,
        captured_head: str,
        captured_branch: str | None,
        captured_status: str,
        captured_index_digest: str,
        method: str,
    ) -> sqlite3.Row:
        now = datetime.now(UTC).isoformat()
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO handoffs(
                    run_id, state, snapshot_commit, snapshot_tree,
                    validation_revision, change_set_revision, checkout_path,
                    common_directory, captured_head, captured_branch,
                    captured_status, captured_index_digest, method,
                    created_at, updated_at
                ) VALUES (?, 'applying', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    state = 'applying',
                    checkout_path = excluded.checkout_path,
                    common_directory = excluded.common_directory,
                    captured_head = excluded.captured_head,
                    captured_branch = excluded.captured_branch,
                    captured_status = excluded.captured_status,
                    captured_index_digest = excluded.captured_index_digest,
                    method = excluded.method,
                    error = NULL,
                    updated_at = excluded.updated_at
                WHERE handoffs.state = 'retry_requested'
                """,
                (
                    str(run_id),
                    snapshot_commit,
                    snapshot_tree,
                    validation_revision,
                    change_set_revision,
                    str(checkout_path),
                    str(common_directory),
                    captured_head,
                    captured_branch,
                    captured_status,
                    captured_index_digest,
                    method,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM handoffs WHERE run_id = ?", (str(run_id),)
            ).fetchone()
        assert row is not None
        identity = (
            row["snapshot_commit"],
            row["snapshot_tree"],
            int(row["validation_revision"]),
            int(row["change_set_revision"]),
        )
        if identity != (
            snapshot_commit,
            snapshot_tree,
            validation_revision,
            change_set_revision,
        ):
            raise RuntimeError("Handoff identity does not match accepted revision")
        return row

    def request_handoff_retry(self, run_id: UUID) -> None:
        with self.connection(immediate=True) as connection:
            cursor = connection.execute(
                """
                UPDATE handoffs
                SET state = 'retry_requested', updated_at = ?
                WHERE run_id = ? AND state = 'blocked'
                """,
                (datetime.now(UTC).isoformat(), str(run_id)),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("Only a blocked handoff can be retried")

    def finish_handoff(
        self,
        run_id: UUID,
        *,
        state: str,
        applied_commit: str | None = None,
        error: str | None = None,
    ) -> None:
        if state not in {"applied", "blocked"}:
            raise ValueError("Unsupported handoff state")
        with self.connection(immediate=True) as connection:
            row = connection.execute(
                "SELECT state FROM handoffs WHERE run_id = ?", (str(run_id),)
            ).fetchone()
            if row is None:
                raise RuntimeError(f"Handoff {run_id} does not exist")
            if row["state"] == state:
                return
            if row["state"] != "applying":
                raise RuntimeError("Handoff is not applying")
            connection.execute(
                """
                UPDATE handoffs
                SET state = ?, applied_commit = ?, error = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (
                    state,
                    applied_commit,
                    error,
                    datetime.now(UTC).isoformat(),
                    str(run_id),
                ),
            )

    def leased_run_ids(self) -> list[UUID]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT run_id FROM runs
                WHERE lease_token IS NOT NULL
                  AND state NOT IN ('review', 'completed', 'failed', 'cancelled')
                ORDER BY run_id
                """
            ).fetchall()
        return [UUID(row["run_id"]) for row in rows]

    def leased_run_records(self) -> list[sqlite3.Row]:
        with self.connection() as connection:
            return connection.execute(
                """
                SELECT run_id, lease_generation, lease_token, worker_slot, state
                FROM runs
                WHERE lease_token IS NOT NULL
                  AND state NOT IN ('review', 'completed', 'failed', 'cancelled')
                ORDER BY COALESCE(worker_slot, 0), run_id
                """
            ).fetchall()

    @staticmethod
    def _port_reservation(row: sqlite3.Row) -> PortReservation:
        return PortReservation(
            run_id=UUID(str(row["run_id"])),
            worker_slot=int(row["worker_slot"]),
            port_start=int(row["port_start"]),
            port_end=int(row["port_end"]),
            state=str(row["state"]),
            revision=int(row["revision"]),
        )

    def port_reservation(self, run_id: UUID) -> PortReservation | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM port_reservations WHERE run_id = ?",
                (str(run_id),),
            ).fetchone()
        return self._port_reservation(row) if row is not None else None

    def active_port_reservations(self) -> list[PortReservation]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM port_reservations
                WHERE released_at IS NULL
                ORDER BY worker_slot, run_id
                """
            ).fetchall()
        return [self._port_reservation(row) for row in rows]

    def reserve_port_range(
        self,
        *,
        run_id: UUID,
        worker_slot: int,
        port_start: int,
        port_end: int,
    ) -> PortReservation:
        now = datetime.now(UTC).isoformat()
        with self.connection(immediate=True) as connection:
            existing = connection.execute(
                "SELECT * FROM port_reservations WHERE run_id = ?",
                (str(run_id),),
            ).fetchone()
            if existing is not None:
                reservation = self._port_reservation(existing)
                if reservation.worker_slot != worker_slot:
                    raise RuntimeError("Run already owns a different worker slot")
                return reservation
            overlap = connection.execute(
                """
                SELECT 1 FROM port_reservations
                WHERE released_at IS NULL
                  AND NOT (port_end < ? OR port_start > ?)
                LIMIT 1
                """,
                (port_start, port_end),
            ).fetchone()
            if overlap is not None:
                raise RuntimeError("Port range is already reserved by another run")
            connection.execute(
                """
                INSERT INTO port_reservations(
                    run_id, worker_slot, port_start, port_end, state,
                    revision, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'reserved', 1, ?, ?)
                """,
                (
                    str(run_id),
                    worker_slot,
                    port_start,
                    port_end,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM port_reservations WHERE run_id = ?",
                (str(run_id),),
            ).fetchone()
        assert row is not None
        return self._port_reservation(row)

    def release_port_reservation(self, run_id: UUID) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                UPDATE port_reservations
                SET state = 'released', released_at = ?, updated_at = ?,
                    revision = revision + 1
                WHERE run_id = ? AND released_at IS NULL
                """,
                (now, now, str(run_id)),
            )

    def set_daemon_status(self, value: str) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connection(immediate=True) as connection:
            for key, setting in (
                ("daemon_status", value),
                ("daemon_status_at", now),
            ):
                connection.execute(
                    """
                    INSERT INTO settings(key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (key, setting),
                )

    def record_registration(self, response: dict) -> None:
        installation_id = str(response["id"])
        status = str(response["status"])
        profiles = response.get("profiles") or []
        codex_profile = next(
            (
                profile
                for profile in profiles
                if profile.get("runtime_kind") == "codex_cli"
            ),
            None,
        )
        with self.connection(immediate=True) as connection:
            values = {
                "installation_id": installation_id,
                "installation_status": status,
            }
            if codex_profile is not None:
                values["agent_profile_id"] = str(codex_profile["id"])
            else:
                connection.execute(
                    "DELETE FROM settings WHERE key = 'agent_profile_id'"
                )
            for key, value in values.items():
                connection.execute(
                    """
                    INSERT INTO settings(key, value) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (key, value),
                )

    def record_worktree(
        self,
        *,
        run_id: UUID,
        project_id: UUID,
        repository_path: Path,
        path: Path,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO worktrees(
                    run_id, project_id, repository_path, path, state, updated_at
                ) VALUES (?, ?, ?, ?, 'running', ?)
                ON CONFLICT(run_id, project_id) DO UPDATE SET
                    project_id = excluded.project_id,
                    repository_path = excluded.repository_path,
                    path = excluded.path,
                    state = excluded.state,
                    updated_at = excluded.updated_at
                """,
                (
                    str(run_id),
                    str(project_id),
                    str(repository_path),
                    str(path),
                    now,
                ),
            )

    def set_worktree_state(self, run_id: UUID, state: str) -> None:
        with self.connection(immediate=True) as connection:
            connection.execute(
                "UPDATE worktrees SET state = ?, updated_at = ? WHERE run_id = ?",
                (state, datetime.now(UTC).isoformat(), str(run_id)),
            )

    def worktree_rows(self) -> list[sqlite3.Row]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM worktrees ORDER BY updated_at, run_id"
            ).fetchall()
        return list(rows)

    def delete_worktree(self, run_id: UUID, project_id: UUID) -> None:
        with self.connection(immediate=True) as connection:
            connection.execute(
                "DELETE FROM worktrees WHERE run_id = ? AND project_id = ?",
                (str(run_id), str(project_id)),
            )

    def save_claim(
        self,
        run_id: UUID,
        generation: int,
        lease_token: str,
        worker_slot: int = 0,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO runs(
                    run_id, lease_generation, lease_token, worker_slot, state, updated_at
                ) VALUES (?, ?, ?, ?, 'claimed', ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    lease_generation = excluded.lease_generation,
                    lease_token = excluded.lease_token,
                    worker_slot = excluded.worker_slot,
                    state = excluded.state,
                    updated_at = excluded.updated_at
                """,
                (str(run_id), generation, lease_token, worker_slot, now),
            )

    def thread_id(self, run_id: UUID) -> str | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT thread_id FROM runs WHERE run_id = ?",
                (str(run_id),),
            ).fetchone()
        return str(row["thread_id"]) if row and row["thread_id"] else None

    def save_thread(self, run_id: UUID, thread_id: str) -> None:
        with self.connection(immediate=True) as connection:
            connection.execute(
                "UPDATE runs SET thread_id = ?, updated_at = ? WHERE run_id = ?",
                (thread_id, datetime.now(UTC).isoformat(), str(run_id)),
            )

    def pending_result(self, run_id: UUID) -> dict[str, object] | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT pending_result FROM runs WHERE run_id = ?",
                (str(run_id),),
            ).fetchone()
        if row is None or not row["pending_result"]:
            return None
        value = json.loads(str(row["pending_result"]))
        return value if isinstance(value, dict) else None

    def pending_result_run_ids(self) -> list[UUID]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT run_id FROM runs WHERE pending_result IS NOT NULL"
            ).fetchall()
        return [UUID(str(row["run_id"])) for row in rows]

    def save_pending_result(self, run_id: UUID, result: dict[str, object]) -> None:
        with self.connection(immediate=True) as connection:
            connection.execute(
                "UPDATE runs SET pending_result = ?, updated_at = ? WHERE run_id = ?",
                (
                    json.dumps(result, separators=(",", ":"), sort_keys=True),
                    datetime.now(UTC).isoformat(),
                    str(run_id),
                ),
            )

    def clear_pending_result(self, run_id: UUID) -> None:
        with self.connection(immediate=True) as connection:
            connection.execute(
                "UPDATE runs SET pending_result = NULL, updated_at = ? WHERE run_id = ?",
                (datetime.now(UTC).isoformat(), str(run_id)),
            )

    def finish_run(self, run_id: UUID, state: str) -> None:
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                UPDATE runs
                SET lease_token = NULL, state = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (state, datetime.now(UTC).isoformat(), str(run_id)),
            )
            connection.execute("DELETE FROM settings WHERE key = 'active_run_id'")
