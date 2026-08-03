"""Crash-safe, profile-local daemon state and credentials."""

from __future__ import annotations

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
                    thread_id TEXT,
                    state TEXT NOT NULL,
                    worktree_path TEXT,
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

    def require_reauthentication(self, *, revoked: bool = False) -> None:
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
            connection.execute(
                "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
                ("authentication_required", "true"),
            )
            if revoked:
                connection.execute(
                    "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
                    ("credential_revoked", "true"),
                )

    def delete_credentials(self) -> None:
        with self.connection(immediate=True) as connection:
            connection.execute("DELETE FROM credentials WHERE singleton = 1")

    def save_setup_session(self, values: dict[str, str]) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO setup_sessions(
                    singleton, session_handle, code_verifier, state_value,
                    nonce_value, redirect_uri, issuer, token_endpoint,
                    credential_endpoint, activation_endpoint, audience,
                    authorization_url, client_id, expires_at, mode, updated_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        return UUID(raw) if raw else None

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

    def save_claim(self, run_id: UUID, generation: int, lease_token: str) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connection(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO runs(
                    run_id, lease_generation, lease_token, state, updated_at
                ) VALUES (?, ?, ?, 'claimed', ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    lease_generation = excluded.lease_generation,
                    lease_token = excluded.lease_token,
                    state = excluded.state,
                    updated_at = excluded.updated_at
                """,
                (str(run_id), generation, lease_token, now),
            )
            connection.execute(
                """
                INSERT INTO settings(key, value) VALUES ('active_run_id', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(run_id),),
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
            connection.execute(
                "DELETE FROM settings WHERE key = 'active_run_id' AND value = ?",
                (str(run_id),),
            )
