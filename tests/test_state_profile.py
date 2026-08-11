import os
import sqlite3
import stat
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from tether_agent.config import ProfileConfig, load_profile_config, write_profile_config
from tether_agent.locking import LockUnavailable, ProfileLock
from tether_agent.paths import ProfilePaths
from tether_agent.profile import ProfileManager
from tether_agent.state import StateStore


def paths_for(tmp_path: Path) -> ProfilePaths:
    return ProfilePaths(
        profile="default",
        config_dir=tmp_path / "config",
        state_dir=tmp_path / "state",
    )


def initialized_profile(tmp_path: Path) -> tuple[ProfilePaths, ProfileManager]:
    paths = paths_for(tmp_path)
    write_profile_config(paths.config_file, ProfileConfig())
    manager = ProfileManager(paths)
    manager.store.set_secret("pat", "tb_pat_original")
    manager.store.set_configuration_revision(1)
    return paths, manager


def test_state_uses_wal_transactions_and_private_permissions(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state/state.sqlite3")
    with store.connection() as connection:
        mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        timeout = connection.execute("PRAGMA busy_timeout").fetchone()[0]
    with (
        pytest.raises(RuntimeError),
        store.connection(immediate=True) as connection,
    ):
        connection.execute("INSERT INTO settings(key, value) VALUES ('rollback', 'no')")
        raise RuntimeError("fault")

    assert mode == "wal"
    assert timeout == 5_000
    assert store.get_setting("rollback") is None
    if os.name != "nt":
        assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
        assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700


def test_state_backup_preserves_identity_leases_and_threads(tmp_path: Path) -> None:
    source = StateStore(tmp_path / "source/state.sqlite3")
    installation_id = uuid4()
    profile_id = uuid4()
    run_id = uuid4()
    source.set_secret("pat", "tb_pat_preserved")
    source.set_setting("installation_id", str(installation_id))
    source.set_setting("agent_profile_id", str(profile_id))
    source.save_claim(run_id, 7, "lease-secret")
    source.save_thread(run_id, "codex-thread")
    source.save_pending_result(
        run_id,
        {
            "status": "completed",
            "message": "Finished once",
            "outputs": [],
            "completion_note": None,
        },
    )
    backup = tmp_path / "backups/state.sqlite3"
    source.backup(backup)

    restored = StateStore(tmp_path / "target/state.sqlite3")
    restored.restore_backup(backup)

    assert restored.get_secret("pat") == "tb_pat_preserved"
    assert restored.get_setting("installation_id") == str(installation_id)
    assert restored.get_setting("agent_profile_id") == str(profile_id)
    assert restored.leased_run_ids() == [run_id]
    assert restored.thread_id(run_id) == "codex-thread"
    assert restored.pending_result(run_id) == {
        "status": "completed",
        "message": "Finished once",
        "outputs": [],
        "completion_note": None,
    }


def test_task_turn_journal_recovers_results_in_batch_order(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state/state.sqlite3")
    run_id = uuid4()
    first_task_id = uuid4()
    second_task_id = uuid4()
    store.save_claim(run_id, 1, "lease-secret")

    for ordinal, task_id in enumerate((first_task_id, second_task_id)):
        store.begin_task_turn(
            run_id=run_id,
            task_id=task_id,
            ordinal=ordinal,
            turn_revision=1,
        )
        store.save_task_turn_result(
            run_id=run_id,
            task_id=task_id,
            turn_revision=1,
            checkpoint_revision=1,
            worktree_tree=str(ordinal + 1) * 40,
            result={
                "status": "succeeded",
                "message": f"Task {ordinal + 1} complete",
                "outputs": [],
            },
        )
        store.acknowledge_task_turn(
            run_id=run_id,
            task_id=task_id,
            turn_revision=1,
        )

    recovered = store.task_turn_results(run_id)

    assert [item["task_id"] for item in recovered] == [
        str(first_task_id),
        str(second_task_id),
    ]
    assert [item["message"] for item in recovered] == [
        "Task 1 complete",
        "Task 2 complete",
    ]
    assert (
        store.task_turn_result(
            run_id=run_id,
            task_id=first_task_id,
            turn_revision=1,
        )["_turn_state"]
        == "checkpoint_acknowledged"
    )


def test_state_backup_closes_every_sqlite_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = StateStore(tmp_path / "source/state.sqlite3")
    original_connect = sqlite3.connect
    closed: list[bool] = []

    class TrackingConnection(sqlite3.Connection):
        def close(self) -> None:
            closed.append(True)
            super().close()

    def connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        return original_connect(*args, **kwargs, factory=TrackingConnection)

    monkeypatch.setattr("tether_agent.state.sqlite3.connect", connect)

    source.backup(tmp_path / "backup/state.sqlite3")

    assert closed == [True, True]


def test_existing_setup_session_schema_gains_a_default_intent(tmp_path: Path) -> None:
    state_path = tmp_path / "state/state.sqlite3"
    state_path.parent.mkdir()
    with sqlite3.connect(state_path) as connection:
        connection.execute(
            """
            CREATE TABLE setup_sessions (
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
            )
            """
        )
        connection.execute(
            """
            INSERT INTO setup_sessions VALUES (
                1, 'handle', 'verifier', 'state', 'nonce',
                'http://127.0.0.1:49152/callback', 'https://tetherbrain.net',
                'https://tetherbrain.net/oauth/token',
                'https://tetherbrain.net/api/agent/setup/complete',
                'https://tetherbrain.net/api/agent/credentials/activate',
                'https://tetherbrain.net/api/agent/v1',
                'https://tetherbrain.net/setup', 'tb-agent-cli',
                '2099-01-01T00:00:00+00:00', 'login',
                '2026-08-04T00:00:00+00:00'
            )
            """
        )
    state_path.chmod(0o600)
    state_path.parent.chmod(0o700)

    session = StateStore(state_path).setup_session()

    assert session is not None
    assert session["intent"] == "reauthorize"


def test_profile_lock_allows_only_one_holder(tmp_path: Path) -> None:
    path = tmp_path / "profile.lock"
    first = ProfileLock(path, label="first")
    second = ProfileLock(path, label="second")
    first.acquire()
    try:
        assert ProfileLock.is_locked(path)
        with pytest.raises(LockUnavailable):
            second.acquire()
    finally:
        first.release()
    second.acquire()
    second.release()


def test_live_capacity_change_does_not_require_execution_maintenance(
    tmp_path: Path,
) -> None:
    paths, manager = initialized_profile(tmp_path)
    run_id = uuid4()
    manager.store.save_claim(run_id, 1, "lease-token", worker_slot=0)

    updated = manager.mutate_live_configuration(
        lambda current: current.model_copy(update={"max_concurrent_runs": 3}),
        environment_keys=frozenset(),
    )

    assert updated.max_concurrent_runs == 3
    assert updated.revision == 2
    assert load_profile_config(paths.config_file).max_concurrent_runs == 3
    assert manager.store.active_run_ids() == [run_id]


def test_mutation_rejects_stale_active_execution(tmp_path: Path) -> None:
    _, manager = initialized_profile(tmp_path)
    run_id = uuid4()
    manager.store.save_claim(run_id, 1, "lease")

    with pytest.raises(RuntimeError, match=str(run_id)):
        manager.mutate(
            lambda config: config,
            environment_keys=frozenset(),
            dotenv_path=tmp_path / "missing",
        )


def test_mutation_waits_for_running_daemon_maintenance(tmp_path: Path) -> None:
    paths, manager = initialized_profile(tmp_path)
    daemon_lock = ProfileLock(paths.daemon_lock, label="daemon")
    daemon_lock.acquire()
    stop = threading.Event()

    def acknowledge() -> None:
        observer = StateStore(paths.state_file)
        while not stop.is_set():
            if observer.maintenance_requested():
                observer.acknowledge_maintenance(observer.maintenance_revision())
                return
            time.sleep(0.01)

    worker = threading.Thread(target=acknowledge)
    worker.start()
    try:
        updated = manager.mutate(
            lambda config: config.model_copy(update={"installation_name": "Reloaded"}),
            environment_keys=frozenset(),
            dotenv_path=tmp_path / "missing",
        )
    finally:
        stop.set()
        worker.join(timeout=2)
        daemon_lock.release()

    assert updated.revision == 2
    assert manager.store.configuration_revision() == 2
    assert manager.store.get_setting("daemon_status") == "reload_requested"
    assert not manager.store.maintenance_requested()


def test_fault_during_mutation_restores_config_and_sqlite_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, manager = initialized_profile(tmp_path)
    original = paths.config_file.read_bytes()

    def fail_write(path: Path, config: ProfileConfig) -> None:
        del path, config
        raise OSError("injected write failure")

    monkeypatch.setattr("tether_agent.profile.write_profile_config", fail_write)
    with pytest.raises(OSError, match="injected"):
        manager.mutate(
            lambda config: config.model_copy(
                update={"installation_name": "Never committed"}
            ),
            environment_keys=frozenset(),
            dotenv_path=tmp_path / "missing",
            state_change=lambda: manager.store.set_secret("pat", "tb_pat_changed"),
        )

    assert paths.config_file.read_bytes() == original
    assert load_profile_config(paths.config_file).revision == 1
    assert manager.store.get_secret("pat") == "tb_pat_original"
    assert manager.store.configuration_revision() == 1
    assert not list(paths.state_dir.glob(".rollback-*.sqlite3"))


def test_sqlite_busy_timeout_allows_serialized_writers(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state/state.sqlite3")
    first = sqlite3.connect(store.path, timeout=5)
    first.execute("BEGIN IMMEDIATE")
    first.execute("INSERT INTO settings(key, value) VALUES ('first', 'writer')")
    completed = threading.Event()

    def second_writer() -> None:
        store.set_setting("second", "writer")
        completed.set()

    worker = threading.Thread(target=second_writer)
    worker.start()
    time.sleep(0.1)
    assert not completed.is_set()
    first.commit()
    first.close()
    worker.join(timeout=2)

    assert completed.is_set()
    assert store.get_setting("second") == "writer"


def test_replacement_activation_detaches_active_state_without_deleting_history(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "state/state.sqlite3")
    old_installation_id = str(uuid4())
    run_id = uuid4()
    store.set_setting("installation_id", old_installation_id)
    store.set_setting("agent_profile_id", str(uuid4()))
    store.set_setting("credential_failure_code", "installation_revoked")
    store.set_secret("pat", "tb_pat_old")
    store.save_claim(run_id, 1, "lease-secret")
    store.save_thread(run_id, "codex-thread-old")

    new_installation_id = str(uuid4())
    new_profile_id = str(uuid4())
    store.activate_replacement_credential(
        access_token="tb_iat_new",
        refresh_token="tb_irt_new",
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
        generation=1,
        oauth_client_id="tb-agent-cli",
        family_id=str(uuid4()),
        installation={
            "id": new_installation_id,
            "status": "pending_approval",
            "profiles": [{"id": new_profile_id, "runtime_kind": "codex_cli"}],
        },
    )

    credential = store.credential()
    assert credential is not None
    assert credential.access_token == "tb_iat_new"
    assert store.get_setting("installation_id") == new_installation_id
    assert store.get_setting("agent_profile_id") == new_profile_id
    assert store.get_setting("credential_failure_code") is None
    assert store.get_secret("pat") is None
    assert store.active_run_id() is None
    assert store.thread_id(run_id) == "codex-thread-old"


def test_deleting_credentials_clears_terminal_classification(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state/state.sqlite3")
    store.activate_installation_credential(
        access_token="tb_iat_old",
        refresh_token="tb_irt_old",
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
        generation=1,
        oauth_client_id="tb-agent-cli",
        family_id=str(uuid4()),
    )
    store.require_reauthentication(
        failure_code="installation_revoked",
        revoked=True,
    )

    store.delete_credentials()

    assert store.credential() is None
    assert store.get_setting("credential_failure_code") is None
    assert store.get_setting("credential_revoked") == "false"
    assert store.get_setting("installation_revoked") == "false"
