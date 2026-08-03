import sqlite3
import stat
import threading
import time
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
    backup = tmp_path / "backups/state.sqlite3"
    source.backup(backup)

    restored = StateStore(tmp_path / "target/state.sqlite3")
    restored.restore_backup(backup)

    assert restored.get_secret("pat") == "tb_pat_preserved"
    assert restored.get_setting("installation_id") == str(installation_id)
    assert restored.get_setting("agent_profile_id") == str(profile_id)
    assert restored.leased_run_ids() == [run_id]
    assert restored.thread_id(run_id) == "codex-thread"


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
