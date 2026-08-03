import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from tether_agent.config import load_profile_config
from tether_agent.migration import migrate_environment
from tether_agent.paths import ProfilePaths
from tether_agent.state import StateStore


def migration_paths(tmp_path: Path) -> ProfilePaths:
    return ProfilePaths(
        profile="migrated",
        config_dir=tmp_path / "new-config",
        state_dir=tmp_path / "new-state",
    )


def configure_legacy_environment(
    monkeypatch: pytest.MonkeyPatch,
    *,
    repository: Path,
    state_path: Path,
    project_id: object,
    installation_id: object,
) -> None:
    values = {
        "TETHER_AGENT_ACCESS_TOKEN": "tb_pat_migration_secret",
        "TETHER_AGENT_SERVER_URL": "https://tetherbrain.net",
        "TETHER_AGENT_STATE_PATH": str(state_path),
        "TETHER_AGENT_INSTALLATION_ID": str(installation_id),
        "TETHER_AGENT_PROJECT_MAPPINGS": json.dumps(
            [
                {
                    "project_id": str(project_id),
                    "local_path": str(repository),
                    "access": "write",
                }
            ]
        ),
    }
    for key in tuple(os.environ):
        if key.startswith("TETHER_AGENT_"):
            monkeypatch.delenv(key, raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_dry_run_changes_nothing_and_never_prints_pat(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    source_path = tmp_path / "legacy/state.sqlite3"
    configure_legacy_environment(
        monkeypatch,
        repository=git_repository,
        state_path=source_path,
        project_id=uuid4(),
        installation_id=uuid4(),
    )
    paths = migration_paths(tmp_path)

    assert migrate_environment(paths, dry_run=True) == 0

    output = capsys.readouterr().out
    assert "Dry run complete" in output
    assert "tb_pat_migration_secret" not in output
    assert not paths.config_file.exists()
    assert not paths.state_file.exists()


def test_dry_run_does_not_initialize_or_modify_existing_legacy_state(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    source_path = tmp_path / "legacy/state.sqlite3"
    source = StateStore(source_path)
    installation_id = uuid4()
    source.set_setting("installation_id", str(installation_id))
    source.set_setting("agent_profile_id", str(uuid4()))
    before = source_path.read_bytes()
    before_files = {item.name for item in source_path.parent.iterdir()}
    configure_legacy_environment(
        monkeypatch,
        repository=git_repository,
        state_path=source_path,
        project_id=uuid4(),
        installation_id=installation_id,
    )

    migrate_environment(migration_paths(tmp_path), dry_run=True)

    assert source_path.read_bytes() == before
    assert {item.name for item in source_path.parent.iterdir()} == before_files


def test_migration_preserves_identity_lease_and_codex_thread_and_is_idempotent(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    source_path = tmp_path / "legacy/state.sqlite3"
    source = StateStore(source_path)
    installation_id = uuid4()
    agent_profile_id = uuid4()
    project_id = uuid4()
    run_id = uuid4()
    source.set_setting("installation_id", str(installation_id))
    source.set_setting("agent_profile_id", str(agent_profile_id))
    source.set_configuration_revision(4)
    source.save_claim(run_id, 9, "lease-token")
    source.save_thread(run_id, "codex-thread-id")
    configure_legacy_environment(
        monkeypatch,
        repository=git_repository,
        state_path=source_path,
        project_id=project_id,
        installation_id=installation_id,
    )
    paths = migration_paths(tmp_path)

    assert migrate_environment(paths, dry_run=False) == 0

    config = load_profile_config(paths.config_file)
    migrated = StateStore(paths.state_file)
    assert config.revision == 4
    assert config.project_mappings[0].project_id == project_id
    assert config.project_mappings[0].local_path == git_repository.resolve()
    assert migrated.get_secret("pat") == "tb_pat_migration_secret"
    assert migrated.get_setting("installation_id") == str(installation_id)
    assert migrated.get_setting("agent_profile_id") == str(agent_profile_id)
    assert migrated.leased_run_ids() == [run_id]
    assert migrated.thread_id(run_id) == "codex-thread-id"
    backups = list((paths.state_dir / "backups").glob("legacy-state-*.sqlite3"))
    assert len(backups) == 1

    assert migrate_environment(paths, dry_run=False) == 0
    assert len(list((paths.state_dir / "backups").glob("legacy-state-*.sqlite3"))) == 1


def test_migration_fault_restores_source_and_removes_partial_target(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    source_path = tmp_path / "legacy/state.sqlite3"
    source = StateStore(source_path)
    installation_id = uuid4()
    profile_id = uuid4()
    source.set_setting("installation_id", str(installation_id))
    source.set_setting("agent_profile_id", str(profile_id))
    configure_legacy_environment(
        monkeypatch,
        repository=git_repository,
        state_path=source_path,
        project_id=uuid4(),
        installation_id=installation_id,
    )
    paths = migration_paths(tmp_path)

    def fail_write(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("injected migration fault")

    monkeypatch.setattr("tether_agent.migration.write_profile_config", fail_write)
    with pytest.raises(OSError, match="injected"):
        migrate_environment(paths, dry_run=False)

    assert not paths.config_file.exists()
    assert not paths.state_file.exists()
    assert source.get_setting("installation_id") == str(installation_id)
    assert source.get_setting("agent_profile_id") == str(profile_id)


def test_migration_does_not_modify_shell_startup_files(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    shell_file = tmp_path / ".zshrc"
    shell_file.write_text("export KEEP_ME=1\n", encoding="utf-8")
    source_path = tmp_path / "legacy/state.sqlite3"
    source = StateStore(source_path)
    installation_id = uuid4()
    source.set_setting("agent_profile_id", str(uuid4()))
    configure_legacy_environment(
        monkeypatch,
        repository=git_repository,
        state_path=source_path,
        project_id=uuid4(),
        installation_id=installation_id,
    )

    migrate_environment(migration_paths(tmp_path), dry_run=False)

    assert shell_file.read_text(encoding="utf-8") == "export KEEP_ME=1\n"


def test_phase_one_migration_rejects_oauth_without_mutation(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    configure_legacy_environment(
        monkeypatch,
        repository=git_repository,
        state_path=tmp_path / "legacy/state.sqlite3",
        project_id=uuid4(),
        installation_id=uuid4(),
    )
    monkeypatch.setenv("TETHER_AGENT_OAUTH_CLIENT_ID", "client")
    monkeypatch.setenv("TETHER_AGENT_OAUTH_REFRESH_TOKEN", "refresh")
    paths = migration_paths(tmp_path)

    with pytest.raises(RuntimeError, match="not available in Phase 1"):
        migrate_environment(paths, dry_run=False)

    assert not paths.config_file.exists()
    assert not paths.state_file.exists()
