import os
import stat
from pathlib import Path
from uuid import uuid4

import pytest

from tether_agent.config import (
    CommandRuntimeModel,
    DaemonSettings,
    ProfileConfig,
    ProjectMapping,
    RuntimeAdapterSettings,
    assert_mutation_not_shadowed,
    load_effective_settings,
    load_profile_config,
    write_profile_config,
)
from tether_agent.paths import ProfilePaths
from tether_agent.secure_files import (
    harden_private_file,
    secure_descriptor,
    validate_private_file,
)
from tether_agent.state import StateStore


def profile_paths(tmp_path: Path, profile: str = "default") -> ProfilePaths:
    return ProfilePaths.resolve(
        profile,
        environ={
            "TETHER_AGENT_CONFIG_HOME": str(tmp_path / "config"),
            "TETHER_AGENT_STATE_HOME": str(tmp_path / "state"),
        },
        home=tmp_path,
        platform="linux",
    )


def test_platform_paths_and_profile_validation(tmp_path: Path) -> None:
    linux = ProfilePaths.resolve(
        "team.one", environ={}, home=tmp_path, platform="linux"
    )
    mac = ProfilePaths.resolve("team.one", environ={}, home=tmp_path, platform="darwin")
    windows = ProfilePaths.resolve(
        "team.one",
        environ={"APPDATA": str(tmp_path / "roaming")},
        home=tmp_path,
        platform="win32",
    )

    assert (
        linux.config_file
        == tmp_path / ".config/tether-agent/profiles/team.one/config.toml"
    )
    assert "Application Support" in str(mac.config_file)
    assert (
        windows.config_file
        == tmp_path / "roaming/tether-agent/profiles/team.one/config.toml"
    )
    with pytest.raises(ValueError, match="Profile names"):
        ProfilePaths.resolve("../escape", environ={}, home=tmp_path)


def test_profile_config_round_trip_has_private_permissions(
    tmp_path: Path,
    git_repository: Path,
) -> None:
    paths = profile_paths(tmp_path)
    mapping = ProjectMapping(
        project_id=uuid4(),
        local_path=git_repository,
        remote_url="ssh://git@github.com/TetherBrain/example",
    )
    config = ProfileConfig(
        server_url="https://tetherbrain.net/",
        project_mappings=[mapping],
    )

    write_profile_config(paths.config_file, config)

    assert load_profile_config(paths.config_file) == config.model_copy(
        update={"server_url": "https://tetherbrain.net"}
    )
    if os.name != "nt":
        assert stat.S_IMODE(paths.config_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(paths.config_file.stat().st_mode) == 0o600


def test_environment_overrides_profile_without_changing_stored_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = profile_paths(tmp_path)
    write_profile_config(
        paths.config_file,
        ProfileConfig(server_url="https://stored.example"),
    )
    store = StateStore(paths.state_file)
    store.set_secret("pat", "tb_pat_stored")
    monkeypatch.setenv("TETHER_AGENT_SERVER_URL", "https://override.example")
    monkeypatch.setenv("TETHER_AGENT_ACCESS_TOKEN", "tb_pat_override")

    settings = load_effective_settings(paths, store)

    assert settings.server_url == "https://override.example"
    assert settings.access_token == "tb_pat_override"
    assert load_profile_config(paths.config_file).server_url == "https://stored.example"


def test_runtime_model_configuration_round_trips_through_toml(tmp_path: Path) -> None:
    paths = profile_paths(tmp_path)
    config = ProfileConfig(
        runtime_adapters=[
            RuntimeAdapterSettings(
                runtime_kind="codex_cli",
                executable="/opt/bin/codex",
                models=[
                    CommandRuntimeModel(
                        id="gpt-test",
                        display_name="GPT Test",
                        supported_reasoning_efforts=["medium", "high"],
                        default_reasoning_effort="medium",
                        is_default=True,
                    )
                ],
            )
        ]
    )

    write_profile_config(paths.config_file, config)

    assert load_profile_config(paths.config_file) == config


def test_legacy_relative_mapping_is_normalized_for_compatibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    settings = DaemonSettings(
        access_token="tb_pat_test",
        project_mappings=[{"project_id": str(uuid4()), "local_path": "repository"}],
    )

    assert settings.project_mappings[0].local_path == tmp_path / "repository"


def test_mutation_rejects_process_or_dotenv_shadowing(tmp_path: Path) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text("TETHER_AGENT_PROJECT_MAPPINGS=[]\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="migrate env"):
        assert_mutation_not_shadowed(
            relevant_keys=frozenset({"TETHER_AGENT_PROJECT_MAPPINGS"}),
            environ={},
            dotenv_path=dotenv,
        )
    with pytest.raises(RuntimeError, match="TETHER_AGENT_ACCESS_TOKEN"):
        assert_mutation_not_shadowed(
            relevant_keys=frozenset({"TETHER_AGENT_ACCESS_TOKEN"}),
            environ={"TETHER_AGENT_ACCESS_TOKEN": "not inspected"},
            dotenv_path=tmp_path / "missing",
        )


@pytest.mark.skipif(os.name == "nt", reason="Windows uses ACLs, not POSIX mode bits")
def test_private_files_reject_unsafe_permissions_and_symlinks(tmp_path: Path) -> None:
    insecure = tmp_path / "insecure.sqlite3"
    insecure.touch(mode=0o644)
    os.chmod(insecure, 0o644)
    with pytest.raises(PermissionError, match="0600"):
        StateStore(insecure)

    target = tmp_path / "target.sqlite3"
    target.touch(mode=0o600)
    symlink = tmp_path / "linked.sqlite3"
    symlink.symlink_to(target)
    with pytest.raises(PermissionError, match="symlinked"):
        StateStore(symlink)

    dangling = tmp_path / "dangling.sqlite3"
    dangling.symlink_to(tmp_path / "missing-target.sqlite3")
    with pytest.raises(PermissionError, match="symlinked"):
        StateStore(dangling)


@pytest.mark.skipif(os.name == "nt", reason="Windows uses ACLs, not POSIX mode bits")
def test_harden_private_file_repairs_owned_file_without_following_symlinks(
    tmp_path: Path,
) -> None:
    private_file = tmp_path / "daemon.log"
    private_file.touch(mode=0o644)
    os.chmod(private_file, 0o644)

    harden_private_file(private_file)

    assert stat.S_IMODE(private_file.stat().st_mode) == 0o600

    symlink = tmp_path / "daemon.log.1"
    symlink.symlink_to(private_file)
    with pytest.raises(PermissionError, match="symlinked"):
        harden_private_file(symlink)


@pytest.mark.skipif(os.name == "nt", reason="Windows uses ACLs, not POSIX mode bits")
def test_harden_private_file_rejects_foreign_owner_before_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_file = tmp_path / "daemon.log"
    private_file.touch(mode=0o644)
    os.chmod(private_file, 0o644)
    monkeypatch.setattr(
        "tether_agent.secure_files.os.getuid",
        lambda: private_file.stat().st_uid + 1,
    )

    with pytest.raises(PermissionError, match="not owned"):
        harden_private_file(private_file)

    assert stat.S_IMODE(private_file.stat().st_mode) == 0o644


def test_private_file_mode_check_is_not_applied_to_windows_acl_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_file = tmp_path / "state.sqlite3"
    private_file.touch(mode=0o644)
    os.chmod(private_file, 0o644)
    monkeypatch.setattr("tether_agent.secure_files.os.name", "nt")

    validate_private_file(private_file, allow_missing=False)


def test_descriptor_mode_change_is_not_applied_to_windows_acl_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_file = tmp_path / "state.sqlite3"
    descriptor = os.open(private_file, os.O_RDWR | os.O_CREAT, 0o600)
    monkeypatch.setattr("tether_agent.secure_files.os.name", "nt")
    monkeypatch.setattr(
        os,
        "fchmod",
        lambda *_: pytest.fail("Windows ACL metadata must not use fchmod"),
        raising=False,
    )
    try:
        secure_descriptor(descriptor, private_file)
    finally:
        os.close(descriptor)
