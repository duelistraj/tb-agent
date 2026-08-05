import json
import logging
import subprocess
from pathlib import Path, PurePosixPath
from uuid import uuid4

import pytest

from tether_agent.cli import (
    _finish_guided_setup,
    _reconcile_oauth_credential,
    _RedactPatFilter,
    build_parser,
    run_cli,
    safe_error_message,
)
from tether_agent.config import (
    ProfileConfig,
    ProjectMapping,
    load_profile_config,
    write_profile_config,
)
from tether_agent.oauth import InstallationRevokedError
from tether_agent.paths import ProfilePaths
from tether_agent.services import (
    ServiceManager,
    _launchd_definition,
    _systemd_definition,
)
from tether_agent.state import StateStore


def set_profile_homes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TETHER_AGENT_CONFIG_HOME", str(tmp_path / "config-home"))
    monkeypatch.setenv("TETHER_AGENT_STATE_HOME", str(tmp_path / "state-home"))


def test_parser_exposes_every_phase_one_command() -> None:
    parser = build_parser()
    commands = [
        ["init"],
        ["run"],
        ["status"],
        ["migrate", "env"],
        ["workspace", "add", "--path", ".", "--project-id", str(uuid4())],
        ["workspace", "list"],
        ["workspace", "remove", str(uuid4())],
        ["profile", "list"],
        ["profile", "remove", "--local-only", "--yes"],
        ["auth", "set-pat"],
        ["auth", "status"],
        ["auth", "logout"],
        *[
            ["service", action]
            for action in (
                "install",
                "uninstall",
                "start",
                "stop",
                "restart",
                "status",
                "logs",
            )
        ],
    ]
    for command in commands:
        parsed = parser.parse_args(["--profile", "testing", *command])
        assert parsed.profile == "testing"


@pytest.mark.asyncio
async def test_guided_setup_waits_for_approval_before_returning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = ProfilePaths("default", tmp_path / "config", tmp_path / "state")
    registrations = 0

    async def register(_: ProfilePaths) -> dict:
        nonlocal registrations
        registrations += 1
        return {"id": str(uuid4()), "status": "active"}

    async def no_wait(_: float) -> None:
        return None

    monkeypatch.setattr("tether_agent.cli._register_profile", register)
    monkeypatch.setattr("tether_agent.cli.asyncio.sleep", no_wait)

    result = await _finish_guided_setup(
        paths,
        {"id": str(uuid4()), "status": "pending_approval"},
    )

    assert result["status"] == "active"
    assert registrations == 1


def test_existing_revoked_profile_is_replaced_by_init_without_manual_cleanup(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_profile_homes(tmp_path, monkeypatch)
    paths = ProfilePaths.resolve("default")
    project_id = uuid4()
    old_installation_id = uuid4()
    write_profile_config(
        paths.config_file,
        ProfileConfig(
            server_url="https://tetherbrain.net",
            installation_name="Local Codex agent",
            project_mappings=[
                ProjectMapping(
                    project_id=project_id,
                    local_path=git_repository,
                    remote_url="ssh://git@github.com/TetherBrain/example",
                )
            ],
        ),
    )
    store = StateStore(paths.state_file)
    store.set_setting("installation_id", str(old_installation_id))
    captured: dict[str, object] = {}

    async def login(**kwargs: object) -> dict:
        captured.update(kwargs)
        return {
            "installation": {
                "id": str(uuid4()),
                "status": "pending_approval",
            }
        }

    monkeypatch.setattr(
        "tether_agent.cli._reconcile_oauth_credential", lambda **kwargs: "revoked"
    )
    monkeypatch.setattr("tether_agent.cli.validate_codex_authentication", lambda: None)
    monkeypatch.setattr("tether_agent.cli.oauth_login", login)
    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: pytest.fail(f"Replacement prompted in the terminal: {prompt}"),
    )

    assert run_cli(["init", "--path", str(git_repository)]) == 0

    assert captured["intent"] == "replace"
    assert captured["replaces_installation_id"] == str(old_installation_id)
    assert captured["replacement_operation_id"]
    assert load_profile_config(paths.config_file).revision == 2
    output = capsys.readouterr().out
    assert "fresh installation" in output
    assert "already exists" not in output


def test_legacy_reauthentication_state_is_probed_once_and_classified_as_revoked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from datetime import UTC, datetime, timedelta

    set_profile_homes(tmp_path, monkeypatch)
    paths = ProfilePaths.resolve("default")
    store = StateStore(paths.state_file)
    store.activate_installation_credential(
        access_token="tb_iat_expired",
        refresh_token="tb_irt_recoverable",
        expires_at=datetime.now(UTC) - timedelta(minutes=5),
        generation=1,
        oauth_client_id="tb-agent-cli",
        family_id="family-legacy",
    )
    rotation_id = "legacy-recovery-rotation-with-entropy-123456"
    store.prepare_credential_refresh(rotation_id)
    store.require_reauthentication(failure_code="legacy_unclassified")
    store.delete_setting("credential_failure_code")
    calls: list[dict[str, object]] = []

    async def refresh(**kwargs: object) -> None:
        calls.append(kwargs)
        store.require_reauthentication(
            failure_code="installation_revoked",
            revoked=True,
        )
        raise InstallationRevokedError(
            "installation_revoked",
            "Installation was revoked",
        )

    monkeypatch.setattr("tether_agent.cli.refresh_credential", refresh)

    config = ProfileConfig()
    assert _reconcile_oauth_credential(paths=paths, config=config) == "revoked"
    assert calls == [
        {
            "paths": paths,
            "server_url": config.server_url,
            "force": True,
            "allow_reauthentication_probe": True,
        }
    ]
    assert store.credential() is not None
    assert store.credential().recovery_rotation_id == rotation_id

    monkeypatch.setattr(
        "tether_agent.cli.refresh_credential",
        lambda **kwargs: pytest.fail(f"Terminal credential retried: {kwargs}"),
    )
    assert _reconcile_oauth_credential(paths=paths, config=config) == "revoked"


def test_auth_login_routes_a_revoked_installation_through_replacement(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_profile_homes(tmp_path, monkeypatch)
    paths = ProfilePaths.resolve("default")
    old_installation_id = uuid4()
    write_profile_config(
        paths.config_file,
        ProfileConfig(
            project_mappings=[
                ProjectMapping(
                    project_id=uuid4(),
                    local_path=git_repository,
                    remote_url="ssh://git@github.com/TetherBrain/example",
                )
            ]
        ),
    )
    StateStore(paths.state_file).set_setting(
        "installation_id", str(old_installation_id)
    )
    captured: dict[str, object] = {}

    async def login(**kwargs: object) -> dict:
        captured.update(kwargs)
        return {
            "installation": {
                "id": str(uuid4()),
                "status": "pending_approval",
            }
        }

    monkeypatch.setattr(
        "tether_agent.cli._reconcile_oauth_credential", lambda **kwargs: "revoked"
    )
    monkeypatch.setattr("tether_agent.cli.validate_codex_authentication", lambda: None)
    monkeypatch.setattr("tether_agent.cli.oauth_login", login)
    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: pytest.fail(f"Replacement prompted in the terminal: {prompt}"),
    )

    assert run_cli(["auth", "login"]) == 0
    assert captured["intent"] == "replace"
    assert captured["replaces_installation_id"] == str(old_installation_id)


def test_replacement_reports_an_environment_pat_that_shadows_new_oauth(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_profile_homes(tmp_path, monkeypatch)
    monkeypatch.setenv("TETHER_AGENT_ACCESS_TOKEN", "tb_pat_environment")
    paths = ProfilePaths.resolve("default")
    old_installation_id = uuid4()
    write_profile_config(
        paths.config_file,
        ProfileConfig(
            project_mappings=[
                ProjectMapping(
                    project_id=uuid4(),
                    local_path=git_repository,
                    remote_url="ssh://git@github.com/TetherBrain/example",
                )
            ],
        ),
    )
    store = StateStore(paths.state_file)
    store.set_setting("installation_id", str(old_installation_id))

    async def login(**kwargs: object) -> dict:
        del kwargs
        return {
            "installation": {
                "id": str(uuid4()),
                "status": "pending_approval",
            }
        }

    monkeypatch.setattr(
        "tether_agent.cli._reconcile_oauth_credential", lambda **kwargs: "revoked"
    )
    monkeypatch.setattr("tether_agent.cli.validate_codex_authentication", lambda: None)
    monkeypatch.setattr("tether_agent.cli.oauth_login", login)

    assert run_cli(["init", "--path", str(git_repository), "--yes"]) == 1

    output = capsys.readouterr().out
    assert "unset TETHER_AGENT_ACCESS_TOKEN" in output
    assert "not complete" in output
    assert store.get_setting("replacement_operation_id") is None


def test_existing_healthy_profile_init_is_an_idempotent_no_op(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_profile_homes(tmp_path, monkeypatch)
    paths = ProfilePaths.resolve("default")
    project_id = uuid4()
    write_profile_config(
        paths.config_file,
        ProfileConfig(
            server_url="https://tetherbrain.net",
            project_mappings=[
                ProjectMapping(
                    project_id=project_id,
                    local_path=git_repository,
                    remote_url="ssh://git@github.com/TetherBrain/example",
                )
            ],
        ),
    )
    StateStore(paths.state_file)
    monkeypatch.setattr(
        "tether_agent.cli._reconcile_oauth_credential", lambda **kwargs: "valid"
    )

    assert run_cli(["init", "--path", str(git_repository)]) == 0
    assert load_profile_config(paths.config_file).revision == 1
    assert "No changes were needed" in capsys.readouterr().out


def test_existing_profile_init_adds_repository_when_registration_prints_itself(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from datetime import UTC, datetime, timedelta

    set_profile_homes(tmp_path, monkeypatch)
    paths = ProfilePaths.resolve("default")
    write_profile_config(
        paths.config_file,
        ProfileConfig(server_url="https://tetherbrain.net"),
    )
    store = StateStore(paths.state_file)
    store.activate_installation_credential(
        access_token="tb_iat_current",
        refresh_token="tb_irt_current",
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
        generation=1,
        oauth_client_id="tb-agent-cli",
        family_id=str(uuid4()),
    )
    project_id = uuid4()

    async def login(**kwargs: object) -> dict:
        del kwargs
        return {
            "installation": {"status": "pending_approval"},
            "resolved_projects": [
                {
                    "id": str(project_id),
                    "repository_url": "https://github.com/TetherBrain/example.git",
                }
            ],
        }

    registrations: list[str] = []
    monkeypatch.setattr(
        "tether_agent.cli._reconcile_oauth_credential", lambda **kwargs: "valid"
    )
    monkeypatch.setattr("tether_agent.cli.oauth_login", login)
    monkeypatch.setattr(
        "tether_agent.cli._sync_registration",
        lambda current: registrations.append(current.profile),
    )

    assert run_cli(["init", "--path", str(git_repository)]) == 0
    assert (
        load_profile_config(paths.config_file).project_mappings[0].project_id
        == project_id
    )
    assert registrations == ["default"]


def test_profile_remove_local_only_is_explicit_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_profile_homes(tmp_path, monkeypatch)
    paths = ProfilePaths.resolve("team")
    write_profile_config(paths.config_file, ProfileConfig())
    StateStore(paths.state_file)
    monkeypatch.setattr(
        "tether_agent.cli.ServiceManager.is_installed", lambda self: False
    )

    command = ["--profile", "team", "profile", "remove", "--local-only", "--yes"]
    assert run_cli(command) == 0
    assert not paths.config_dir.exists()
    assert not paths.state_dir.exists()
    assert run_cli(command) == 0


def test_init_uses_hidden_pat_and_creates_private_profile(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_profile_homes(tmp_path, monkeypatch)
    project_id = uuid4()
    credential_id = uuid4()
    prompted: list[str] = []

    async def validate_pat(server: str, pat: str) -> dict:
        assert server == "https://tetherbrain.net"
        assert pat == "tb_pat_never_print_me"
        return {
            "credential": {"id": str(credential_id)},
            "capabilities": {"content_write": True},
        }

    async def register(paths: ProfilePaths) -> dict:
        del paths
        return {"status": "pending_approval"}

    monkeypatch.setattr("tether_agent.cli.validate_codex_authentication", lambda: None)
    monkeypatch.setattr("tether_agent.cli._validate_pat", validate_pat)
    monkeypatch.setattr("tether_agent.cli._register_profile", register)
    monkeypatch.setattr(
        "tether_agent.services.ServiceManager.install",
        lambda self: pytest.fail("init must not install a service"),
    )
    monkeypatch.setattr(
        "tether_agent.cli.getpass.getpass",
        lambda prompt: prompted.append(prompt) or "tb_pat_never_print_me",
    )

    result = run_cli(
        [
            "--profile",
            "team",
            "init",
            "--auth",
            "pat",
            "--server",
            "https://tetherbrain.net",
            "--path",
            str(git_repository),
            "--project-id",
            str(project_id),
        ]
    )

    paths = ProfilePaths.resolve("team")
    config = load_profile_config(paths.config_file)
    store = StateStore(paths.state_file)
    output = capsys.readouterr().out
    assert result == 0
    assert prompted == ["Tether Brain PAT: "]
    assert config.project_mappings[0].project_id == project_id
    assert store.get_secret("pat") == "tb_pat_never_print_me"
    assert store.get_setting("credential_id") == str(credential_id)
    assert "awaiting capability approval" in output
    assert "tb_pat_never_print_me" not in output
    assert b"tb_pat_never_print_me" not in paths.config_file.read_bytes()


def test_oauth_init_resolves_project_from_remote_without_prompting_for_an_id(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_profile_homes(tmp_path, monkeypatch)
    project_id = uuid4()
    captured_hints: list[dict[str, str]] = []

    async def login(**kwargs: object) -> dict:
        hints = kwargs.get("repository_hints")
        assert isinstance(hints, list)
        captured_hints.extend(hints)
        return {
            "installation": {"status": "pending_approval"},
            "resolved_projects": [
                {
                    "id": str(project_id),
                    "repository_url": "https://github.com/TetherBrain/example",
                }
            ],
        }

    async def register(paths: ProfilePaths) -> dict:
        config = load_profile_config(paths.config_file)
        assert config.project_mappings[0].project_id == project_id
        return {"status": "pending_approval"}

    monkeypatch.setattr("tether_agent.cli.validate_codex_authentication", lambda: None)
    monkeypatch.setattr("tether_agent.cli.oauth_login", login)
    monkeypatch.setattr("tether_agent.cli._register_profile", register)
    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: pytest.fail(f"OAuth init unexpectedly prompted: {prompt}"),
    )

    result = run_cli(
        [
            "--profile",
            "oauth-team",
            "init",
            "--server",
            "https://tetherbrain.net",
            "--path",
            str(git_repository),
        ]
    )

    paths = ProfilePaths.resolve("oauth-team")
    mapping = load_profile_config(paths.config_file).project_mappings[0]
    assert result == 0
    assert mapping.project_id == project_id
    assert mapping.local_path == git_repository.resolve()
    assert captured_hints == [
        {
            "repository_url": "ssh://git@github.com/TetherBrain/example",
            "access": "write",
        }
    ]
    assert str(git_repository.resolve()) not in json.dumps(captured_hints)


def test_workspace_add_and_remove_without_pat_rotation_or_restart(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_profile_homes(tmp_path, monkeypatch)
    paths = ProfilePaths.resolve("team")
    from tether_agent.config import ProfileConfig, write_profile_config

    write_profile_config(paths.config_file, ProfileConfig())
    store = StateStore(paths.state_file)
    store.set_secret("pat", "tb_pat_unchanged")
    store.set_configuration_revision(1)
    syncs: list[str] = []
    monkeypatch.setattr(
        "tether_agent.cli._sync_registration",
        lambda current: syncs.append(current.profile),
    )
    project_id = uuid4()

    assert (
        run_cli(
            [
                "--profile",
                "team",
                "workspace",
                "add",
                "--path",
                str(git_repository),
                "--project-id",
                str(project_id),
            ]
        )
        == 0
    )
    assert load_profile_config(paths.config_file).revision == 2
    assert store.get_secret("pat") == "tb_pat_unchanged"

    assert run_cli(["--profile", "team", "workspace", "remove", str(project_id)]) == 0
    assert load_profile_config(paths.config_file).revision == 3
    assert load_profile_config(paths.config_file).project_mappings == []
    assert store.get_secret("pat") == "tb_pat_unchanged"
    assert syncs == ["team", "team"]


def test_oauth_workspace_add_resolves_project_without_prompting_for_an_id(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from datetime import UTC, datetime, timedelta

    from tether_agent.config import ProfileConfig, write_profile_config

    set_profile_homes(tmp_path, monkeypatch)
    paths = ProfilePaths.resolve("team")
    write_profile_config(paths.config_file, ProfileConfig())
    store = StateStore(paths.state_file)
    store.activate_installation_credential(
        access_token="tb_iat_current",
        refresh_token="tb_irt_current",
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
        generation=1,
        oauth_client_id="tb-agent-cli",
        family_id=str(uuid4()),
    )
    project_id = uuid4()
    captured: dict[str, object] = {}

    async def login(**kwargs: object) -> dict:
        captured.update(kwargs)
        return {
            "installation": {"status": "pending_approval"},
            "resolved_projects": [
                {
                    "id": str(project_id),
                    "repository_url": "https://github.com/TetherBrain/example.git",
                }
            ],
        }

    registrations: list[str] = []
    monkeypatch.setattr("tether_agent.cli.oauth_login", login)
    monkeypatch.setattr(
        "tether_agent.cli._sync_registration",
        lambda current: registrations.append(current.profile),
    )
    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: pytest.fail(f"OAuth workspace add prompted: {prompt}"),
    )

    assert (
        run_cli(
            [
                "--profile",
                "team",
                "workspace",
                "add",
                "--path",
                str(git_repository),
            ]
        )
        == 0
    )

    mapping = load_profile_config(paths.config_file).project_mappings[0]
    assert mapping.project_id == project_id
    assert mapping.local_path == git_repository.resolve()
    assert captured["intent"] == "workspace_add"
    assert captured["repository_hints"] == [
        {
            "repository_url": "ssh://git@github.com/TetherBrain/example",
            "access": "write",
        }
    ]
    assert registrations == ["team"]


def test_oauth_workspace_add_rejects_an_existing_remote_before_authorization(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from datetime import UTC, datetime, timedelta

    from tether_agent.config import ProfileConfig, ProjectMapping, write_profile_config

    set_profile_homes(tmp_path, monkeypatch)
    paths = ProfilePaths.resolve("team")
    other_path = tmp_path / "other-checkout"
    other_path.mkdir()
    write_profile_config(
        paths.config_file,
        ProfileConfig(
            project_mappings=[
                ProjectMapping(
                    project_id=uuid4(),
                    local_path=other_path,
                    remote_url="https://github.com/tetherbrain/example.git",
                )
            ]
        ),
    )
    StateStore(paths.state_file).activate_installation_credential(
        access_token="tb_iat_current",
        refresh_token="tb_irt_current",
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
        generation=1,
        oauth_client_id="tb-agent-cli",
        family_id=str(uuid4()),
    )
    monkeypatch.setattr(
        "tether_agent.cli.oauth_login",
        lambda **kwargs: pytest.fail(f"OAuth started unexpectedly: {kwargs}"),
    )

    with pytest.raises(RuntimeError, match="already mapped to project"):
        run_cli(
            [
                "--profile",
                "team",
                "workspace",
                "add",
                "--path",
                str(git_repository),
            ]
        )
    assert load_profile_config(paths.config_file).revision == 1


def test_auth_set_pat_and_logout_preserve_installation_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_profile_homes(tmp_path, monkeypatch)
    paths = ProfilePaths.resolve("team")
    from tether_agent.config import ProfileConfig, write_profile_config

    write_profile_config(paths.config_file, ProfileConfig())
    store = StateStore(paths.state_file)
    credential_id = uuid4()
    installation_id = uuid4()
    profile_id = uuid4()
    store.set_secret("pat", "tb_pat_old")
    store.set_setting("credential_id", str(credential_id))
    store.set_setting("installation_id", str(installation_id))
    store.set_setting("agent_profile_id", str(profile_id))
    store.set_configuration_revision(1)

    async def validate_pat(server: str, pat: str) -> dict:
        del server
        assert pat == "tb_pat_replacement"
        return {
            "credential": {"id": str(credential_id)},
            "capabilities": {"content_write": True},
        }

    monkeypatch.setattr("tether_agent.cli._validate_pat", validate_pat)
    monkeypatch.setattr(
        "tether_agent.cli.getpass.getpass",
        lambda prompt: "tb_pat_replacement",
    )
    monkeypatch.setattr("tether_agent.cli._sync_registration", lambda paths: None)

    assert run_cli(["--profile", "team", "auth", "set-pat"]) == 0
    assert store.get_secret("pat") == "tb_pat_replacement"
    assert run_cli(["--profile", "team", "auth", "logout"]) == 0
    assert store.get_secret("pat") is None
    assert store.get_setting("authentication_required") == "true"
    assert store.get_setting("installation_id") == str(installation_id)
    assert store.get_setting("agent_profile_id") == str(profile_id)
    assert "tb_pat_replacement" not in capsys.readouterr().out


def test_environment_pat_keeps_stored_oauth_migration_shadowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_profile_homes(tmp_path, monkeypatch)
    paths = ProfilePaths.resolve("team")
    from datetime import UTC, datetime, timedelta

    from tether_agent.config import ProfileConfig, write_profile_config

    write_profile_config(paths.config_file, ProfileConfig())
    store = StateStore(paths.state_file)
    store.activate_installation_credential(
        access_token="tb_iat_stored",
        refresh_token="tb_irt_stored",
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
        generation=1,
        oauth_client_id="tether-agent-cli",
        family_id=str(uuid4()),
    )
    monkeypatch.setenv("TETHER_AGENT_ACCESS_TOKEN", "tb_pat_environment")

    assert run_cli(["--profile", "team", "auth", "migrate"]) == 1

    output = capsys.readouterr().out
    assert "unset TETHER_AGENT_ACCESS_TOKEN" in output
    assert "not complete" in output
    assert "tb_pat_environment" not in output


def test_init_fault_removes_partial_config_and_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_profile_homes(tmp_path, monkeypatch)

    async def validate_pat(server: str, pat: str) -> dict:
        del server, pat
        return {
            "credential": {"id": str(uuid4())},
            "capabilities": {"content_write": True},
        }

    monkeypatch.setattr("tether_agent.cli.validate_codex_authentication", lambda: None)
    monkeypatch.setattr("tether_agent.cli._validate_pat", validate_pat)
    monkeypatch.setattr(
        "tether_agent.cli.getpass.getpass", lambda prompt: "tb_pat_test"
    )

    def fail_revision(self: StateStore, revision: int) -> None:
        del self, revision
        raise OSError("injected init fault")

    monkeypatch.setattr(StateStore, "set_configuration_revision", fail_revision)
    with pytest.raises(OSError, match="injected"):
        run_cli(["--profile", "fault", "init", "--auth", "pat"])

    paths = ProfilePaths.resolve("fault")
    assert not paths.config_file.exists()
    assert not paths.state_file.exists()


def test_pat_redaction_covers_errors_and_log_records() -> None:
    secret = "tb_pat_abcdefghijklmnopqrstuvwxyz"
    assert secret not in safe_error_message(RuntimeError(f"failed with {secret}"))
    record = logging.LogRecord(
        "test",
        logging.ERROR,
        __file__,
        1,
        "request failed: %s",
        (secret,),
        None,
    )
    assert _RedactPatFilter().filter(record)
    assert secret not in record.getMessage()


def test_legacy_environment_status_and_workspace_list_require_no_migration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_profile_homes(tmp_path, monkeypatch)
    project_id = uuid4()
    monkeypatch.setenv("TETHER_AGENT_ACCESS_TOKEN", "tb_pat_legacy")
    monkeypatch.setenv(
        "TETHER_AGENT_PROJECT_MAPPINGS",
        json.dumps(
            [
                {
                    "project_id": str(project_id),
                    "local_path": str(tmp_path / "legacy-repository"),
                }
            ]
        ),
    )

    assert run_cli(["--profile", "legacy", "status"]) == 0
    assert run_cli(["--profile", "legacy", "auth", "status"]) == 0
    assert run_cli(["--profile", "legacy", "workspace", "list"]) == 0

    output = capsys.readouterr().out
    assert "legacy environment" in output
    assert "PAT configured by environment" in output
    assert str(project_id) in output
    assert "tb_pat_legacy" not in output
    assert not ProfilePaths.resolve("legacy").state_file.exists()


def test_service_definitions_contain_only_profile_executable_and_service_metadata(
    tmp_path: Path,
) -> None:
    paths = ProfilePaths(
        profile="team",
        config_dir=tmp_path / "private/repository/path",
        state_dir=tmp_path / "private/state/path",
    )
    executable = PurePosixPath("/opt/tether/bin/tb-agent")
    linux = _systemd_definition(paths, executable).decode()
    mac = _launchd_definition(paths, executable).decode()

    for definition in (linux, mac):
        assert str(executable) in definition
        assert "team" in definition
        assert "tb_pat_" not in definition
        assert str(paths.config_dir) not in definition
        assert str(paths.state_dir) not in definition


def test_service_management_rejects_windows_and_uses_user_systemd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = ProfilePaths("default", tmp_path / "config", tmp_path / "state")
    with pytest.raises(RuntimeError, match="foreground on Windows"):
        ServiceManager(paths, platform="win32").start()

    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        del kwargs
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("tether_agent.services.subprocess.run", run)
    assert ServiceManager(paths, platform="linux").status() == 0
    assert commands == [
        ["systemctl", "--user", "status", "tether-agent-default.service"]
    ]


def test_service_status_warns_when_definition_uses_removed_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    paths = ProfilePaths("default", tmp_path / "config", tmp_path / "state")
    unit = tmp_path / "tether-agent-default.service"
    unit.write_text(
        '[Service]\nExecStart="/opt/tether/bin/tether-agent" run\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("tether_agent.services._systemd_path", lambda paths: unit)
    monkeypatch.setattr(
        "tether_agent.services.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0),
    )

    assert ServiceManager(paths, platform="linux").status() == 0

    output = capsys.readouterr().out
    assert "removed tether-agent executable" in output
    assert "tb-agent service install" in output


def test_systemd_service_install_is_optional_and_contains_no_profile_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = ProfilePaths("work", tmp_path / "config", tmp_path / "private-state")
    unit = tmp_path / "systemd/tether-agent-work.service"
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        del kwargs
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("tether_agent.services._systemd_path", lambda paths: unit)
    monkeypatch.setattr(
        "tether_agent.services._executable",
        lambda: PurePosixPath("/opt/tether/bin/tb-agent"),
    )
    monkeypatch.setattr("tether_agent.services.subprocess.run", run)

    ServiceManager(paths, platform="linux").install()

    definition = unit.read_text(encoding="utf-8")
    assert 'ExecStart="/opt/tether/bin/tb-agent" --profile "work" run' in definition
    assert str(paths.config_dir) not in definition
    assert str(paths.state_dir) not in definition
    assert commands == [
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", "tether-agent-work.service"],
    ]
