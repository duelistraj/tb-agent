"""Profile-aware command line interface for the local Tether Agent."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import logging.handlers
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO
from uuid import UUID, uuid4

import httpx

from tether_agent import __version__
from tether_agent.api import TetherApi
from tether_agent.changes import require_change_set, snapshot_diff, validate_snapshot
from tether_agent.codex_skill import install_skill, skill_status, uninstall_skill
from tether_agent.config import (
    MUTABLE_ENV_KEYS,
    DaemonSettings,
    ProfileConfig,
    ProjectMapping,
    assert_mutation_not_shadowed,
    configured_environment_keys,
    load_effective_settings,
    write_profile_config,
)
from tether_agent.daemon import AgentDaemon
from tether_agent.locking import LockUnavailable, ProfileLock
from tether_agent.oauth import (
    CredentialRefreshRejected,
    InstallationRevokedError,
    oauth_login,
    refresh_credential,
    validate_installation_credential,
)
from tether_agent.paths import DEFAULT_PROFILE, ProfilePaths
from tether_agent.profile import ProfileManager
from tether_agent.repositories import (
    git_remote_identity,
    inspect_repository,
    normalize_git_remote,
)
from tether_agent.secure_files import (
    FILE_MODE,
    ensure_private_directory,
    harden_private_file,
    secure_descriptor,
)
from tether_agent.services import ServiceManager
from tether_agent.state import StateStore

TOKEN_PATTERN = re.compile(r"tb_(?:pat|oat|ort|iat|irt|sat|sac|ssh|wsr)_[A-Za-z0-9_-]+")
WORKSPACE_ENV_KEYS = frozenset(
    {
        "TETHER_AGENT_CONFIG_REVISION",
        "TETHER_AGENT_PROJECT_MAPPINGS",
        "TETHER_AGENT_STATE_PATH",
    }
)
AUTH_ENV_KEYS = frozenset(
    {
        "TETHER_AGENT_ACCESS_TOKEN",
        "TETHER_AGENT_CONFIG_REVISION",
        "TETHER_AGENT_STATE_PATH",
    }
)
CONFIGURATION_ENV_KEYS = MUTABLE_ENV_KEYS
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3


class _RedactTokenFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        record.msg = TOKEN_PATTERN.sub("[REDACTED CREDENTIAL]", message)
        record.args = ()
        return True


# Keep the Phase 1 test and import surface while broadening redaction coverage.
_RedactPatFilter = _RedactTokenFilter


class _PrivateRotatingFileHandler(logging.handlers.RotatingFileHandler):
    def _open(self) -> TextIO:
        path = Path(self.baseFilename)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, FILE_MODE)
        try:
            secure_descriptor(descriptor, path)
            return os.fdopen(
                descriptor,
                self.mode,
                encoding=self.encoding,
                errors=self.errors,
            )
        except BaseException:
            os.close(descriptor)
            raise


def _configure_logging(paths: ProfilePaths) -> None:
    ensure_private_directory(paths.state_dir)
    for backup_index in range(LOG_BACKUP_COUNT + 1):
        suffix = "" if backup_index == 0 else f".{backup_index}"
        harden_private_file(Path(f"{paths.log_file}{suffix}"))
    if not paths.log_file.exists():
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(paths.log_file, flags, FILE_MODE)
        os.close(descriptor)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    file_handler = _PrivateRotatingFileHandler(
        paths.log_file,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    redactor = _RedactTokenFilter()
    stream.addFilter(redactor)
    file_handler.addFilter(redactor)
    logging.basicConfig(level=logging.INFO, handlers=[stream, file_handler], force=True)


def validate_codex_authentication() -> None:
    executable = shutil.which("codex")
    if executable is None:
        raise RuntimeError("Codex CLI is not installed or is not available on PATH")
    result = subprocess.run(
        [executable, "login", "status"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError("Codex CLI is not authenticated. Run 'codex login' first.")


async def _validate_pat(server_url: str, pat: str) -> dict:
    if not pat.startswith("tb_pat_"):
        raise RuntimeError("The supplied credential is not a Tether Brain PAT")
    api = TetherApi(server_url, pat)
    try:
        identity = await api.identity()
    except httpx.HTTPError as error:
        raise RuntimeError("Tether Brain rejected the supplied PAT") from error
    finally:
        await api.close()
    capabilities = identity.get("capabilities") or {}
    if not capabilities.get("content_write"):
        raise RuntimeError(
            "The daemon requires a PAT with Read and write access. Create or edit "
            "the PAT in Tether Brain Connections and retry."
        )
    return identity


async def _register_profile(paths: ProfilePaths) -> dict:
    store = StateStore(paths.state_file)
    settings = load_effective_settings(paths, store)
    daemon = AgentDaemon(settings, paths=paths)
    try:
        return await daemon.register_once()
    finally:
        await daemon.api.close()


async def _finish_guided_setup(
    paths: ProfilePaths,
    initial: dict,
) -> dict:
    """Keep setup alive until approval and model catalogue reporting finish."""
    response = initial
    if response["status"] == "active":
        return response
    print("Waiting for capability approval in the open browser page...")
    deadline = time.monotonic() + 600
    while response["status"] != "active":
        if time.monotonic() >= deadline:
            print(
                "Setup is still awaiting approval. Run 'tb-agent init --path .' "
                "to resume it later."
            )
            return response
        await asyncio.sleep(2)
        response = await _register_profile(paths)
    return response


def _print_registration(response: dict) -> None:
    if response["status"] == "active":
        print("Daemon installation is ready.")
    else:
        print(
            "Daemon installation is registered and awaiting capability approval "
            "in Tether Brain Agent execution settings."
        )


def _setup_session_status(store: StateStore) -> str:
    setup = store.setup_session()
    if setup is None:
        return "none"
    try:
        expires_at = datetime.fromisoformat(setup["expires_at"])
    except (KeyError, ValueError):
        return "invalid"
    return "resumable" if expires_at > datetime.now(UTC) else "expired"


def _sync_registration(paths: ProfilePaths) -> None:
    store = StateStore(paths.state_file)
    sync_lock = ProfileLock(paths.mutation_lock, label="capability registration")
    try:
        sync_lock.acquire()
    except LockUnavailable as error:
        raise RuntimeError(
            f"Another command is changing profile '{paths.profile}'"
        ) from error
    try:
        daemon_running = ProfileLock.is_locked(paths.daemon_lock)
        if not daemon_running:
            _print_registration(asyncio.run(_register_profile(paths)))
            return
    finally:
        sync_lock.release()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        status = store.get_setting("daemon_status")
        if status in {"pending_approval", "ready", "registration_error"}:
            if status == "ready":
                print("Running daemon reloaded the profile and is ready.")
            elif status == "pending_approval":
                print(
                    "Running daemon reloaded the profile and is awaiting capability "
                    "approval in Tether Brain."
                )
            else:
                print("Running daemon reloaded the profile but registration failed.")
            return
        time.sleep(0.2)
    print("Profile updated. The running daemon will reload it shortly.")


def _mapping_from_arguments(args: argparse.Namespace) -> ProjectMapping | None:
    if args.path is None:
        if (
            args.project_id is not None
            or args.remote is not None
            or args.allow_no_remote
        ):
            raise RuntimeError(
                "--project-id, --remote, and --allow-no-remote require --path"
            )
        return None
    project_id = args.project_id
    if project_id is None:
        raw = input("Tether Brain logical project ID: ").strip()
        if not raw:
            raise RuntimeError("A logical project ID is required when --path is used")
        project_id = UUID(raw)
    repository = inspect_repository(
        args.path,
        remote=args.remote,
        allow_no_remote=args.allow_no_remote,
    )
    return ProjectMapping(
        project_id=project_id,
        local_path=repository.root,
        access="write",
        remote_url=repository.remote_url,
    )


def _repository_for_existing_init(
    args: argparse.Namespace,
    config: ProfileConfig,
) -> tuple[object | None, ProjectMapping | None]:
    if args.path is None:
        return None, None
    repository = inspect_repository(
        args.path,
        remote=args.remote,
        allow_no_remote=args.allow_no_remote,
    )
    mapping = next(
        (
            item
            for item in config.project_mappings
            if item.local_path == repository.root
            or item.remote_url is not None
            and repository.remote_url is not None
            and git_remote_identity(item.remote_url)
            == git_remote_identity(repository.remote_url)
        ),
        None,
    )
    if mapping is not None and args.project_id not in {None, mapping.project_id}:
        raise RuntimeError(
            "The repository is already mapped to a different logical project"
        )
    return repository, mapping


def _validate_preserved_mappings(config: ProfileConfig) -> None:
    for mapping in config.project_mappings:
        repository = inspect_repository(
            mapping.local_path,
            allow_no_remote=mapping.remote_url is None,
        )
        if repository.root != mapping.local_path:
            raise RuntimeError(
                f"Stored repository mapping is no longer canonical: {mapping.local_path}"
            )
        if (
            mapping.remote_url is not None
            and repository.remote_url is not None
            and git_remote_identity(mapping.remote_url)
            != git_remote_identity(repository.remote_url)
        ):
            raise RuntimeError(
                "A stored repository remote changed. Remove and add the mapping again."
            )


def _reconcile_oauth_credential(*, paths: ProfilePaths, config: ProfileConfig) -> str:
    store = StateStore(paths.state_file)
    credential = store.credential()
    if credential is None:
        return "reauthorize"
    if store.get_setting("installation_revoked") == "true":
        return "revoked"
    if credential.reauthentication_required:
        failure_code = store.get_setting("credential_failure_code")
        if failure_code is not None:
            return (
                "revoked" if failure_code == "installation_revoked" else "reauthorize"
            )
        try:
            asyncio.run(
                refresh_credential(
                    paths=paths,
                    server_url=config.server_url,
                    force=True,
                    allow_reauthentication_probe=True,
                )
            )
            return "valid"
        except InstallationRevokedError:
            return "revoked"
        except CredentialRefreshRejected:
            return "reauthorize"
        except httpx.TransportError:
            return "offline"
    try:
        if credential.access_expires_at <= datetime.now(UTC):
            asyncio.run(
                refresh_credential(
                    paths=paths,
                    server_url=config.server_url,
                    force=True,
                )
            )
            return "valid"
        remote = asyncio.run(
            validate_installation_credential(
                server_url=config.server_url,
                access_token=credential.access_token,
            )
        )
        if remote.get("activated") is False:
            store.set_setting("credential_activation_pending", "true")
            asyncio.run(
                refresh_credential(
                    paths=paths,
                    server_url=config.server_url,
                )
            )
        return "revoked" if remote.get("revoked") else "valid"
    except InstallationRevokedError:
        return "revoked"
    except CredentialRefreshRejected:
        return "reauthorize"
    except httpx.HTTPStatusError as error:
        if error.response.status_code not in {401, 403}:
            raise
        try:
            asyncio.run(
                refresh_credential(
                    paths=paths,
                    server_url=config.server_url,
                    force=True,
                )
            )
            return "valid"
        except InstallationRevokedError:
            return "revoked"
        except CredentialRefreshRejected:
            return "reauthorize"
    except httpx.TransportError:
        return "offline"


def _reauthorize_existing_profile(
    *, manager: ProfileManager, paths: ProfilePaths, config: ProfileConfig
) -> dict:
    result: dict = {}

    def login() -> None:
        nonlocal result
        result = asyncio.run(
            oauth_login(
                paths=paths,
                config=config,
                mode="login",
                intent="reauthorize",
            )
        )

    manager.mutate(
        lambda current: current,
        environment_keys=_oauth_mutation_environment_keys(),
        state_change=login,
    )
    return result


def _replace_revoked_profile(
    *,
    manager: ProfileManager,
    paths: ProfilePaths,
    config: ProfileConfig,
) -> int:
    installation_id = manager.store.get_setting("installation_id")
    if installation_id is None:
        raise RuntimeError(
            "The revoked installation identity is missing. Remove this local profile "
            "and initialize it again."
        )
    if not config.project_mappings:
        raise RuntimeError(
            "The revoked profile has no repository mappings to preserve. Remove this "
            "local profile and initialize it again."
        )
    _validate_preserved_mappings(config)
    validate_codex_authentication()
    result: dict = {}
    replacement_operation_id = manager.store.get_setting(
        "replacement_operation_id"
    ) or str(uuid4())
    manager.store.set_setting("replacement_operation_id", replacement_operation_id)

    def replace() -> None:
        nonlocal result
        result = asyncio.run(
            oauth_login(
                paths=paths,
                config=config,
                mode="login",
                intent="replace",
                replaces_installation_id=installation_id,
                replacement_operation_id=replacement_operation_id,
            )
        )

    manager.mutate(
        lambda current: current,
        environment_keys=_oauth_mutation_environment_keys(),
        state_change=replace,
    )
    _print_registration(result["installation"])
    manager.store.delete_setting("replacement_operation_id")
    shadowed = _warn_environment_pat_shadow()
    print(
        f"Local profile '{paths.profile}' now uses fresh installation "
        f"{result['installation']['id']}."
    )
    if shadowed:
        print(
            "Replacement is stored but is not complete until the environment PAT "
            "override is removed."
        )
        return 1
    return 0


def _initialize_existing_profile(args: argparse.Namespace, paths: ProfilePaths) -> int:
    if args.auth == "pat":
        raise RuntimeError(
            "This local profile already exists. Use 'tb-agent auth set-pat' to "
            "switch explicitly to PAT fallback."
        )
    manager = ProfileManager(paths)
    config = manager.config()
    if args.server is not None and args.server.rstrip("/") != config.server_url:
        raise RuntimeError(
            f"Local profile '{paths.profile}' is configured for {config.server_url}. "
            "Use a different --profile for another server."
        )
    repository, mapping = _repository_for_existing_init(args, config)
    state = _reconcile_oauth_credential(paths=paths, config=config)
    if state == "offline":
        raise RuntimeError(
            "Tether Brain could not be reached. The local profile was preserved; "
            "retry when the server is available."
        )
    if state == "revoked":
        return _replace_revoked_profile(
            manager=manager,
            paths=paths,
            config=config,
        )
    if state == "reauthorize":
        validate_codex_authentication()
        result = _reauthorize_existing_profile(
            manager=manager,
            paths=paths,
            config=config,
        )
        _print_registration(result["installation"])
    if repository is not None and mapping is None:
        workspace_args = argparse.Namespace(
            path=args.path,
            project_id=args.project_id,
            remote=args.remote,
            allow_no_remote=args.allow_no_remote,
            setup_reference=None,
            access="write",
        )
        return command_workspace_add(workspace_args, paths)
    print(f"Local profile: {paths.profile}")
    if mapping is not None:
        print(f"Repository is already mapped to logical project {mapping.project_id}.")
    print("This local profile is already configured. No changes were needed.")
    capability_state = manager.store.get_setting("installation_status")
    if capability_state == "pending_approval":
        print("Capability approval is still pending in Tether Brain.")
    return 0


def command_init(args: argparse.Namespace, paths: ProfilePaths) -> int:
    if paths.config_file.exists():
        return _initialize_existing_profile(args, paths)
    lock = ProfileLock(paths.mutation_lock, label="profile initialization")
    try:
        lock.acquire()
    except LockUnavailable as error:
        raise RuntimeError(
            f"Another command is changing profile '{paths.profile}'"
        ) from error
    try:
        return _initialize_profile(args, paths)
    finally:
        lock.release()


def _initialize_profile(args: argparse.Namespace, paths: ProfilePaths) -> int:
    if paths.config_file.exists():
        raise RuntimeError(
            f"Profile '{paths.profile}' already exists. Use workspace or auth commands "
            "to change it."
        )
    assert_mutation_not_shadowed(relevant_keys=CONFIGURATION_ENV_KEYS)
    if ProfileLock.is_locked(paths.daemon_lock):
        raise RuntimeError(
            "A daemon is already running for this profile. Stop it and use "
            "'tb-agent migrate env' to preserve its existing installation."
        )
    state_existed = paths.state_file.exists()
    store = StateStore(paths.state_file) if state_existed else None
    if store is not None and store.active_run_id() is not None:
        raise RuntimeError(
            "An execution is active in the existing local state. Wait for it to "
            "finish before initializing this profile."
        )
    validate_codex_authentication()
    deferred_repository = None
    if args.auth == "oauth" and args.path is not None and args.project_id is None:
        deferred_repository = inspect_repository(
            args.path,
            remote=args.remote,
            allow_no_remote=args.allow_no_remote,
        )
        if deferred_repository.remote_url is None:
            raise RuntimeError(
                "Browser project selection requires a Git remote. Pass --project-id "
                "for a repository without a remote."
            )
        mapping = None
    else:
        mapping = _mapping_from_arguments(args)
    server_url = args.server or "https://tetherbrain.net"
    installation_name = args.name or "Local Codex agent"
    config = ProfileConfig(
        server_url=server_url,
        installation_name=installation_name,
        project_mappings=[mapping] if mapping is not None else [],
    )
    store = store or StateStore(paths.state_file)
    state_backup = paths.state_dir / f".init-rollback-{uuid4().hex}.sqlite3"
    if state_existed:
        store.backup(state_backup)
    try:
        write_profile_config(paths.config_file, config)
        store.set_configuration_revision(config.revision)
        if args.auth == "pat":
            print("PAT authentication is an advanced fallback.")
            pat = getpass.getpass("Tether Brain PAT: ")
            identity = asyncio.run(_validate_pat(server_url, pat))
            store.set_secret("pat", pat)
            store.set_setting("credential_id", str(identity["credential"]["id"]))
            store.set_setting("authentication_required", "false")
            store.set_setting("credential_revoked", "false")
            store.set_setting("last_credential_type", "pat")
        else:
            result = asyncio.run(
                oauth_login(
                    paths=paths,
                    config=config,
                    intent="init",
                    repository_hints=(
                        [
                            {
                                "repository_url": deferred_repository.remote_url,
                                "access": "write",
                            }
                        ]
                        if deferred_repository is not None
                        else None
                    ),
                )
            )
            if deferred_repository is not None:
                matches = [
                    item
                    for item in result.get("resolved_projects", [])
                    if git_remote_identity(str(item["repository_url"]))
                    == git_remote_identity(deferred_repository.remote_url)
                ]
                if len(matches) != 1:
                    raise RuntimeError(
                        "The browser did not confirm exactly one logical project "
                        "for this Git remote"
                    )
                resolved_mapping = ProjectMapping(
                    project_id=UUID(str(matches[0]["id"])),
                    local_path=deferred_repository.root,
                    access="write",
                    remote_url=deferred_repository.remote_url,
                )
                config = config.model_copy(
                    update={"project_mappings": [resolved_mapping]}
                )
                write_profile_config(paths.config_file, config)
    except BaseException:
        paths.config_file.unlink(missing_ok=True)
        if state_existed:
            store.restore_backup(state_backup)
        else:
            for suffix in ("", "-wal", "-shm"):
                Path(f"{paths.state_file}{suffix}").unlink(missing_ok=True)
        state_backup.unlink(missing_ok=True)
        raise
    try:
        registration = (
            asyncio.run(_register_profile(paths))
            if args.auth == "pat" or deferred_repository is not None
            else result["installation"]
        )
        if args.auth == "oauth" and sys.stdin.isatty():
            registration = asyncio.run(_finish_guided_setup(paths, registration))
    except BaseException:
        paths.config_file.unlink(missing_ok=True)
        if state_existed:
            store.restore_backup(state_backup)
        else:
            for suffix in ("", "-wal", "-shm"):
                Path(f"{paths.state_file}{suffix}").unlink(missing_ok=True)
        raise
    finally:
        state_backup.unlink(missing_ok=True)
    _print_registration(registration)
    print(f"Profile '{paths.profile}' stored at {paths.config_file}.")
    print(f"Run it with: tb-agent --profile {paths.profile} run")
    return 0


def command_run(args: argparse.Namespace, paths: ProfilePaths) -> int:
    del args
    settings = load_effective_settings(paths)
    _configure_logging(paths)
    asyncio.run(AgentDaemon(settings, paths=paths).run_forever())
    return 0


def command_status(args: argparse.Namespace, paths: ProfilePaths) -> int:
    if not paths.config_file.exists():
        environment_keys = configured_environment_keys()
        if environment_keys:
            print(f"Profile: {paths.profile}")
            print("Configuration: legacy environment")
            print(
                f"Daemon: {'running' if ProfileLock.is_locked(paths.daemon_lock) else 'stopped'}"
            )
            return 0
        print(f"Profile '{paths.profile}' is not initialized.")
        return 1
    manager = ProfileManager(paths)
    config = manager.config()
    store = manager.store
    environment_keys = configured_environment_keys()
    environment_pat = "TETHER_AGENT_ACCESS_TOKEN" in environment_keys
    credential = store.credential()
    remote_state = "local only" if args.offline else "not checked"
    if credential is not None and not environment_pat and not args.offline:
        try:
            remote_state = _reconcile_oauth_credential(paths=paths, config=config)
        except httpx.HTTPError:
            remote_state = "unavailable"
        credential = store.credential()
    print(f"Profile: {paths.profile}")
    print(f"Server: {config.server_url}")
    print(f"Configuration revision: {config.revision}")
    authentication = (
        "PAT configured by environment"
        if environment_pat
        else "OAuth installation credential"
        if credential is not None
        else "PAT advanced fallback"
        if store.get_secret("pat")
        else "logged out"
    )
    print(f"Authentication: {authentication}")
    if credential is not None:
        validity = (
            "revoked"
            if store.get_setting("installation_revoked") == "true"
            else "reauthentication required"
            if credential.reauthentication_required
            else "access token expired; refresh available"
            if credential.access_expires_at <= datetime.now(UTC)
            else "valid"
        )
        print(f"Credential validity: {validity}")
        print(f"Credential generation: {credential.generation}")
        print(f"Access token expiration: {credential.access_expires_at.isoformat()}")
        print(
            "Refresh status: "
            + ("recovery pending" if credential.recovery_rotation_id else "ready")
        )
        print(
            "Reauthentication required: "
            + ("yes" if credential.reauthentication_required else "no")
        )
        print(
            "Credential terminal reason: "
            + (store.get_setting("credential_failure_code") or "none")
        )
        print(f"Remote credential status: {remote_state}")
        print(
            "Credential activation pending: "
            + (
                "yes"
                if store.get_setting("credential_activation_pending") == "true"
                else "no"
            )
        )
        if environment_pat:
            print("Stored OAuth credential shadowed by environment PAT: yes")
    print(f"Installation: {store.get_setting('installation_id') or 'not registered'}")
    print(f"Agent Profile: {store.get_setting('agent_profile_id') or 'not reported'}")
    print(f"Capability state: {store.get_setting('installation_status') or 'unknown'}")
    print(
        "Authentication required: "
        + ("yes" if store.get_setting("authentication_required") == "true" else "no")
    )
    print(
        "Installation revocation: "
        + (
            "revoked"
            if credential is not None
            and store.get_setting("installation_revoked") == "true"
            or store.get_setting("credential_revoked") == "true"
            else "not reported"
        )
    )
    print(
        f"Daemon: {'running' if ProfileLock.is_locked(paths.daemon_lock) else 'stopped'}"
    )
    print(f"Daemon state: {store.get_setting('daemon_status') or 'unknown'}")
    active_runs = store.active_run_ids()
    print(f"Concurrency: {len(active_runs)}/{config.max_concurrent_runs}")
    print(
        "Active executions: "
        + (", ".join(str(run_id) for run_id in active_runs) if active_runs else "none")
    )
    print(f"Workspace mappings: {len(config.project_mappings)}")
    if environment_keys:
        print("Environment overrides: " + ", ".join(sorted(environment_keys)))
    print(f"Incomplete setup session: {_setup_session_status(store)}")
    return 0


def command_concurrency_status(args: argparse.Namespace, paths: ProfilePaths) -> int:
    del args
    manager = ProfileManager(paths)
    config = manager.config()
    active_runs = manager.store.active_run_ids()
    print(f"Configured capacity: {config.max_concurrent_runs}")
    print(f"Active executions: {len(active_runs)}")
    for run_id in active_runs:
        reservation = manager.store.port_reservation(run_id)
        suffix = (
            f" ports {reservation.port_start}-{reservation.port_end}"
            if reservation is not None
            else ""
        )
        print(f"  {run_id}{suffix}")
    return 0


def command_concurrency_set(args: argparse.Namespace, paths: ProfilePaths) -> int:
    manager = ProfileManager(paths)
    updated = manager.mutate_live_configuration(
        lambda current: current.model_copy(
            update={"max_concurrent_runs": args.capacity}
        ),
        environment_keys=frozenset({"TETHER_AGENT_MAX_CONCURRENT_RUNS"}),
    )
    active_count = len(manager.store.active_run_ids())
    print(f"Concurrent run capacity set to {updated.max_concurrent_runs}.")
    if active_count > updated.max_concurrent_runs:
        print(
            f"{active_count} runs remain active. No new run will be claimed until "
            "the active count is below the new capacity."
        )
    return 0


def command_changes_list(args: argparse.Namespace, paths: ProfilePaths) -> int:
    del args
    store = StateStore(paths.state_file)
    records = store.change_sets()
    if not records:
        print("No local change sets.")
        return 0
    for item in records:
        item = require_change_set(store, item.run_id)
        print(
            f"{item.run_id}\t{item.state}\trevision {item.change_set_revision}\t"
            f"validation {item.validation_status}"
        )
    return 0


def command_changes_status(args: argparse.Namespace, paths: ProfilePaths) -> int:
    store = StateStore(paths.state_file)
    record = require_change_set(store, args.run_id)
    print(f"Run: {record.run_id}")
    print(f"State: {record.state}")
    print(f"Base commit: {record.base_commit}")
    print(f"Snapshot commit: {record.snapshot_commit or 'none'}")
    print(f"Snapshot tree: {record.snapshot_tree or 'none'}")
    print(f"Change-set revision: {record.change_set_revision}")
    print(f"Validation revision: {record.validation_revision}")
    print(f"Validation: {record.validation_status}")
    handoff = store.handoff(args.run_id)
    if handoff is not None:
        print(f"Handoff state: {str(handoff['state']).replace('_', ' ')}")
        print(f"Handoff attempts: {int(handoff['attempt_count'])}")
        print(f"Next retry: {handoff['next_retry_at'] or 'none'}")
        print(f"Last handoff error: {handoff['last_error_message'] or 'none'}")
    if record.state == "legacy_manual_review_required":
        print(
            "Automatic snapshot and application are disabled. Inspect this worktree, "
            "then discard it or rerun the task."
        )
    return 0


def command_changes_diff(args: argparse.Namespace, paths: ProfilePaths) -> int:
    record = require_change_set(StateStore(paths.state_file), args.run_id)
    print(snapshot_diff(record) or "No file changes.")
    return 0


def command_changes_test(args: argparse.Namespace, paths: ProfilePaths) -> int:
    store = StateStore(paths.state_file)
    record = require_change_set(store, args.run_id)
    command = list(args.test_command)
    if command[:1] == ["--"]:
        command = command[1:]

    def report_validation(
        *,
        validation_revision: int,
        validation_status: str,
    ) -> None:
        settings = load_effective_settings(paths)
        daemon = AgentDaemon(settings, paths=paths)

        async def report() -> None:
            try:
                assert record.snapshot_commit is not None
                assert record.snapshot_tree is not None
                await daemon.api.report_change_set_validation(
                    record.run_id,
                    {
                        "run_id": str(record.run_id),
                        "snapshot_commit": record.snapshot_commit,
                        "snapshot_tree": record.snapshot_tree,
                        "validation_revision": validation_revision,
                        "change_set_revision": record.change_set_revision,
                        "validation_status": validation_status,
                    },
                )
            finally:
                await daemon.api.close()

        asyncio.run(report())

    updated, log_path = validate_snapshot(
        store=store,
        record=record,
        command=command,
        on_started=lambda revision: report_validation(
            validation_revision=revision,
            validation_status="running",
        ),
    )
    report_validation(
        validation_revision=updated.validation_revision,
        validation_status=updated.validation_status,
    )
    print(f"Validation {updated.validation_status}.")
    print(f"Log: {log_path}")
    return 0 if updated.validation_status == "passed" else 1


def command_changes_apply(args: argparse.Namespace, paths: ProfilePaths) -> int:
    settings = load_effective_settings(paths)
    daemon = AgentDaemon(settings, paths=paths)

    async def apply_pending() -> dict:
        try:
            remote = await daemon.api.run(args.run_id)
            if remote.get("state") not in {
                "accepted",
                "applying",
                "handoff_blocked",
                "awaiting_acknowledgement",
            }:
                raise RuntimeError(
                    "The exact change-set revision has not been accepted in Tether Brain"
                )
            if remote.get("state") == "handoff_blocked":
                daemon.store.request_handoff_retry(args.run_id)
            await daemon._reconcile_handoffs()
            return await daemon.api.run(args.run_id)
        finally:
            await daemon.api.close()

    result = asyncio.run(apply_pending())
    print(f"Handoff state: {str(result.get('state', 'unknown')).replace('_', ' ')}")
    return 0 if result.get("state") in {"completed", "awaiting_acknowledgement"} else 1


def command_workspace_add(args: argparse.Namespace, paths: ProfilePaths) -> int:
    repository = inspect_repository(
        args.path,
        remote=args.remote,
        allow_no_remote=args.allow_no_remote,
    )
    project_id = args.project_id
    if args.setup_reference:
        settings = load_effective_settings(paths)
        daemon = AgentDaemon(settings, paths=paths)

        async def redeem() -> dict:
            try:
                return await daemon.api.redeem_workspace_setup_reference(
                    args.setup_reference
                )
            finally:
                await daemon.api.close()

        resolved = asyncio.run(redeem())
        if project_id is not None and str(project_id) != str(resolved["project_id"]):
            raise RuntimeError("Setup reference does not match --project-id")
        project_id = UUID(str(resolved["project_id"]))
        expected_remote = normalize_git_remote(str(resolved["repository_url"]))
        if repository.remote_url is None or git_remote_identity(
            repository.remote_url
        ) != git_remote_identity(expected_remote):
            raise RuntimeError(
                "The current Git remote does not match the browser-confirmed repository"
            )
    if project_id is None and not args.setup_reference:
        manager = ProfileManager(paths)
        if manager.store.credential() is not None:
            if repository.remote_url is None:
                raise RuntimeError(
                    "Browser project selection requires a Git remote. Pass "
                    "--project-id for a repository without a remote."
                )
            resolved_mapping: ProjectMapping | None = None
            oauth_result: dict | None = None

            def add_resolved(config: ProfileConfig) -> ProfileConfig:
                if any(
                    item.local_path == repository.root
                    for item in config.project_mappings
                ):
                    raise RuntimeError(
                        f"Repository {repository.root} is already mapped"
                    )
                existing_remote = next(
                    (
                        item
                        for item in config.project_mappings
                        if item.remote_url is not None
                        and git_remote_identity(item.remote_url)
                        == git_remote_identity(repository.remote_url)
                    ),
                    None,
                )
                if existing_remote is not None:
                    raise RuntimeError(
                        "This Git repository is already mapped to project "
                        f"{existing_remote.project_id}"
                    )
                if resolved_mapping is None:
                    return config
                if any(
                    item.project_id == resolved_mapping.project_id
                    for item in config.project_mappings
                ):
                    raise RuntimeError(
                        f"Project {resolved_mapping.project_id} is already mapped"
                    )
                return config.model_copy(
                    update={
                        "project_mappings": [
                            *config.project_mappings,
                            resolved_mapping,
                        ]
                    }
                )

            def authorize_resolution() -> None:
                nonlocal oauth_result, resolved_mapping
                oauth_result = asyncio.run(
                    oauth_login(
                        paths=paths,
                        config=manager.config(),
                        mode="login",
                        intent="workspace_add",
                        repository_hints=[
                            {
                                "repository_url": repository.remote_url,
                                "access": args.access,
                            }
                        ],
                    )
                )
                matches = [
                    item
                    for item in oauth_result.get("resolved_projects", [])
                    if git_remote_identity(str(item["repository_url"]))
                    == git_remote_identity(repository.remote_url)
                ]
                if len(matches) != 1:
                    raise RuntimeError(
                        "The browser did not confirm exactly one logical project "
                        "for this Git remote"
                    )
                resolved_mapping = ProjectMapping(
                    project_id=UUID(str(matches[0]["id"])),
                    local_path=repository.root,
                    access=args.access,
                    remote_url=repository.remote_url,
                )

            manager.mutate(
                add_resolved,
                environment_keys=WORKSPACE_ENV_KEYS,
                state_change=authorize_resolution,
            )
            _sync_registration(paths)
            _warn_environment_pat_shadow()
            return 0
    if project_id is None:
        raw = input(
            "Logical project ID, or generate a setup command from Tether Brain "
            "Agent execution settings: "
        ).strip()
        if not raw:
            raise RuntimeError("A logical project ID or --setup-reference is required")
        project_id = UUID(raw)
    mapping = ProjectMapping(
        project_id=project_id,
        local_path=repository.root,
        access=args.access,
        remote_url=repository.remote_url,
    )
    manager = ProfileManager(paths)
    if (
        manager.store.credential() is None
        and manager.store.get_secret("pat") is None
        and "TETHER_AGENT_ACCESS_TOKEN" not in configured_environment_keys()
    ):
        raise RuntimeError("Authenticate this profile before changing workspaces")
    oauth_result: dict | None = None

    def add(config: ProfileConfig) -> ProfileConfig:
        if any(
            item.project_id == mapping.project_id for item in config.project_mappings
        ):
            raise RuntimeError(f"Project {mapping.project_id} is already mapped")
        if any(
            item.local_path == mapping.local_path for item in config.project_mappings
        ):
            raise RuntimeError(f"Repository {mapping.local_path} is already mapped")
        return config.model_copy(
            update={"project_mappings": [*config.project_mappings, mapping]}
        )

    proposed = add(manager.config())

    def authorize_change() -> None:
        nonlocal oauth_result
        if manager.store.credential() is not None:
            oauth_result = asyncio.run(
                oauth_login(
                    paths=paths,
                    config=proposed,
                    mode="login",
                    intent="workspace_add",
                )
            )

    manager.mutate(
        add,
        environment_keys=WORKSPACE_ENV_KEYS,
        state_change=authorize_change,
    )
    if oauth_result is not None:
        _print_registration(oauth_result["installation"])
        _warn_environment_pat_shadow()
    else:
        _sync_registration(paths)
        print(
            "If this workspace is not already granted to the PAT, add it in "
            "Tether Brain Connections."
        )
    return 0


def command_workspace_remove(args: argparse.Namespace, paths: ProfilePaths) -> int:
    manager = ProfileManager(paths)
    if (
        manager.store.credential() is None
        and manager.store.get_secret("pat") is None
        and "TETHER_AGENT_ACCESS_TOKEN" not in configured_environment_keys()
    ):
        raise RuntimeError("Authenticate this profile before changing workspaces")
    oauth_result: dict | None = None

    def remove(config: ProfileConfig) -> ProfileConfig:
        retained = [
            item
            for item in config.project_mappings
            if item.project_id != args.project_id
        ]
        if len(retained) == len(config.project_mappings):
            raise RuntimeError(f"Project {args.project_id} is not mapped")
        return config.model_copy(update={"project_mappings": retained})

    proposed = remove(manager.config())

    def authorize_change() -> None:
        nonlocal oauth_result
        if manager.store.credential() is not None:
            oauth_result = asyncio.run(
                oauth_login(
                    paths=paths,
                    config=proposed,
                    mode="login",
                    intent="workspace_remove",
                )
            )

    manager.mutate(
        remove,
        environment_keys=WORKSPACE_ENV_KEYS,
        state_change=authorize_change,
    )
    if oauth_result is not None:
        _print_registration(oauth_result["installation"])
        _warn_environment_pat_shadow()
    else:
        _sync_registration(paths)
    return 0


def command_workspace_list(args: argparse.Namespace, paths: ProfilePaths) -> int:
    del args
    environment_keys = configured_environment_keys()
    if "TETHER_AGENT_PROJECT_MAPPINGS" in environment_keys:
        mappings = DaemonSettings().project_mappings
        print("Workspace mappings are supplied by the environment.")
    elif paths.config_file.exists():
        mappings = ProfileManager(paths).config().project_mappings
    else:
        raise RuntimeError(
            f"Profile '{paths.profile}' is not initialized. Run init or migrate env."
        )
    if not mappings:
        print("No workspace mappings are configured.")
        return 0
    for mapping in mappings:
        print(f"{mapping.project_id}\t{mapping.access}\t{mapping.local_path}")
        print(f"  remote: {mapping.remote_url or 'none'}")
    return 0


def command_auth_set_pat(args: argparse.Namespace, paths: ProfilePaths) -> int:
    del args
    manager = ProfileManager(paths)
    config = manager.config()
    oauth_credential = manager.store.credential()
    previously_oauth = (
        oauth_credential is not None
        or manager.store.get_setting("last_credential_type") == "oauth_installation"
    )
    if previously_oauth:
        confirmation = input(
            "Switch this installation from OAuth to PAT fallback? Type 'switch-to-pat': "
        ).strip()
        if confirmation != "switch-to-pat":
            raise RuntimeError("PAT fallback switch was cancelled")
    pat = getpass.getpass("Tether Brain PAT: ")
    identity = asyncio.run(_validate_pat(config.server_url, pat))
    credential_id = str(identity["credential"]["id"])
    existing_credential_id = manager.store.get_setting("credential_id")
    if (
        oauth_credential is None
        and existing_credential_id
        and existing_credential_id != credential_id
    ):
        raise RuntimeError(
            "This installation is bound to a different PAT identity. Phase 1 cannot "
            "rebind installations. Restore the original PAT or create a new profile."
        )

    def store_pat() -> None:
        if previously_oauth:
            installation_id = manager.store.get_setting("installation_id")
            if installation_id is None:
                raise RuntimeError("Installation identity is missing")
            response = httpx.post(
                f"{config.server_url}/api/agent/v1/credentials/use-pat",
                headers={"Authorization": f"Bearer {pat}"},
                json={"installation_id": installation_id},
                timeout=30,
            )
            response.raise_for_status()
            manager.store.delete_credentials()
        manager.store.set_secret("pat", pat)
        manager.store.set_setting("credential_id", credential_id)
        manager.store.set_setting("authentication_required", "false")
        manager.store.set_setting("credential_revoked", "false")
        manager.store.set_setting("installation_revoked", "false")
        manager.store.delete_setting("credential_failure_code")
        manager.store.set_setting("last_credential_type", "pat")

    manager.mutate(
        lambda current: current,
        environment_keys=AUTH_ENV_KEYS,
        state_change=store_pat,
    )
    _sync_registration(paths)
    print("PAT updated without exposing its value.")
    return 0


def _warn_environment_pat_shadow() -> bool:
    if "TETHER_AGENT_ACCESS_TOKEN" not in configured_environment_keys():
        return False
    print("Warning: TETHER_AGENT_ACCESS_TOKEN still shadows stored OAuth credentials.")
    print(
        "Run 'unset TETHER_AGENT_ACCESS_TOKEN' and remove it from the environment source that sets it."
    )
    return True


def _oauth_mutation_environment_keys() -> frozenset[str]:
    return AUTH_ENV_KEYS - {"TETHER_AGENT_ACCESS_TOKEN"}


def command_auth_login(args: argparse.Namespace, paths: ProfilePaths) -> int:
    del args
    manager = ProfileManager(paths)
    config = manager.config()
    state = _reconcile_oauth_credential(paths=paths, config=config)
    if state == "offline":
        raise RuntimeError(
            "Tether Brain could not be reached. The local profile was preserved; "
            "retry when the server is available."
        )
    if state == "revoked":
        return _replace_revoked_profile(
            manager=manager,
            paths=paths,
            config=config,
        )
    result: dict = {}

    def login() -> None:
        nonlocal result
        result = asyncio.run(
            oauth_login(
                paths=paths,
                config=config,
                mode="login",
                intent="reauthorize",
            )
        )
        manager.store.delete_secret("pat")

    manager.mutate(
        lambda current: current,
        environment_keys=_oauth_mutation_environment_keys(),
        state_change=login,
    )
    shadowed = _warn_environment_pat_shadow()
    _print_registration(result["installation"])
    if shadowed:
        print(
            "OAuth login is stored but is not yet the effective authentication method."
        )
        return 1
    print("OAuth installation authentication is active.")
    return 0


def command_auth_migrate(args: argparse.Namespace, paths: ProfilePaths) -> int:
    del args
    manager = ProfileManager(paths)
    if manager.store.credential() is not None:
        print(
            "Installation already has OAuth installation credentials. No changes made."
        )
        if _warn_environment_pat_shadow():
            print(
                "Migration is not complete until the environment PAT override is removed."
            )
            return 1
        return 0
    if (
        manager.store.get_secret("pat") is None
        and "TETHER_AGENT_ACCESS_TOKEN" not in configured_environment_keys()
    ):
        raise RuntimeError("This profile has no PAT installation to migrate")
    if manager.store.get_setting("installation_id") is None:
        raise RuntimeError("Register the PAT installation before migrating it")
    config = manager.config()
    result: dict = {}

    def migrate() -> None:
        nonlocal result
        result = asyncio.run(
            oauth_login(
                paths=paths,
                config=config,
                mode="migrate",
                intent="migrate",
            )
        )
        manager.store.delete_secret("pat")

    manager.mutate(
        lambda current: current,
        environment_keys=_oauth_mutation_environment_keys(),
        state_change=migrate,
    )
    shadowed = _warn_environment_pat_shadow()
    _print_registration(result["installation"])
    if shadowed:
        print(
            "Migration is not complete until the environment PAT override is removed."
        )
        return 1
    print(
        "PAT installation migrated to OAuth without changing its installation identity."
    )
    return 0


def command_auth_refresh(args: argparse.Namespace, paths: ProfilePaths) -> int:
    del args
    manager = ProfileManager(paths)
    config = manager.config()
    refreshed = None

    def refresh() -> None:
        nonlocal refreshed
        refreshed = asyncio.run(
            refresh_credential(paths=paths, server_url=config.server_url, force=True)
        )

    manager.mutate(
        lambda current: current,
        environment_keys=_oauth_mutation_environment_keys(),
        state_change=refresh,
    )
    assert refreshed is not None
    print(f"OAuth credential refreshed to generation {refreshed.generation}.")
    _warn_environment_pat_shadow()
    return 0


def command_auth_revoke(args: argparse.Namespace, paths: ProfilePaths) -> int:
    if ProfileLock.is_locked(paths.daemon_lock):
        raise RuntimeError("Stop the daemon before revoking installation credentials")
    manager = ProfileManager(paths)
    credential = manager.store.credential()
    if credential is None:
        if manager.store.get_setting("installation_revoked") == "true":
            print("Installation access is already revoked.")
        else:
            print("No OAuth installation credential is configured.")
        if args.purge:
            return command_profile_remove(
                argparse.Namespace(local_only=True, yes=True), paths
            )
        return 0

    def revoke() -> None:
        _revoke_profile_credential(manager=manager, paths=paths)
        manager.store.delete_credentials()
        manager.store.set_setting("authentication_required", "true")
        manager.store.set_setting("credential_revoked", "true")
        manager.store.set_setting("installation_revoked", "true")

    manager.mutate(
        lambda current: current,
        environment_keys=_oauth_mutation_environment_keys(),
        state_change=revoke,
    )
    print("Installation credentials were revoked server-side and removed locally.")
    _warn_environment_pat_shadow()
    if args.purge:
        return command_profile_remove(
            argparse.Namespace(local_only=True, yes=True), paths
        )
    return 0


def command_auth_status(args: argparse.Namespace, paths: ProfilePaths) -> int:
    environment_pat = "TETHER_AGENT_ACCESS_TOKEN" in configured_environment_keys()
    if not paths.config_file.exists():
        if environment_pat:
            print("Authentication: PAT configured by environment")
            print("Credential identity: stored in the legacy installation state")
            return 0
        print(f"Profile '{paths.profile}' is not initialized.")
        return 1
    manager = ProfileManager(paths)
    credential = manager.store.credential()
    remote_state = "local only" if args.offline else "not checked"
    if credential is not None and not environment_pat and not args.offline:
        try:
            remote_state = _reconcile_oauth_credential(
                paths=paths,
                config=manager.config(),
            )
        except httpx.HTTPError:
            remote_state = "unavailable"
        credential = manager.store.credential()
    configured = (
        environment_pat
        or credential is not None
        or manager.store.get_secret("pat") is not None
    )
    status = (
        "PAT configured by environment"
        if environment_pat
        else "OAuth installation credential"
        if credential is not None
        else "PAT configured"
        if configured
        else "logged out"
    )
    print(f"Authentication: {status}")
    if credential is not None:
        now = datetime.now(UTC)
        validity = (
            "revoked"
            if manager.store.get_setting("installation_revoked") == "true"
            else "reauthentication required"
            if credential.reauthentication_required
            else "access token expired; refresh available"
            if credential.access_expires_at <= now
            else "valid"
        )
        print(f"Credential validity: {validity}")
        print(f"Access token expiration: {credential.access_expires_at.isoformat()}")
        print(
            f"Refresh status: {'recovery pending' if credential.recovery_rotation_id else 'ready'}"
        )
        print(f"Credential generation: {credential.generation}")
        print(f"Credential family: {credential.family_id}")
        revocation = (
            "revoked"
            if manager.store.get_setting("installation_revoked") == "true"
            else "not revoked"
            if remote_state == "valid"
            else "not reported"
        )
        print(f"Installation revocation: {revocation}")
        print(f"Remote credential status: {remote_state}")
        print(
            "Credential activation pending: "
            + (
                "yes"
                if manager.store.get_setting("credential_activation_pending") == "true"
                else "no"
            )
        )
        print(
            f"Reauthentication required: {'yes' if credential.reauthentication_required else 'no'}"
        )
        print(
            "Credential terminal reason: "
            + (manager.store.get_setting("credential_failure_code") or "none")
        )
    else:
        print(
            f"Credential identity: {manager.store.get_setting('credential_id') or 'unknown'}"
        )
        print(
            "Installation revocation: "
            + (
                "revoked"
                if manager.store.get_setting("credential_revoked") == "true"
                else "not reported"
            )
        )
        print(
            "Reauthentication required: "
            + (
                "yes"
                if manager.store.get_setting("authentication_required") == "true"
                else "no"
            )
        )
    print(f"Incomplete setup session: {_setup_session_status(manager.store)}")
    if environment_pat and credential is not None:
        print("Stored OAuth credential shadowed by environment PAT: yes")
        _warn_environment_pat_shadow()
    return 0 if configured else 1


def command_auth_logout(args: argparse.Namespace, paths: ProfilePaths) -> int:
    del args
    manager = ProfileManager(paths)
    if manager.store.get_secret("pat") is None and manager.store.credential() is None:
        print("Profile is already logged out.")
        return 0
    manager.mutate(
        lambda current: current,
        environment_keys=AUTH_ENV_KEYS,
        state_change=lambda: (
            manager.store.delete_secret("pat"),
            manager.store.delete_credentials(),
            manager.store.clear_setup_session(),
        ),
    )
    manager.store.set_setting("authentication_required", "true")
    print(
        "Local credentials removed. Installation and Agent Profile identities were preserved."
    )
    _warn_environment_pat_shadow()
    return 0


def _revoke_profile_credential(*, manager: ProfileManager, paths: ProfilePaths) -> bool:
    credential = manager.store.credential()
    if credential is None:
        return manager.store.get_setting("installation_revoked") == "true"
    try:
        refreshed = asyncio.run(
            refresh_credential(
                paths=paths,
                server_url=manager.config().server_url,
                force=True,
            )
        )
    except InstallationRevokedError:
        return True
    except CredentialRefreshRejected as error:
        raise RuntimeError(
            "The server installation could not be revoked with the stored "
            "credential. Revoke it in Tether Brain Connections, or rerun with "
            "--local-only if local removal is intentional."
        ) from error
    response = httpx.post(
        f"{manager.config().server_url}/api/agent/v1/credentials/revoke",
        headers={"Authorization": f"Bearer {refreshed.access_token}"},
        timeout=30,
    )
    if response.status_code in {401, 403}:
        try:
            asyncio.run(
                refresh_credential(
                    paths=paths,
                    server_url=manager.config().server_url,
                    force=True,
                )
            )
        except InstallationRevokedError:
            return True
    response.raise_for_status()
    return True


def _remove_profile_directory(path: Path, *, profile: str) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.name != profile or path.parent.name != "profiles":
        raise RuntimeError(f"Refusing unsafe profile removal target: {path}")
    if path.is_symlink():
        raise RuntimeError(f"Refusing to remove symlinked profile directory: {path}")
    metadata = path.stat()
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise RuntimeError(
            f"Profile directory is not owned by the current user: {path}"
        )
    shutil.rmtree(path)


def command_profile_list(args: argparse.Namespace, paths: ProfilePaths) -> int:
    del args
    roots = {paths.config_dir.parent, paths.state_dir.parent}
    names: set[str] = set()
    for root in roots:
        if not root.exists() or root.is_symlink():
            continue
        names.update(
            child.name
            for child in root.iterdir()
            if child.is_dir() and not child.is_symlink()
        )
    if not names:
        print("No local profiles are configured.")
        return 0
    for name in sorted(names):
        marker = " (default)" if name == DEFAULT_PROFILE else ""
        print(f"{name}{marker}")
    return 0


def command_profile_remove(args: argparse.Namespace, paths: ProfilePaths) -> int:
    if not paths.config_dir.exists() and not paths.state_dir.exists():
        print(f"Local profile '{paths.profile}' does not exist. No changes made.")
        return 0
    assert_mutation_not_shadowed(relevant_keys=CONFIGURATION_ENV_KEYS)
    store = StateStore(paths.state_file) if paths.state_file.exists() else None
    if store is not None and store.active_run_id() is not None:
        raise RuntimeError(
            "An execution is active. Wait for it to finish before removing this "
            "local profile."
        )
    warning = (
        " Server credentials will not be revoked."
        if args.local_only
        else " Server credentials will be revoked when still active."
    )
    if not args.yes:
        confirmation = input(
            f"Remove local profile '{paths.profile}' and its stored credentials?"
            f"{warning} Type the profile name to continue: "
        ).strip()
        if confirmation != paths.profile:
            print("Profile removal cancelled. No local state was changed.")
            return 1
    service = ServiceManager(paths)
    if service.is_installed():
        service.uninstall()
    if ProfileLock.is_locked(paths.daemon_lock):
        raise RuntimeError(
            "The foreground daemon is still running. Stop it before removing this "
            "local profile."
        )
    if not args.local_only and paths.config_file.exists() and store is not None:
        manager = ProfileManager(paths)
        _revoke_profile_credential(manager=manager, paths=paths)
    unique_directories = {paths.config_dir, paths.state_dir}
    for directory in unique_directories:
        _remove_profile_directory(directory, profile=paths.profile)
    print(f"Local profile '{paths.profile}' was removed.")
    if args.local_only:
        print(
            "Only local files were removed. Revoke the installation in Tether Brain "
            "Connections if it is still active."
        )
    return 0


def command_service(args: argparse.Namespace, paths: ProfilePaths) -> int:
    action = args.service_command.replace("-", "_")
    if action in {"install", "start", "restart"}:
        if not paths.config_file.exists():
            raise RuntimeError(
                "Initialize or migrate this profile before managing its service"
            )
        load_effective_settings(paths)
    manager = ServiceManager(paths)
    result = getattr(manager, action)()
    return int(result or 0)


def command_codex_skill(args: argparse.Namespace, paths: ProfilePaths) -> int:
    del paths
    if args.skill_command == "install":
        destination = install_skill()
        print(f"Tether Brain Codex skill installed at {destination}.")
        print(
            "Codex detects skill changes automatically. Start a new session if it is not listed yet."
        )
        return 0
    if args.skill_command == "uninstall":
        destination = uninstall_skill()
        print(f"Tether Brain Codex skill removed from {destination}.")
        return 0
    status_value, destination = skill_status()
    print(f"Tether Brain Codex skill: {status_value}")
    print(f"Location: {destination}")
    return 0 if status_value == "installed" else 1


def _add_repository_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--project-id", type=UUID)
    parser.add_argument("--setup-reference")
    parser.add_argument("--remote")
    parser.add_argument("--allow-no-remote", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tb-agent")
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    commands = parser.add_subparsers(dest="command")

    init = commands.add_parser("init")
    init.add_argument("--server")
    init.add_argument("--path", type=Path)
    init.add_argument("--project-id", type=UUID)
    init.add_argument("--remote")
    init.add_argument("--allow-no-remote", action="store_true")
    init.add_argument("--name")
    init.add_argument("--auth", choices=("oauth", "pat"), default="oauth")
    init.add_argument(
        "--yes",
        action="store_true",
        help="Confirm replacement of a revoked local installation",
    )
    init.set_defaults(handler=command_init)

    run = commands.add_parser("run")
    run.set_defaults(handler=command_run)
    status = commands.add_parser("status")
    status.add_argument("--offline", action="store_true")
    status.set_defaults(handler=command_status)

    concurrency = commands.add_parser("concurrency")
    concurrency_commands = concurrency.add_subparsers(
        dest="concurrency_command", required=True
    )
    concurrency_status = concurrency_commands.add_parser("status")
    concurrency_status.set_defaults(handler=command_concurrency_status)
    concurrency_set = concurrency_commands.add_parser("set")
    concurrency_set.add_argument("capacity", type=int, choices=range(1, 5))
    concurrency_set.set_defaults(handler=command_concurrency_set)

    changes = commands.add_parser("changes")
    changes_commands = changes.add_subparsers(dest="changes_command", required=True)
    changes_list = changes_commands.add_parser("list")
    changes_list.set_defaults(handler=command_changes_list)
    changes_status = changes_commands.add_parser("status")
    changes_status.add_argument("run_id", type=UUID)
    changes_status.set_defaults(handler=command_changes_status)
    changes_diff = changes_commands.add_parser("diff")
    changes_diff.add_argument("run_id", type=UUID)
    changes_diff.set_defaults(handler=command_changes_diff)
    changes_test = changes_commands.add_parser("test")
    changes_test.add_argument("run_id", type=UUID)
    changes_test.add_argument("test_command", nargs=argparse.REMAINDER)
    changes_test.set_defaults(handler=command_changes_test)
    changes_apply = changes_commands.add_parser("apply")
    changes_apply.add_argument("run_id", type=UUID)
    changes_apply.set_defaults(handler=command_changes_apply)

    migrate = commands.add_parser("migrate")
    migrate_commands = migrate.add_subparsers(dest="migrate_command", required=True)
    migrate_env = migrate_commands.add_parser("env")
    migrate_env.add_argument("--dry-run", action="store_true")

    workspace = commands.add_parser("workspace")
    workspace_commands = workspace.add_subparsers(
        dest="workspace_command",
        required=True,
    )
    workspace_add = workspace_commands.add_parser("add")
    _add_repository_arguments(workspace_add)
    workspace_add.add_argument("--access", choices=("read", "write"), default="write")
    workspace_add.set_defaults(handler=command_workspace_add)
    workspace_list = workspace_commands.add_parser("list")
    workspace_list.set_defaults(handler=command_workspace_list)
    workspace_remove = workspace_commands.add_parser("remove")
    workspace_remove.add_argument("project_id", type=UUID)
    workspace_remove.set_defaults(handler=command_workspace_remove)

    profile = commands.add_parser("profile")
    profile_commands = profile.add_subparsers(dest="profile_command", required=True)
    profile_list = profile_commands.add_parser("list")
    profile_list.set_defaults(handler=command_profile_list)
    profile_remove = profile_commands.add_parser("remove")
    profile_remove.add_argument("--local-only", action="store_true")
    profile_remove.add_argument("--yes", action="store_true")
    profile_remove.set_defaults(handler=command_profile_remove)

    auth = commands.add_parser("auth")
    auth_commands = auth.add_subparsers(dest="auth_command", required=True)
    auth_set_pat = auth_commands.add_parser("set-pat")
    auth_set_pat.set_defaults(handler=command_auth_set_pat)
    auth_status = auth_commands.add_parser("status")
    auth_status.add_argument("--offline", action="store_true")
    auth_status.set_defaults(handler=command_auth_status)
    auth_logout = auth_commands.add_parser("logout")
    auth_logout.set_defaults(handler=command_auth_logout)
    auth_login = auth_commands.add_parser("login")
    auth_login.set_defaults(handler=command_auth_login)
    auth_migrate = auth_commands.add_parser("migrate")
    auth_migrate.set_defaults(handler=command_auth_migrate)
    auth_refresh = auth_commands.add_parser("refresh")
    auth_refresh.set_defaults(handler=command_auth_refresh)
    auth_revoke = auth_commands.add_parser("revoke")
    auth_revoke.add_argument("--purge", action="store_true")
    auth_revoke.set_defaults(handler=command_auth_revoke)

    service = commands.add_parser("service")
    service_commands = service.add_subparsers(dest="service_command", required=True)
    for action in (
        "install",
        "uninstall",
        "start",
        "stop",
        "restart",
        "status",
        "logs",
    ):
        item = service_commands.add_parser(action)
        item.set_defaults(handler=command_service)

    codex = commands.add_parser("codex")
    codex_commands = codex.add_subparsers(dest="codex_command", required=True)
    codex_skill = codex_commands.add_parser("skill")
    codex_skill_commands = codex_skill.add_subparsers(
        dest="skill_command", required=True
    )
    for action in ("install", "status", "uninstall"):
        item = codex_skill_commands.add_parser(action)
        item.set_defaults(handler=command_codex_skill)
    return parser


def run_cli(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        args = parser.parse_args(["--profile", args.profile, "run"])
    paths = ProfilePaths.resolve(args.profile)
    if args.command == "migrate":
        from tether_agent.migration import migrate_environment

        return migrate_environment(paths, dry_run=args.dry_run)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.error("a command is required")
    return int(handler(args, paths))


def safe_error_message(error: BaseException) -> str:
    return TOKEN_PATTERN.sub("[REDACTED CREDENTIAL]", str(error))


def main() -> None:
    try:
        raise SystemExit(run_cli())
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except (httpx.HTTPError, OSError, RuntimeError, ValueError) as error:
        print(f"Error: {safe_error_message(error)}", file=sys.stderr)
        raise SystemExit(1) from None
