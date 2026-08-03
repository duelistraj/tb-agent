"""Polling daemon that claims and runs one leased task at a time."""

from __future__ import annotations

import asyncio
import copy
import logging
import subprocess
import time
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
from openai_codex import CodexError

from tether_agent import __version__
from tether_agent.api import TetherApi
from tether_agent.config import DaemonSettings, load_effective_settings
from tether_agent.locking import LockUnavailable, ProfileLock
from tether_agent.oauth import refresh_credential
from tether_agent.paths import ProfilePaths
from tether_agent.runtime import RuntimeRegistry
from tether_agent.state import StateStore
from tether_agent.worktrees import WorktreeManager

logger = logging.getLogger(__name__)


class AgentDaemon:
    def __init__(
        self,
        settings: DaemonSettings,
        *,
        paths: ProfilePaths | None = None,
    ) -> None:
        self.settings = settings
        self.paths = paths
        self.store = StateStore(settings.state_path)
        self.api = self._api(settings)
        self.runtimes = RuntimeRegistry(
            store=self.store,
            sandbox=settings.sandbox,
            settings=settings.runtime_adapters,
        )
        self.worktrees = WorktreeManager(settings.worktrees)
        self.installation_id: UUID | None = settings.installation_id
        self.approved_manifest_digest: str | None = None
        self._last_catalog_refresh = 0.0
        self._loaded_revision = settings.config_revision

    def _api(self, settings: DaemonSettings) -> TetherApi:
        async def installation_token(force: bool) -> str:
            assert self.paths is not None
            credential = await refresh_credential(
                paths=self.paths,
                server_url=settings.server_url,
                force=force,
            )
            return credential.access_token

        return TetherApi(
            settings.server_url,
            settings.access_token,
            oauth_client_id=settings.oauth_client_id,
            oauth_refresh_token=(
                self.store.get_setting("oauth_refresh_token")
                or settings.oauth_refresh_token
            ),
            save_refresh_token=lambda token: self.store.set_setting(
                "oauth_refresh_token", token
            ),
            installation_token_provider=(
                installation_token
                if settings.credential_type == "oauth_installation"
                and self.paths is not None
                else None
            ),
        )

    async def _reload_if_changed(self) -> bool:
        if self.paths is None:
            return False
        revision = self.store.configuration_revision()
        if revision <= self._loaded_revision:
            return False
        next_settings = load_effective_settings(self.paths, self.store)
        await self.api.close()
        self.settings = next_settings
        self.api = self._api(next_settings)
        self.runtimes = RuntimeRegistry(
            store=self.store,
            sandbox=next_settings.sandbox,
            settings=next_settings.runtime_adapters,
        )
        self.worktrees = WorktreeManager(next_settings.worktrees)
        self.installation_id = next_settings.installation_id
        self.approved_manifest_digest = None
        self._last_catalog_refresh = 0.0
        self._loaded_revision = revision
        self.store.set_daemon_status("reloading")
        return True

    def _capabilities(self) -> dict[str, Any]:
        return {
            "runtimes": self.runtimes.capabilities(),
            "sandbox": self.settings.sandbox,
            "shell": True,
            "git": True,
            "network": self.settings.allow_network,
            "writable_roots": [
                mapping.security_revision()
                for mapping in self.settings.project_mappings
                if mapping.access == "write"
            ],
            "projects": [
                {
                    "project_id": str(mapping.project_id),
                    "access": mapping.access,
                    "mapping_revision": mapping.security_revision(),
                }
                for mapping in self.settings.project_mappings
            ],
        }

    def _remote_safe(self, value: Any) -> Any:
        """Remove machine-local repository and worktree paths from remote payloads."""
        local_paths: set[str] = set()
        for mapping in self.settings.project_mappings:
            local_paths.add(str(mapping.local_path))
            worktree_root = (
                mapping.worktree_root or mapping.local_path.parent / ".tether-worktrees"
            )
            local_paths.add(str(worktree_root))
        for row in self.store.worktree_rows():
            local_paths.add(str(row["repository_path"]))
            local_paths.add(str(row["path"]))
        replacements = sorted(
            (path for path in local_paths if path),
            key=len,
            reverse=True,
        )

        def sanitize(item: Any) -> Any:
            if isinstance(item, str):
                for local_path in replacements:
                    item = item.replace(local_path, "[local-path]")
                return item
            if isinstance(item, dict):
                return {sanitize(key): sanitize(nested) for key, nested in item.items()}
            if isinstance(item, list):
                return [sanitize(nested) for nested in item]
            if isinstance(item, tuple):
                return tuple(sanitize(nested) for nested in item)
            return item

        return sanitize(value)

    async def register_once(self) -> dict[str, Any]:
        stored = self.store.get_setting("installation_id")
        installation_id = self.installation_id or (UUID(stored) if stored else None)
        response = await self.api.register(
            {
                "installation_id": str(installation_id) if installation_id else None,
                "name": self.settings.installation_name,
                "protocol_version": self.settings.protocol_version,
                "daemon_version": __version__,
                "capabilities": self._capabilities(),
            }
        )
        self.installation_id = UUID(response["id"])
        self.store.record_registration(response)
        if response["status"] == "active":
            approved_manifest = response.get("approved_manifest") or {}
            self.approved_manifest_digest = approved_manifest.get("digest")
            if self.approved_manifest_digest is None:
                raise RuntimeError(
                    "Active installation has no approved capability digest"
                )
            try:
                await self._refresh_catalogs(force=True)
            except BaseException:
                self.approved_manifest_digest = None
                raise
            self.store.set_daemon_status("ready")
        else:
            self.approved_manifest_digest = None
            self.store.set_daemon_status("pending_approval")
        return response

    async def register(self) -> None:
        while True:
            try:
                response = await self.register_once()
            except httpx.HTTPError as exc:
                logger.warning("Agent registration failed and will be retried: %s", exc)
                self.store.set_daemon_status("registration_error")
            else:
                if response["status"] == "active":
                    return
                logger.warning(
                    "Capability manifest is awaiting approval in Tether Brain"
                )
            await asyncio.sleep(self.settings.poll_seconds)

    async def run_forever(self) -> None:
        daemon_lock: ProfileLock | None = None
        if self.paths is not None:
            startup_lock = ProfileLock(
                self.paths.mutation_lock,
                label="daemon startup",
            )
            try:
                startup_lock.acquire()
            except LockUnavailable as error:
                raise RuntimeError(
                    f"Profile '{self.paths.profile}' is being changed by another command"
                ) from error
            daemon_lock = ProfileLock(self.paths.daemon_lock, label="daemon")
            try:
                daemon_lock.acquire()
            except LockUnavailable as error:
                raise RuntimeError(
                    f"A daemon is already running for profile '{self.paths.profile}'"
                ) from error
            finally:
                startup_lock.release()
        self.store.set_daemon_status("starting")
        try:
            while True:
                try:
                    await self._reload_if_changed()
                    if self.store.maintenance_requested():
                        self.store.acknowledge_maintenance(
                            self.store.maintenance_revision()
                        )
                        self.store.set_daemon_status("maintenance")
                        await asyncio.sleep(self.settings.poll_seconds)
                        continue
                    if self.approved_manifest_digest is None:
                        response = await self.register_once()
                        if response["status"] != "active":
                            await asyncio.sleep(self.settings.poll_seconds)
                            continue
                    assert self.installation_id is not None
                    claim = await self.api.claim(self.installation_id)
                    if claim is None:
                        await self.api.liveness(
                            {
                                "installation_id": str(self.installation_id),
                                "protocol_version": self.settings.protocol_version,
                                "daemon_version": __version__,
                            }
                        )
                        await self._refresh_catalogs()
                        await self._cleanup_worktrees()
                    else:
                        await self._execute(claim)
                except (
                    CodexError,
                    httpx.HTTPError,
                    OSError,
                    RuntimeError,
                    subprocess.SubprocessError,
                    ValueError,
                ) as exc:
                    credential = self.store.credential()
                    if credential is not None and credential.reauthentication_required:
                        self.store.set_daemon_status("reauthentication_required")
                    else:
                        self.store.set_daemon_status("operation_error")
                    logger.warning(
                        "Daemon operation failed and will be retried: %s",
                        exc,
                    )
                await asyncio.sleep(self.settings.poll_seconds)
        finally:
            self.store.set_daemon_status("stopped")
            await self.api.close()
            if daemon_lock is not None:
                daemon_lock.release()

    async def _execute(self, claim: dict[str, Any]) -> None:
        run = claim["run"]
        run_id = UUID(run["id"])
        generation = int(run["lease_generation"])
        lease_token = str(claim["lease_token"])
        self.store.save_claim(run_id, generation, lease_token)
        stop_heartbeat = asyncio.Event()
        heartbeat = asyncio.create_task(
            self._heartbeat_loop(run_id, generation, lease_token, stop_heartbeat)
        )
        try:
            try:
                context = await self.api.context(run_id, generation, lease_token)
            except httpx.HTTPStatusError as exc:
                detail = self._required_mapping_error(exc)
                if detail is None:
                    raise
                await self.api.comment(
                    run_id,
                    generation,
                    lease_token,
                    "blocker",
                    self._remote_safe(detail),
                )
                self.store.finish_run(run_id, "blocked")
                return
            try:
                directory, local_context = self._prepare_projects(
                    context=context,
                    run_id=run_id,
                )
            except RuntimeError as exc:
                await self.api.comment(
                    run_id,
                    generation,
                    lease_token,
                    "blocker",
                    self._remote_safe(str(exc)),
                )
                self.store.finish_run(run_id, "blocked")
                return
            runtime = self.runtimes.get(str(run["runtime_kind"]))
            model_value = run.get("model_id")
            if not isinstance(model_value, str) or not model_value:
                message = "Run has no immutable model selection."
                await self.api.state(
                    run_id,
                    generation,
                    lease_token,
                    "failed",
                    message,
                )
                self.store.finish_run(run_id, "failed")
                self.store.set_worktree_state(run_id, "failed")
                return
            model_id = model_value
            reasoning_effort = run.get("reasoning_effort")
            await self.api.state(
                run_id,
                generation,
                lease_token,
                "running",
                effective_model_id=model_id,
                effective_reasoning_effort=reasoning_effort,
            )
            progress_number = 0

            async def progress(
                message: str,
                payload: dict[str, Any],
            ) -> None:
                nonlocal progress_number
                progress_number += 1
                await self.api.timeline(
                    run_id,
                    generation,
                    lease_token,
                    (
                        f"{run_id}:{generation}:progress:"
                        f"{progress_number}:{payload.get('semantic_key', '')}"
                    ),
                    self._remote_safe(message),
                    self._remote_safe(payload),
                )

            runtime_task = asyncio.create_task(
                runtime.run(
                    run_id=run_id,
                    context=local_context,
                    working_directory=directory,
                    model_id=model_id,
                    reasoning_effort=reasoning_effort,
                    progress=progress,
                )
            )
            completed, _ = await asyncio.wait(
                {runtime_task, heartbeat},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if heartbeat in completed:
                runtime_task.cancel()
                with suppress(asyncio.CancelledError):
                    await runtime_task
                heartbeat_error = heartbeat.exception()
                if heartbeat_error is not None:
                    raise heartbeat_error
                raise RuntimeError("Run heartbeat stopped unexpectedly")
            result = await runtime_task
            if (
                result.get("effective_model_id") != model_id
                or result.get("effective_reasoning_effort") != reasoning_effort
            ):
                message = (
                    "Runtime reported a model or reasoning effort that does not "
                    "match the immutable run selection."
                )
                await self.api.state(
                    run_id,
                    generation,
                    lease_token,
                    "failed",
                    message,
                )
                self.store.finish_run(run_id, "failed")
                self.store.set_worktree_state(run_id, "failed")
                return
            if result["status"] in {"question", "blocked"}:
                await self.api.comment(
                    run_id,
                    generation,
                    lease_token,
                    result["status"],
                    self._remote_safe(result["message"]),
                )
                self.store.finish_run(run_id, result["status"])
                self.store.set_worktree_state(run_id, result["status"])
                return
            if result["status"] == "failed":
                await self.api.state(
                    run_id,
                    generation,
                    lease_token,
                    "failed",
                    self._remote_safe(result["message"]),
                )
                self.store.finish_run(run_id, "failed")
                self.store.set_worktree_state(run_id, "failed")
                return
            completed = await self.api.complete(
                run_id,
                generation,
                lease_token,
                int(run["task_version"]),
                self._remote_safe(result["message"]),
                self._remote_safe(result["outputs"]),
                self._remote_safe(result.get("completion_note")),
            )
            self.store.finish_run(run_id, completed["state"])
            self.store.set_worktree_state(run_id, completed["state"])
        finally:
            stop_heartbeat.set()
            heartbeat.cancel()
            with suppress(asyncio.CancelledError, httpx.HTTPError):
                await heartbeat

    def _prepare_projects(
        self,
        *,
        context: dict[str, Any],
        run_id: UUID,
    ) -> tuple[Path, dict[str, Any]]:
        local_context = copy.deepcopy(context)
        project_items = [
            item for item in local_context["items"] if item["kind"] == "project"
        ]
        primary_items = [
            item for item in project_items if item["payload"].get("is_primary")
        ]
        if len(primary_items) != 1:
            raise RuntimeError(
                "The run must contain exactly one primary logical project."
            )
        mappings = {
            mapping.project_id: mapping for mapping in self.settings.project_mappings
        }
        primary_directory: Path | None = None
        for item in project_items:
            project = item["payload"]
            project_id = UUID(project["id"])
            mapping = mappings.get(project_id)
            if mapping is None:
                if project["mapping_requirement"] == "required":
                    raise RuntimeError(
                        "A required logical project has no approved local "
                        f"mapping: {project['name']}."
                    )
                continue
            directory = self.worktrees.working_directory(
                mapping,
                run_id,
                project.get("ref"),
            )
            project["local_checkout"] = str(directory)
            if directory != mapping.local_path:
                self.store.record_worktree(
                    run_id=run_id,
                    project_id=mapping.project_id,
                    repository_path=mapping.local_path,
                    path=directory,
                )
            if project.get("is_primary"):
                primary_directory = directory
        if primary_directory is None:
            raise RuntimeError(
                "The primary logical project has no approved local mapping."
            )
        return primary_directory, local_context

    async def _refresh_catalogs(self, *, force: bool = False) -> None:
        if self.installation_id is None or self.approved_manifest_digest is None:
            return
        now = time.monotonic()
        if not force and now - self._last_catalog_refresh < 300:
            return
        for catalog in await self.runtimes.catalogs():
            await self.api.report_runtime_catalog(
                self.installation_id,
                {
                    **catalog,
                    "capability_manifest_digest": (self.approved_manifest_digest),
                },
            )
        self._last_catalog_refresh = now

    @staticmethod
    def _required_mapping_error(
        exc: httpx.HTTPStatusError,
    ) -> str | None:
        if exc.response.status_code != 409:
            return None
        try:
            detail = exc.response.json().get("detail")
        except ValueError:
            return None
        if not isinstance(detail, dict):
            return None
        if detail.get("code") != "required_project_mapping_missing":
            return None
        projects = ", ".join(str(item) for item in detail.get("projects", []))
        suffix = f": {projects}" if projects else ""
        return f"A required logical project has no approved local mapping{suffix}."

    async def _heartbeat_loop(
        self,
        run_id: UUID,
        generation: int,
        lease_token: str,
        stop: asyncio.Event,
    ) -> None:
        while not stop.is_set():
            await asyncio.sleep(25)
            await self.api.heartbeat(run_id, generation, lease_token)

    async def _cleanup_worktrees(self) -> None:
        for row in self.store.worktree_rows():
            run_id = UUID(row["run_id"])
            project_id = UUID(row["project_id"])
            path = Path(row["path"])
            if not path.exists():
                self.store.delete_worktree(run_id, project_id)
                continue
            try:
                run = await self.api.run(run_id)
            except httpx.HTTPError as exc:
                logger.warning(
                    "Could not inspect run %s during worktree cleanup: %s",
                    run_id,
                    exc,
                )
                continue
            if run["state"] not in {"review", "completed", "failed", "cancelled"}:
                continue
            accepted = run["acceptance_status"] == "accepted"
            superseded = run["acceptance_status"] in {
                "changes_requested",
                "superseded",
            }
            finished_at_value = run.get("finished_at")
            if not finished_at_value:
                continue
            decision = self.worktrees.cleanup_decision(
                path=path,
                state="completed" if superseded else run["state"],
                accepted=accepted or superseded,
                pinned=bool(row["pinned"]),
                finished_at=datetime.fromisoformat(finished_at_value),
            )
            if not decision.removable:
                continue
            if not row["repository_path"]:
                continue
            try:
                self.worktrees.remove(Path(row["repository_path"]), path)
            except (OSError, RuntimeError):
                continue
            self.store.delete_worktree(run_id, project_id)
        retained_bytes = sum(
            self._directory_size(Path(row["path"]))
            for row in self.store.worktree_rows()
            if Path(row["path"]).exists()
        )
        if retained_bytes > self.settings.worktrees.max_total_bytes:
            logger.warning(
                "Retained worktrees exceed the configured disk limit: %d > %d. "
                "Dirty, pinned, grace-period, and pending-review worktrees were kept.",
                retained_bytes,
                self.settings.worktrees.max_total_bytes,
            )

    @staticmethod
    def _directory_size(path: Path) -> int:
        total = 0
        for item in path.rglob("*"):
            try:
                if item.is_file() and not item.is_symlink():
                    total += item.stat().st_size
            except OSError:
                continue
        return total
