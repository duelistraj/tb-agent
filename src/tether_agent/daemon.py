"""Polling daemon that claims and runs one leased task at a time."""

from __future__ import annotations

import asyncio
import copy
import logging
import re
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
from tether_agent.api import AgentApiError, TetherApi
from tether_agent.changes import refresh_snapshot_state
from tether_agent.config import DaemonSettings, load_effective_settings
from tether_agent.handoff import apply_accepted_snapshot
from tether_agent.locking import LockUnavailable, ProfileLock
from tether_agent.oauth import refresh_credential
from tether_agent.paths import ProfilePaths
from tether_agent.ports import PortAllocator, RunNamespace
from tether_agent.runtime import RuntimeRegistry
from tether_agent.snapshots import create_snapshot, head_commit
from tether_agent.state import StateStore
from tether_agent.worktrees import WorktreeManager

logger = logging.getLogger(__name__)
CONTROL_PLANE_INTERVAL_SECONDS = 25
ACKNOWLEDGED_RESULT_STATES = frozenset(
    {"completion_pending", "review", "completed", "failed", "cancelled"}
)
FILE_URI_PATTERN = re.compile(r"\bfile://[^\s,;)}\]]+")
ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?<![\w:/])(?:~[/\\]|/|[A-Za-z]:[/\\])[^\s,;)}\]]+"
)


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
        self.ports = PortAllocator(self.store)
        self.installation_id: UUID | None = settings.installation_id
        self.approved_manifest_digest: str | None = None
        self._last_catalog_refresh = 0.0
        self._loaded_revision = settings.config_revision
        self._mark_legacy_dirty_worktrees()

    def _mark_legacy_dirty_worktrees(self) -> None:
        for row in self.store.worktree_rows():
            run_id = UUID(str(row["run_id"]))
            if self.store.change_set(run_id) is not None:
                continue
            path = Path(str(row["path"]))
            repository = Path(str(row["repository_path"]))
            if not path.exists() or not repository.exists():
                continue
            try:
                dirty = self.worktrees.is_dirty(path)
                base_commit = head_commit(path)
            except (OSError, subprocess.SubprocessError):
                continue
            if dirty:
                self.store.begin_change_set(
                    run_id=run_id,
                    repository_path=repository,
                    worktree_path=path,
                    base_commit=base_commit,
                    legacy=True,
                )

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

    def _reload_live_capacity_if_changed(self) -> bool:
        if self.paths is None:
            return False
        revision = self.store.configuration_revision()
        if revision <= self._loaded_revision:
            return False
        next_settings = load_effective_settings(self.paths, self.store)
        current = self.settings.model_dump(
            exclude={"max_concurrent_runs", "config_revision"}
        )
        proposed = next_settings.model_dump(
            exclude={"max_concurrent_runs", "config_revision"}
        )
        if current != proposed:
            return False
        self.settings = self.settings.model_copy(
            update={
                "max_concurrent_runs": next_settings.max_concurrent_runs,
                "config_revision": next_settings.config_revision,
            }
        )
        self._loaded_revision = revision
        self.store.set_daemon_status("capacity_reloaded")
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
                item = FILE_URI_PATTERN.sub("[local-path]", item)
                return ABSOLUTE_PATH_PATTERN.sub("[local-path]", item)
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
                "configuration_revision": self.store.configuration_revision(),
                "configured_capacity": self.settings.max_concurrent_runs,
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
            except AgentApiError as exc:
                if not exc.recoverable:
                    self.store.set_daemon_status("registration_blocked")
                    raise RuntimeError(exc.user_message) from exc
                logger.warning("Agent registration failed and will be retried: %s", exc)
                self.store.set_daemon_status("registration_error")
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
        stop_control_plane = asyncio.Event()
        control_plane = asyncio.create_task(
            self._control_plane_loop(stop_control_plane)
        )
        try:
            active_tasks: dict[UUID, asyncio.Task[None]] = {}
            slot_by_run: dict[UUID, int] = {}
            recovery_attempted = False
            while True:
                try:
                    self._reload_live_capacity_if_changed()
                    finished_run_ids = [
                        run_id for run_id, task in active_tasks.items() if task.done()
                    ]
                    for run_id in finished_run_ids:
                        task = active_tasks.pop(run_id)
                        slot_by_run.pop(run_id, None)
                        try:
                            task.result()
                        except (
                            CodexError,
                            httpx.HTTPError,
                            OSError,
                            RuntimeError,
                            subprocess.SubprocessError,
                            ValueError,
                        ) as exc:
                            logger.warning("Execution %s failed: %s", run_id, exc)
                    if not active_tasks:
                        await self._reload_if_changed()
                    if self.store.maintenance_requested():
                        if active_tasks or not await self._reconcile_idle_active_runs():
                            self.store.set_daemon_status(
                                "maintenance_waiting_for_run_recovery"
                            )
                            await asyncio.sleep(self.settings.poll_seconds)
                            continue
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
                    if not recovery_attempted:
                        await self._recover_workers(active_tasks, slot_by_run)
                        recovery_attempted = True
                    await self._reconcile_change_set_integrity()
                    await self._reconcile_handoffs()
                    await self._reconcile_terminal_resources()
                    used_slots = set(slot_by_run.values())
                    available_slots = [
                        slot
                        for slot in range(self.settings.max_concurrent_runs)
                        if slot not in used_slots
                    ]
                    claimed_any = False
                    for worker_slot in available_slots:
                        claim = await self.api.claim(
                            self.installation_id,
                            worker_slot=worker_slot,
                            configured_capacity=self.settings.max_concurrent_runs,
                        )
                        if claim is None:
                            break
                        run_id = UUID(str(claim["run"]["id"]))
                        namespace = self.ports.allocate(
                            run_id=run_id,
                            worker_slot=worker_slot,
                        )
                        slot_by_run[run_id] = worker_slot
                        active_tasks[run_id] = asyncio.create_task(
                            self._execute(
                                claim,
                                worker_slot=worker_slot,
                                namespace=namespace,
                            )
                        )
                        claimed_any = True
                    if not active_tasks and not claimed_any:
                        await self.api.liveness(
                            {
                                "installation_id": str(self.installation_id),
                                "protocol_version": self.settings.protocol_version,
                                "daemon_version": __version__,
                                "configured_capacity": self.settings.max_concurrent_runs,
                                "active_run_count": 0,
                            }
                        )
                        await self._refresh_catalogs()
                        await self._reconcile_pending_results()
                        await self._reconcile_idle_active_runs()
                        await self._cleanup_worktrees()
                    elif active_tasks:
                        self.store.set_daemon_status(
                            f"running:{len(active_tasks)}/{self.settings.max_concurrent_runs}"
                        )
                except AgentApiError as exc:
                    if not exc.recoverable:
                        self.store.set_daemon_status("registration_blocked")
                        logger.error(
                            "Daemon registration is blocked: %s",
                            exc.user_message,
                        )
                        raise
                    self.store.set_daemon_status("operation_error")
                    logger.warning(
                        "Daemon operation failed and will be retried: %s",
                        exc,
                    )
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
            for task in locals().get("active_tasks", {}).values():
                task.cancel()
            for task in locals().get("active_tasks", {}).values():
                with suppress(asyncio.CancelledError):
                    await task
            stop_control_plane.set()
            control_plane.cancel()
            with suppress(asyncio.CancelledError):
                await control_plane
            self.store.set_daemon_status("stopped")
            await self.api.close()
            if daemon_lock is not None:
                daemon_lock.release()

    async def _execute(
        self,
        claim: dict[str, Any],
        *,
        worker_slot: int = 0,
        namespace: RunNamespace | None = None,
    ) -> None:
        run = claim["run"]
        run_id = UUID(run["id"])
        generation = int(run["lease_generation"])
        lease_token = str(claim["lease_token"])
        self.store.save_claim(run_id, generation, lease_token, worker_slot)
        stop_heartbeat = asyncio.Event()
        heartbeat = asyncio.create_task(
            self._heartbeat_loop(run_id, generation, lease_token, stop_heartbeat)
        )
        try:
            pending_result = self.store.pending_result(run_id)
            directory: Path | None = None
            local_context: dict[str, Any] | None = None
            if pending_result is None:
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
            progress_last_sent_at = 0.0
            progress_last_fingerprint: str | None = None

            async def progress(
                message: str,
                payload: dict[str, Any],
            ) -> None:
                nonlocal \
                    progress_last_fingerprint, \
                    progress_last_sent_at, \
                    progress_number
                fingerprint = repr(
                    (
                        message,
                        payload.get("semantic_key"),
                        payload.get("repository_paths"),
                    )
                )
                now = time.monotonic()
                if not payload.get("milestone", False) and (
                    fingerprint == progress_last_fingerprint
                    or now - progress_last_sent_at < 3
                ):
                    return
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
                progress_last_fingerprint = fingerprint
                progress_last_sent_at = now

            if pending_result is None:
                assert directory is not None and local_context is not None
                runtime_task = asyncio.create_task(
                    runtime.run(
                        run_id=run_id,
                        context=local_context,
                        working_directory=directory,
                        model_id=model_id,
                        reasoning_effort=reasoning_effort,
                        environment=(namespace.environment() if namespace else {}),
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
            else:
                result = pending_result
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
                self.ports.release(run_id)
                return
            if pending_result is None:
                self.store.save_pending_result(run_id, result)
            change_set = self.store.change_set(run_id)
            if change_set is not None:
                if change_set.state == "legacy_manual_review_required":
                    raise RuntimeError(
                        "Legacy dirty worktree requires manual review and cannot "
                        "be snapshotted automatically"
                    )
                if change_set.state == "executing":
                    change_set = self.store.transition_change_set(
                        run_id,
                        expected_states=frozenset({"executing"}),
                        next_state="snapshotting",
                    )
                if change_set.state == "snapshotting":
                    snapshot = create_snapshot(
                        repository=change_set.repository_path,
                        worktree=change_set.worktree_path,
                        run_id=run_id,
                        base_commit=change_set.base_commit,
                    )
                    change_set = self.store.transition_change_set(
                        run_id,
                        expected_states=frozenset({"snapshotting"}),
                        next_state="snapshot_ready",
                        values={
                            "snapshot_commit": snapshot.commit,
                            "snapshot_tree": snapshot.tree,
                        },
                    )
                if change_set.state == "snapshot_ready":
                    change_set = self.store.transition_change_set(
                        run_id,
                        expected_states=frozenset({"snapshot_ready"}),
                        next_state="review_ready",
                    )
                if (
                    change_set.state != "review_ready"
                    or change_set.snapshot_commit is None
                    or change_set.snapshot_tree is None
                ):
                    raise RuntimeError(
                        f"Change set is not ready for review: {change_set.state}"
                    )
                result["change_set"] = {
                    "snapshot_commit": change_set.snapshot_commit,
                    "snapshot_tree": change_set.snapshot_tree,
                    "base_commit": change_set.base_commit,
                    "validation_revision": change_set.validation_revision,
                    "validation_status": change_set.validation_status,
                    "change_set_revision": change_set.change_set_revision,
                }
            self.store.save_pending_result(run_id, result)
            completed = await self._complete_with_retry(
                run_id=run_id,
                generation=generation,
                lease_token=lease_token,
                task_version=int(run["task_version"]),
                result=result,
            )
            self.store.clear_pending_result(run_id)
            self.store.finish_run(run_id, completed["state"])
            self.store.set_worktree_state(run_id, completed["state"])
            if completed["state"] in {"completed", "failed", "cancelled"}:
                self.ports.release(run_id)
        finally:
            stop_heartbeat.set()
            heartbeat.cancel()
            with suppress(asyncio.CancelledError, httpx.HTTPError):
                await heartbeat

    async def _complete_with_retry(
        self,
        *,
        run_id: UUID,
        generation: int,
        lease_token: str,
        task_version: int,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        for attempt in range(3):
            try:
                return await self.api.complete(
                    run_id,
                    generation,
                    lease_token,
                    task_version,
                    self._remote_safe(result["message"]),
                    self._remote_safe(result["outputs"]),
                    self._remote_safe(result.get("completion_note")),
                    self._remote_safe(result.get("change_set")),
                )
            except AgentApiError as exc:
                if not exc.recoverable or attempt == 2:
                    raise
                await asyncio.sleep(2**attempt)
            except httpx.TransportError:
                if attempt == 2:
                    raise
                await asyncio.sleep(2**attempt)
        raise RuntimeError("Completion retry loop exited unexpectedly")

    async def _control_plane_loop(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await asyncio.wait_for(
                    stop.wait(), timeout=CONTROL_PLANE_INTERVAL_SECONDS
                )
                continue
            except TimeoutError:
                pass
            if (
                self.installation_id is None
                or self.approved_manifest_digest is None
                or self.store.maintenance_requested()
            ):
                continue
            try:
                await self.api.liveness(
                    {
                        "installation_id": str(self.installation_id),
                        "protocol_version": self.settings.protocol_version,
                        "daemon_version": __version__,
                        "configured_capacity": self.settings.max_concurrent_runs,
                        "active_run_count": len(self.store.active_run_ids()),
                    }
                )
                await self._refresh_catalogs()
            except (AgentApiError, httpx.HTTPError, OSError, RuntimeError) as exc:
                logger.warning("Daemon background heartbeat failed: %s", exc)

    async def _reconcile_handoffs(self) -> None:
        if self.installation_id is None:
            return
        for remote_run in await self.api.pending_handoffs(self.installation_id):
            run_id = UUID(str(remote_run["id"]))
            remote_change_set = remote_run.get("change_set")
            if not isinstance(remote_change_set, dict):
                continue
            binding = {
                "run_id": str(run_id),
                "snapshot_commit": remote_change_set["snapshot_commit"],
                "snapshot_tree": remote_change_set["snapshot_tree"],
                "validation_revision": remote_change_set["validation_revision"],
                "change_set_revision": remote_change_set["change_set_revision"],
            }
            local = self.store.change_set(run_id)
            if local is None:
                logger.error("Accepted run %s has no local change set", run_id)
                continue
            if remote_run["state"] == "awaiting_acknowledgement":
                reason = (remote_run.get("pending_completion") or {}).get("reason")
                if reason != "handoff_ack_pending":
                    continue
                if local.state == "accepted":
                    local = self.store.transition_change_set(
                        run_id,
                        expected_states=frozenset({"accepted"}),
                        next_state="applied",
                    )
                await self.api.acknowledge_handoff(run_id, binding)
                self.ports.release(run_id)
                continue
            if remote_run["state"] == "handoff_blocked":
                handoff = self.store.handoff(run_id)
                if handoff is None or handoff["state"] != "retry_requested":
                    continue
            if local.state == "review_ready":
                local = self.store.accept_change_set(
                    run_id=run_id,
                    snapshot_commit=str(binding["snapshot_commit"]),
                    snapshot_tree=str(binding["snapshot_tree"]),
                    validation_revision=int(binding["validation_revision"]),
                    change_set_revision=int(binding["change_set_revision"]),
                )
            if local.state != "accepted":
                logger.error(
                    "Accepted server handoff %s conflicts with local state %s",
                    run_id,
                    local.state,
                )
                continue
            try:
                if remote_run["state"] in {"accepted", "handoff_blocked"}:
                    await self.api.start_handoff(run_id, binding)
                result = apply_accepted_snapshot(
                    store=self.store,
                    change_set=local,
                    checkout=local.repository_path,
                )
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                await self.api.complete_handoff(
                    run_id,
                    {
                        **binding,
                        "status": "blocked",
                        "message": self._remote_safe(str(error)),
                    },
                )
                continue
            response = await self.api.complete_handoff(
                run_id,
                {
                    **binding,
                    "status": "applied",
                    "method": result.method,
                    "applied_commit": result.applied_commit,
                },
            )
            local = self.store.transition_change_set(
                run_id,
                expected_states=frozenset({"accepted"}),
                next_state="applied",
            )
            if (response.get("pending_completion") or {}).get("reason") == (
                "handoff_ack_pending"
            ):
                await self.api.acknowledge_handoff(run_id, binding)
                self.ports.release(run_id)

    async def _reconcile_change_set_integrity(self) -> None:
        for record in self.store.change_sets():
            updated = (
                refresh_snapshot_state(self.store, record)
                if record.state == "review_ready"
                else record
            )
            if (
                updated.state != "superseded"
                or updated.validation_status != "snapshot_invalidated"
            ):
                continue
            assert updated.snapshot_commit is not None
            assert updated.snapshot_tree is not None
            await self.api.supersede_change_set(
                updated.run_id,
                {
                    "run_id": str(updated.run_id),
                    "snapshot_commit": updated.snapshot_commit,
                    "snapshot_tree": updated.snapshot_tree,
                    "expected_change_set_revision": (updated.change_set_revision - 1),
                    "new_change_set_revision": updated.change_set_revision,
                    "reason": "snapshot_invalidated",
                },
            )
            self.ports.release(updated.run_id)

    async def _reconcile_terminal_resources(self) -> None:
        terminal_states = {
            "completed",
            "failed",
            "cancelled",
            "rejected",
            "superseded",
        }
        for reservation in self.store.active_port_reservations():
            remote = await self.api.run(reservation.run_id)
            remote_state = str(remote.get("state", ""))
            if remote_state not in terminal_states:
                continue
            change_set = self.store.change_set(reservation.run_id)
            if (
                remote_state in {"rejected", "superseded"}
                and change_set is not None
                and change_set.state == "review_ready"
            ):
                self.store.transition_change_set(
                    reservation.run_id,
                    expected_states=frozenset({"review_ready"}),
                    next_state=remote_state,
                )
            self.store.finish_run(reservation.run_id, remote_state)
            self.ports.release(reservation.run_id)

    async def _recover_workers(
        self,
        active_tasks: dict[UUID, asyncio.Task[None]],
        slot_by_run: dict[UUID, int],
    ) -> None:
        for row in self.store.leased_run_records():
            run_id = UUID(str(row["run_id"]))
            generation = int(row["lease_generation"])
            lease_token = str(row["lease_token"])
            worker_slot = int(row["worker_slot"] or 0)
            if worker_slot >= self.settings.max_concurrent_runs:
                continue
            remote = await self.api.run(run_id)
            expires_at = remote.get("lease_expires_at")
            lease_active = (
                remote.get("state") in {"claimed", "gathering_context", "running"}
                and int(remote.get("lease_generation", 0)) == generation
                and isinstance(expires_at, str)
                and datetime.fromisoformat(expires_at) > datetime.now().astimezone()
            )
            if not lease_active:
                self.store.finish_run(run_id, str(remote.get("state", "expired")))
                continue
            await self.api.heartbeat(run_id, generation, lease_token)
            namespace = self.ports.allocate(
                run_id=run_id,
                worker_slot=worker_slot,
            )
            active_tasks[run_id] = asyncio.create_task(
                self._execute(
                    {"run": remote, "lease_token": lease_token},
                    worker_slot=worker_slot,
                    namespace=namespace,
                )
            )
            slot_by_run[run_id] = worker_slot
            logger.info("Recovered execution %s in worker slot %d", run_id, worker_slot)

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
                    existing_change_set = self.store.change_set(run_id)
                    legacy = existing_change_set is None and self.worktrees.is_dirty(
                        directory
                    )
                    change_set = self.store.begin_change_set(
                        run_id=run_id,
                        repository_path=mapping.local_path,
                        worktree_path=directory,
                        base_commit=(
                            existing_change_set.base_commit
                            if existing_change_set is not None
                            else head_commit(directory)
                        ),
                        legacy=legacy,
                    )
                    if change_set.state == "legacy_manual_review_required":
                        raise RuntimeError(
                            "A dirty worktree from an older tb-agent version needs "
                            "manual review. Use 'tb-agent changes status "
                            f"{run_id}' to inspect it, then discard or rerun it."
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

    async def _reconcile_pending_results(self) -> None:
        for run_id in self.store.pending_result_run_ids():
            try:
                run = await self.api.run(run_id)
            except httpx.HTTPError as exc:
                logger.warning(
                    "Could not reconcile saved result for run %s: %s",
                    run_id,
                    exc,
                )
                continue
            state = str(run.get("state", ""))
            if state not in ACKNOWLEDGED_RESULT_STATES:
                continue
            self.store.clear_pending_result(run_id)
            self.store.finish_run(run_id, state)

    async def _reconcile_idle_active_runs(self) -> bool:
        """Clear claims left behind when no execution coroutine is running."""
        reconciled = True
        for run_id in self.store.active_run_ids():
            try:
                run = await self.api.run(run_id)
            except httpx.HTTPError as exc:
                logger.warning(
                    "Could not reconcile inactive local run %s: %s", run_id, exc
                )
                reconciled = False
                continue
            state = str(run.get("state", ""))
            pending_result = self.store.pending_result(run_id)
            if not state or (
                pending_result is not None and state not in ACKNOWLEDGED_RESULT_STATES
            ):
                reconciled = False
                continue
            if pending_result is not None:
                self.store.clear_pending_result(run_id)
            self.store.finish_run(run_id, state)
            logger.info(
                "Reconciled inactive local run %s with server state %s",
                run_id,
                state,
            )
        return reconciled

    async def _reconcile_idle_active_run(self) -> bool:
        """Compatibility wrapper for callers written before multi-run profiles."""
        return await self._reconcile_idle_active_runs()

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
