"""Polling daemon that claims and runs one leased task at a time."""

from __future__ import annotations

import asyncio
import copy
import logging
import re
import subprocess
import time
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
from openai_codex import CodexError

from tether_agent import __version__
from tether_agent.api import AgentApiError, TetherApi
from tether_agent.branches import prepare_run_branch
from tether_agent.changes import refresh_snapshot_state
from tether_agent.config import DaemonSettings, ProjectMapping, load_effective_settings
from tether_agent.handoff import apply_accepted_snapshot
from tether_agent.locking import LockUnavailable, ProfileLock
from tether_agent.oauth import refresh_credential
from tether_agent.paths import ProfilePaths
from tether_agent.ports import PortAllocator, RunNamespace
from tether_agent.publication import (
    cleanup_merged_publication,
    publish_github_pull_request,
)
from tether_agent.repositories import resolve_remote
from tether_agent.runtime import PlanSuspended, RuntimeRegistry
from tether_agent.snapshots import (
    canonical_common_directory,
    create_snapshot,
    head_commit,
    restore_worktree_tree,
    tree_for_worktree,
)
from tether_agent.state import StateStore
from tether_agent.worktrees import WorktreeManager

logger = logging.getLogger(__name__)
CONTROL_PLANE_INTERVAL_SECONDS = 25
PLAN_QUESTION_LIVE_WAIT_SECONDS = 15 * 60
HANDOFF_RETRY_DELAYS_SECONDS = (5, 15, 30, 60, 120, 300)
BASE_SUPPORTED_FEATURES = ("multi_task_runs_v1", "multi_task_runs_v2")
ACKNOWLEDGED_RESULT_STATES = frozenset(
    {"completion_pending", "review", "completed", "failed", "cancelled"}
)
FILE_URI_PATTERN = re.compile(r"\bfile://[^\s,;)}\]]+")
ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?<![\w:/])(?:~[/\\]|/|[A-Za-z]:[/\\])[^\s,;)}\]]+"
)


class BatchRecoveryError(RuntimeError):
    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


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

    @property
    def supported_features(self) -> tuple[str, ...]:
        return tuple(
            sorted({*BASE_SUPPORTED_FEATURES, *self.runtimes.supported_features()})
        )

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
            "per_run_branch_handoff": True,
            "remote_pr_publication": True,
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
                "supported_features": list(self.supported_features),
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
                    await self._reconcile_publications()
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
                            supported_features=self.supported_features,
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
                                "supported_features": list(self.supported_features),
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
            if str(run.get("mode") or "execute") == "plan":
                try:
                    await self._execute_plan(
                        run=run,
                        run_id=run_id,
                        generation=generation,
                        lease_token=lease_token,
                        namespace=namespace,
                    )
                except AgentApiError as exc:
                    if exc.recoverable:
                        raise
                    await self.api.comment(
                        run_id,
                        generation,
                        lease_token,
                        "blocker",
                        self._remote_safe(exc.user_message),
                    )
                    self.store.finish_run(run_id, "blocked")
                    self.ports.release(run_id)
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    await self.api.comment(
                        run_id,
                        generation,
                        lease_token,
                        "blocker",
                        self._remote_safe(str(exc)),
                    )
                    self.store.finish_run(run_id, "blocked")
                    self.ports.release(run_id)
                return
            if bool(run.get("is_batch")):
                try:
                    await self._execute_batch(
                        run=run,
                        run_id=run_id,
                        generation=generation,
                        lease_token=lease_token,
                        heartbeat=heartbeat,
                        worker_slot=worker_slot,
                        namespace=namespace,
                    )
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    failure_code = (
                        exc.code
                        if isinstance(exc, BatchRecoveryError)
                        else "agent_internal_error"
                    )
                    failed = await self.api.state(
                        run_id,
                        generation,
                        lease_token,
                        "failed",
                        self._remote_safe(str(exc)),
                        failure_code=failure_code,
                    )
                    self.store.finish_run(run_id, str(failed["state"]))
                    self.store.set_worktree_state(run_id, str(failed["state"]))
                return
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
                        agent_name=str(run.get("profile_name") or "agent"),
                        task_title=str(run.get("task_title") or "task"),
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
            usage_sequence = 0
            usage_supported = True

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

            async def token_usage(payload: dict[str, Any]) -> None:
                nonlocal usage_sequence, usage_supported
                if not usage_supported:
                    return
                usage_sequence += 1
                try:
                    await self.api.token_usage(
                        run_id,
                        generation,
                        lease_token,
                        usage_sequence,
                        payload,
                    )
                except AgentApiError as exc:
                    if exc.response.status_code in {404, 405}:
                        usage_supported = False
                        logger.info(
                            "Server does not support live token usage for run %s",
                            run_id,
                        )
                        return
                    logger.warning(
                        "Could not report live token usage for run %s: %s",
                        run_id,
                        exc,
                    )
                except httpx.TransportError as exc:
                    logger.warning(
                        "Could not report live token usage for run %s: %s",
                        run_id,
                        exc,
                    )

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
                        token_usage=token_usage,
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

    async def _execute_plan(
        self,
        *,
        run: dict[str, Any],
        run_id: UUID,
        generation: int,
        lease_token: str,
        namespace: RunNamespace | None,
    ) -> None:
        runtime = self.runtimes.get(str(run["runtime_kind"]))
        run_plan = getattr(runtime, "run_plan", None)
        if not callable(run_plan):
            failed = await self.api.state(
                run_id,
                generation,
                lease_token,
                "failed",
                "This runtime does not satisfy the native planning contract.",
            )
            self.store.finish_run(run_id, str(failed["state"]))
            self.ports.release(run_id)
            return
        model_id = run.get("model_id")
        if not isinstance(model_id, str) or not model_id:
            failed = await self.api.state(
                run_id,
                generation,
                lease_token,
                "failed",
                "Plan run has no immutable model selection.",
            )
            self.store.finish_run(run_id, str(failed["state"]))
            self.ports.release(run_id)
            return
        pending = self.store.pending_result(run_id)
        mapping: ProjectMapping | None = None
        directory: Path | None = None
        if pending is None:
            run = await self._bind_plan_repository_bases(
                run=run,
                run_id=run_id,
                generation=generation,
                lease_token=lease_token,
            )
            context = await self.api.context(run_id, generation, lease_token)
            directory, local_context, mapping = self._prepare_plan_project(
                context=context,
                run=run,
                run_id=run_id,
            )
            outstanding = run.get("outstanding_question")
            if isinstance(outstanding, dict) and outstanding.get("state") == "answered":
                local_context["suspended_question_answer"] = (
                    self._normalized_plan_answer(outstanding)
                )
            await self.api.state(
                run_id,
                generation,
                lease_token,
                "running",
                effective_model_id=model_id,
                effective_reasoning_effort=run.get("reasoning_effort"),
            )

            async def progress(message: str, payload: dict[str, Any]) -> None:
                await self.api.timeline(
                    run_id,
                    generation,
                    lease_token,
                    f"{run_id}:{generation}:plan:{payload.get('semantic_key', 'work')}",
                    self._remote_safe(message),
                    self._remote_safe(payload),
                )

            usage_sequence = 0

            async def token_usage(payload: dict[str, Any]) -> None:
                nonlocal usage_sequence
                usage_sequence += 1
                await self.api.token_usage(
                    run_id,
                    generation,
                    lease_token,
                    usage_sequence,
                    payload,
                )

            async def question(
                request_key: str, questions: list[dict[str, Any]]
            ) -> dict[str, list[str]]:
                created = await self.api.create_question(
                    run_id,
                    generation,
                    lease_token,
                    request_key=request_key,
                    questions=self._remote_safe(questions),
                )
                return await self._wait_for_plan_answer(
                    run_id,
                    UUID(str(created["id"])),
                    generation,
                    lease_token,
                )

            try:
                result = await run_plan(
                    run_id=run_id,
                    context=local_context,
                    working_directory=directory,
                    model_id=model_id,
                    reasoning_effort=run.get("reasoning_effort"),
                    environment=namespace.environment() if namespace else {},
                    progress=progress,
                    token_usage=token_usage,
                    question=question,
                )
            except PlanSuspended:
                self.store.finish_run(run_id, "waiting_for_user")
                self._remove_plan_worktree(run_id, mapping, directory)
                self.ports.release(run_id)
                return
            except (OSError, RuntimeError, subprocess.SubprocessError):
                if not self.worktrees.is_dirty(directory):
                    self._remove_plan_worktree(run_id, mapping, directory)
                raise
            worktree_dirty = self.worktrees.is_dirty(directory)
            if result.get("file_change_items_emitted") or worktree_dirty:
                failed = await self.api.state(
                    run_id,
                    generation,
                    lease_token,
                    "failed",
                    "Planning attempted to modify the read-only repository worktree.",
                )
                self.store.finish_run(run_id, str(failed["state"]))
                self.store.set_worktree_state(run_id, str(failed["state"]))
                if not worktree_dirty:
                    self._remove_plan_worktree(run_id, mapping, directory)
                self.ports.release(run_id)
                return
            safe_markdown = str(self._remote_safe(str(result["markdown"]))).strip()
            if not safe_markdown or len(safe_markdown) > 100_000:
                raise RuntimeError(
                    "Codex returned a planning artifact outside the supported size"
                )
            result["markdown"] = safe_markdown
            self.store.save_pending_result(run_id, result)
            pending = result
        if mapping is not None and directory is not None:
            self._remove_plan_worktree(run_id, mapping, directory)
        assert pending is not None
        completed = await self.api.complete_plan(
            run_id,
            generation,
            lease_token,
            markdown=str(pending["markdown"]),
            codex_thread_id=str(pending["codex_thread_id"]),
            codex_turn_id=str(pending["codex_turn_id"]),
        )
        self.store.clear_pending_result(run_id)
        self.store.finish_run(run_id, str(completed["state"]))
        self.ports.release(run_id)

    async def _wait_for_plan_answer(
        self,
        run_id: UUID,
        question_id: UUID,
        generation: int,
        lease_token: str,
    ) -> dict[str, list[str]]:
        deadline = time.monotonic() + PLAN_QUESTION_LIVE_WAIT_SECONDS
        while time.monotonic() < deadline:
            remote = await self.api.run(run_id)
            answer = self._live_plan_answer(remote, question_id)
            if answer is not None:
                await self.api.consume_question(
                    run_id,
                    question_id,
                    generation,
                    lease_token,
                )
                return answer
            await asyncio.sleep(2)
        suspended = await self.api.suspend_question(
            run_id,
            question_id,
            generation,
            lease_token,
        )
        raced_answer = self._live_plan_answer(suspended, question_id)
        if raced_answer is not None:
            await self.api.consume_question(
                run_id,
                question_id,
                generation,
                lease_token,
            )
            return raced_answer
        raise PlanSuspended("Planning is waiting for a recorded user answer")

    @staticmethod
    def _live_plan_answer(
        run: dict[str, Any], question_id: UUID
    ) -> dict[str, list[str]] | None:
        current = run.get("outstanding_question")
        if not (
            isinstance(current, dict)
            and current.get("id") == str(question_id)
            and current.get("state") == "answered"
            and isinstance(current.get("answers"), dict)
        ):
            return None
        return {
            str(key): [str(value) for value in values]
            for key, values in current["answers"].items()
            if isinstance(values, list)
        }

    async def _bind_plan_repository_bases(
        self,
        *,
        run: dict[str, Any],
        run_id: UUID,
        generation: int,
        lease_token: str,
    ) -> dict[str, Any]:
        projects = [
            item
            for item in run.get("project_snapshot", [])
            if item.get("mapping_requirement") == "required"
        ]
        if not projects:
            raise RuntimeError("A Plan run requires one mapped logical project")
        existing = run.get("plan_repository_bases")
        existing_by_project = existing if isinstance(existing, dict) else {}
        bases: dict[UUID, str] = {}
        for project in projects:
            project_id = UUID(str(project["id"]))
            mapping = next(
                (
                    item
                    for item in self.settings.project_mappings
                    if item.project_id == project_id
                ),
                None,
            )
            if mapping is None:
                raise RuntimeError(
                    f"Plan run project {project_id} has no approved local mapping"
                )
            captured = existing_by_project.get(str(project_id))
            if isinstance(captured, str):
                self._verify_plan_base(mapping.local_path, captured)
                bases[project_id] = captured
                continue
            bases[project_id] = self._resolve_plan_base(
                mapping=mapping,
                requested_ref=project.get("ref"),
            )
        if existing_by_project:
            if {str(project_id): commit for project_id, commit in bases.items()} != (
                existing_by_project
            ):
                raise RuntimeError(
                    "The persisted planning repository bases do not match this run"
                )
            return run
        return await self.api.bind_plan_repository_bases(
            run_id,
            generation,
            lease_token,
            bases,
        )

    @staticmethod
    def _verify_plan_base(repository: Path, commit: str) -> None:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "rev-parse",
                "--verify",
                f"{commit}^{{commit}}",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0 or result.stdout.strip() != commit:
            raise RuntimeError(
                "The exact planning repository base is unavailable locally"
            )

    @classmethod
    def _resolve_plan_base(
        cls,
        *,
        mapping: ProjectMapping,
        requested_ref: object,
    ) -> str:
        if not isinstance(requested_ref, str) or not requested_ref.strip():
            raise RuntimeError(
                "The logical project has no configured default ref. Configure one "
                "before starting a Plan run."
            )
        ref = requested_ref.strip()
        if re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", ref):
            cls._verify_plan_base(mapping.local_path, ref)
            return ref
        try:
            remote_name, _ = resolve_remote(
                mapping.local_path,
                remote=mapping.remote_url,
                remote_name=mapping.remote_name,
            )
        except ValueError as error:
            raise RuntimeError(
                "The repository has no unambiguous selected Git remote. Re-add the "
                "workspace mapping with --remote-name and --remote."
            ) from error
        if remote_name is None:
            raise RuntimeError(
                "The repository has no explicitly selected Git remote. Re-add the "
                "workspace mapping with --remote-name."
            )
        if ref.startswith("refs/") and not ref.startswith("refs/heads/"):
            raise RuntimeError("The configured default ref is not a valid branch")
        branch = ref.removeprefix("refs/heads/")
        if not branch:
            raise RuntimeError("The configured default ref is not a valid branch")
        if branch.startswith(("origin/", "upstream/")):
            raise RuntimeError(
                "The configured default branch must not include a Git remote name"
            )
        valid = subprocess.run(
            ["git", "check-ref-format", f"refs/heads/{branch}"],
            check=False,
            capture_output=True,
            text=True,
        )
        if valid.returncode != 0:
            raise RuntimeError("The configured default ref is not a valid branch")
        remote_ref = f"refs/remotes/{remote_name}/{branch}"
        common_directory = canonical_common_directory(mapping.local_path)
        lock = ProfileLock(
            common_directory / "tb-agent" / "repository.lock",
            label="repository",
        )
        try:
            lock.acquire(blocking=True)
            fetch = subprocess.run(
                [
                    "git",
                    "-C",
                    str(mapping.local_path),
                    "fetch",
                    "--no-tags",
                    remote_name,
                    f"+refs/heads/{branch}:{remote_ref}",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if fetch.returncode != 0:
                detail = fetch.stderr.strip() or fetch.stdout.strip()
                raise RuntimeError(
                    f"Could not fetch configured default branch {branch!r} from "
                    f"the selected remote {remote_name!r}: {detail}"
                )
            result = subprocess.run(
                [
                    "git",
                    "-C",
                    str(mapping.local_path),
                    "rev-parse",
                    "--verify",
                    f"{remote_ref}^{{commit}}",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        finally:
            lock.release()
        commit = result.stdout.strip()
        if result.returncode != 0 or not re.fullmatch(
            r"[0-9a-f]{40}(?:[0-9a-f]{24})?", commit
        ):
            raise RuntimeError(
                f"Configured default branch {branch!r} is not available from the "
                f"selected remote {remote_name!r}. Fetch it or correct the "
                "workspace repository settings."
            )
        return commit

    def _prepare_plan_project(
        self,
        *,
        context: dict[str, Any],
        run: dict[str, Any],
        run_id: UUID,
    ) -> tuple[Path, dict[str, Any], ProjectMapping]:
        local_context = copy.deepcopy(context)
        project_items = [
            item for item in local_context["items"] if item["kind"] == "project"
        ]
        primary_items = [
            item for item in project_items if item["payload"].get("is_primary")
        ]
        if len(primary_items) != 1:
            raise RuntimeError("A Plan run requires one primary logical project")
        project = primary_items[0]["payload"]
        project_id = UUID(str(project["id"]))
        mapping = next(
            (
                item
                for item in self.settings.project_mappings
                if item.project_id == project_id
            ),
            None,
        )
        if mapping is None:
            raise RuntimeError("The Plan run has no approved local mapping")
        base_commit = str(project.get("ref") or "")
        if len(base_commit) not in {40, 64}:
            raise RuntimeError("The Plan run has no exact captured repository base")
        directory = self.worktrees.planning_directory(mapping, run_id, base_commit)
        self.store.record_worktree(
            run_id=run_id,
            project_id=mapping.project_id,
            repository_path=mapping.local_path,
            path=directory,
        )
        project["local_checkout"] = str(directory)
        project["read_only"] = True
        return directory, local_context, mapping

    def _remove_plan_worktree(
        self,
        run_id: UUID,
        mapping: ProjectMapping,
        directory: Path,
    ) -> None:
        if directory.exists():
            if self.worktrees.is_dirty(directory):
                raise RuntimeError("Refusing to remove a dirty planning worktree")
            self.worktrees.remove(mapping.local_path, directory)
        self.store.delete_worktree(run_id, mapping.project_id)

    @staticmethod
    def _normalized_plan_answer(question: dict[str, Any]) -> str:
        normalized = question.get("normalized_answer")
        if not isinstance(normalized, str) or not normalized.strip():
            raise TypeError("Suspended planning answer is missing its server record")
        return normalized

    async def _execute_batch(
        self,
        *,
        run: dict[str, Any],
        run_id: UUID,
        generation: int,
        lease_token: str,
        heartbeat: asyncio.Task[None],
        worker_slot: int,
        namespace: RunNamespace | None,
    ) -> None:
        del worker_slot
        runtime = self.runtimes.get(str(run["runtime_kind"]))
        model_value = run.get("model_id")
        if not isinstance(model_value, str) or not model_value:
            await self.api.state(
                run_id,
                generation,
                lease_token,
                "failed",
                "Run has no immutable model selection.",
            )
            self.store.finish_run(run_id, "blocked")
            return
        model_id = model_value
        reasoning_effort = run.get("reasoning_effort")
        progress_number = 0
        progress_last_sent_at = 0.0
        progress_last_fingerprint: str | None = None
        usage_sequence = 0
        usage_supported = True
        latest_usage: dict[str, Any] | None = None

        async def progress(message: str, payload: dict[str, Any]) -> None:
            nonlocal progress_last_fingerprint, progress_last_sent_at, progress_number
            fingerprint = repr(
                (
                    run.get("current_task_id"),
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
                f"{run_id}:{generation}:batch-progress:{progress_number}",
                self._remote_safe(message),
                self._remote_safe({**payload, "task_id": run.get("current_task_id")}),
            )
            progress_last_fingerprint = fingerprint
            progress_last_sent_at = now

        async def token_usage(payload: dict[str, Any]) -> None:
            nonlocal latest_usage, usage_sequence, usage_supported
            latest_usage = payload
            if not usage_supported:
                return
            usage_sequence += 1
            try:
                await self.api.token_usage(
                    run_id,
                    generation,
                    lease_token,
                    usage_sequence,
                    payload,
                )
            except AgentApiError as exc:
                if exc.response.status_code in {404, 405}:
                    usage_supported = False
                else:
                    logger.warning(
                        "Could not report live token usage for batch run %s: %s",
                        run_id,
                        exc,
                    )
            except httpx.TransportError as exc:
                logger.warning(
                    "Could not report live token usage for batch run %s: %s",
                    run_id,
                    exc,
                )

        pending_result = self.store.pending_result(run_id)
        directory: Path | None = None
        while pending_result is None:
            tasks = list(run.get("tasks") or [])
            current_task_id = UUID(str(run["current_task_id"]))
            member = next(
                (
                    item
                    for item in tasks
                    if str(item["task_id"]) == str(current_task_id)
                ),
                None,
            )
            if member is None:
                raise RuntimeError("Batch claim has no current task membership")
            for completed_member in tasks[: int(member["ordinal"])]:
                if completed_member.get("state") != "completed":
                    continue
                self.store.acknowledge_task_turn(
                    run_id=run_id,
                    task_id=UUID(str(completed_member["task_id"])),
                    turn_revision=int(completed_member["turn_revision"]),
                )
            recovering = (
                int(run.get("resume_count") or 0) > 0
                or int(run.get("recovery_count") or 0) > 0
                or int(member["ordinal"]) > 0
            )
            if recovering:
                retained = self.store.change_set(run_id)
                if retained is None or not retained.worktree_path.exists():
                    raise BatchRecoveryError(
                        "The retained batch worktree is no longer available",
                        code="local_batch_artifacts_missing",
                    )
            context = await self.api.context(run_id, generation, lease_token)
            try:
                directory, local_context = self._prepare_projects(
                    context=context,
                    run_id=run_id,
                    agent_name=str(run.get("profile_name") or "agent"),
                    task_title=str(
                        run.get("task_title") or member.get("title") or "batch"
                    ),
                )
            except RuntimeError as exc:
                if recovering:
                    raise BatchRecoveryError(
                        str(exc), code="local_batch_artifacts_changed"
                    ) from exc
                raise
            change_set = self.store.change_set(run_id)
            if change_set is None:
                raise RuntimeError("Batch run has no local change set")
            if run.get("state") != "running":
                run = await self.api.state(
                    run_id,
                    generation,
                    lease_token,
                    "running",
                    effective_model_id=model_id,
                    effective_reasoning_effort=reasoning_effort,
                )
            turn_revision = int(member["turn_revision"])
            saved = self.store.task_turn_result(
                run_id=run_id,
                task_id=current_task_id,
                turn_revision=turn_revision,
            )
            checkpoint_tree = (
                str(saved["_worktree_tree"])
                if saved is not None
                else next(
                    (
                        str(item["worktree_tree"])
                        for item in reversed(tasks[: int(member["ordinal"])])
                        if item.get("state") == "completed"
                        and item.get("worktree_tree")
                    ),
                    None,
                )
            )
            expected_tree = checkpoint_tree or self._git_tree(
                change_set.repository_path,
                change_set.base_commit,
            )
            if tree_for_worktree(directory) != expected_tree:
                try:
                    restore_worktree_tree(
                        worktree=directory,
                        base_commit=change_set.base_commit,
                        expected_tree=expected_tree,
                    )
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    raise BatchRecoveryError(
                        str(exc), code="local_batch_artifacts_changed"
                    ) from exc
            if saved is None:
                self.store.begin_task_turn(
                    run_id=run_id,
                    task_id=current_task_id,
                    ordinal=int(member["ordinal"]),
                    turn_revision=turn_revision,
                )
                runtime_task = asyncio.create_task(
                    runtime.run(
                        run_id=run_id,
                        context=local_context,
                        working_directory=directory,
                        model_id=model_id,
                        reasoning_effort=reasoning_effort,
                        environment=(namespace.environment() if namespace else {}),
                        progress=progress,
                        token_usage=token_usage,
                    )
                )
                completed, _ = await asyncio.wait(
                    {runtime_task, heartbeat}, return_when=asyncio.FIRST_COMPLETED
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
                result = {
                    key: value
                    for key, value in saved.items()
                    if not key.startswith("_")
                }
            if (
                result.get("effective_model_id") != model_id
                or result.get("effective_reasoning_effort") != reasoning_effort
            ):
                result = {
                    "status": "failed",
                    "message": "Runtime selection changed during the batch.",
                    "outputs": [],
                    "completion_note": None,
                    "effective_model_id": model_id,
                    "effective_reasoning_effort": reasoning_effort,
                }
            if result["status"] in {"question", "blocked"}:
                await self.api.comment(
                    run_id,
                    generation,
                    lease_token,
                    result["status"],
                    self._remote_safe(result["message"]),
                )
                self.store.finish_run(run_id, str(result["status"]))
                self.store.set_worktree_state(run_id, str(result["status"]))
                return
            if result["status"] == "failed":
                blocked = await self.api.state(
                    run_id,
                    generation,
                    lease_token,
                    "failed",
                    self._remote_safe(result["message"]),
                )
                self.store.finish_run(run_id, str(blocked["state"]))
                self.store.set_worktree_state(run_id, str(blocked["state"]))
                return
            checkpoint_revision = int(member.get("checkpoint_revision") or 0) + 1
            if saved is None:
                worktree_tree = tree_for_worktree(directory)
                self.store.save_task_turn_result(
                    run_id=run_id,
                    task_id=current_task_id,
                    turn_revision=turn_revision,
                    checkpoint_revision=checkpoint_revision,
                    worktree_tree=worktree_tree,
                    result=result,
                )
            else:
                worktree_tree = str(saved["_worktree_tree"])
                checkpoint_revision = int(saved["_checkpoint_revision"])
            run = await self.api.checkpoint_task(
                run_id,
                current_task_id,
                generation,
                lease_token,
                turn_revision=turn_revision,
                checkpoint_revision=checkpoint_revision,
                worktree_tree=worktree_tree,
                summary=self._remote_safe(str(result["message"])),
                token_usage=self._remote_safe(latest_usage),
            )
            self.store.acknowledge_task_turn(
                run_id=run_id,
                task_id=current_task_id,
                turn_revision=turn_revision,
            )
            if int(run["current_task_ordinal"]) > int(member["ordinal"]):
                latest_usage = None
                continue
            task_results = self.store.task_turn_results(run_id)
            outputs = [
                output
                for task_result in task_results
                for output in list(task_result.get("outputs") or [])
            ]
            notes = [
                task_result.get("completion_note")
                for task_result in task_results
                if task_result.get("completion_note")
            ]
            pending_result = {
                "status": "succeeded",
                "message": f"Completed {len(task_results)} tasks in one execution batch.",
                "outputs": outputs,
                "completion_note": (
                    {
                        "title": "Batch execution summary",
                        "markdown": "\n\n".join(
                            str(note.get("markdown") or "")
                            for note in notes
                            if isinstance(note, dict)
                        ),
                    }
                    if notes
                    else None
                ),
                "effective_model_id": model_id,
                "effective_reasoning_effort": reasoning_effort,
            }
            self.store.save_pending_result(run_id, pending_result)

        assert directory is not None or self.store.change_set(run_id) is not None
        result = pending_result
        change_set = self.store.change_set(run_id)
        if change_set is None:
            raise RuntimeError("Batch run has no local change set")
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
            raise RuntimeError(f"Batch change set is not ready: {change_set.state}")
        result["change_set"] = {
            "snapshot_commit": change_set.snapshot_commit,
            "snapshot_tree": change_set.snapshot_tree,
            "base_commit": change_set.base_commit,
            "validation_revision": change_set.validation_revision,
            "validation_status": change_set.validation_status,
            "change_set_revision": change_set.change_set_revision,
        }
        self.store.save_pending_result(run_id, result)
        completed_run = await self._complete_with_retry(
            run_id=run_id,
            generation=generation,
            lease_token=lease_token,
            task_version=int(run["task_version"]),
            result=result,
        )
        self.store.clear_pending_result(run_id)
        self.store.finish_run(run_id, str(completed_run["state"]))
        self.store.set_worktree_state(run_id, str(completed_run["state"]))

    @staticmethod
    def _git_tree(repository: Path, commit: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", f"{commit}^{{tree}}"],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

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
                        "supported_features": list(self.supported_features),
                    }
                )
                await self._refresh_catalogs()
            except (AgentApiError, httpx.HTTPError, OSError, RuntimeError) as exc:
                logger.warning("Daemon background heartbeat failed: %s", exc)

    async def _reconcile_handoffs(self) -> None:
        if self.installation_id is None:
            return
        for remote_run in await self.api.pending_handoffs(self.installation_id):
            try:
                await self._reconcile_handoff(remote_run)
            except (AgentApiError, httpx.HTTPError, OSError) as error:
                await self._record_handoff_failure(remote_run, error)
            except (RuntimeError, subprocess.SubprocessError) as error:
                logger.error(
                    "Handoff %s requires local attention: %s",
                    remote_run.get("id", "unknown"),
                    self._remote_safe(str(error)),
                )

    async def _record_handoff_failure(
        self,
        remote_run: dict[str, Any],
        error: Exception,
    ) -> None:
        run_id = UUID(str(remote_run["id"]))
        remote_change_set = remote_run.get("change_set")
        if not isinstance(remote_change_set, dict):
            return
        current = self.store.handoff(run_id)
        attempt_count = (
            int(current["attempt_count"]) if current is not None else 0
        ) + 1
        recoverable = not isinstance(error, AgentApiError) or error.recoverable
        retry_index = min(attempt_count - 1, len(HANDOFF_RETRY_DELAYS_SECONDS) - 1)
        jitter = 0.9 + ((run_id.int + attempt_count) % 21) / 100
        next_retry_at = (
            datetime.now(UTC)
            + timedelta(seconds=HANDOFF_RETRY_DELAYS_SECONDS[retry_index] * jitter)
            if recoverable
            else None
        )
        message = self._remote_safe(
            error.user_message if isinstance(error, AgentApiError) else str(error)
        )
        error_code = "server_transient" if recoverable else "unknown"
        self.store.schedule_handoff_retry(
            run_id,
            attempt_count=attempt_count,
            next_retry_at=next_retry_at,
            error_code=error_code,
            error_message=str(message),
            retryable=recoverable,
        )
        if recoverable and next_retry_at is not None:
            binding = self._handoff_binding(run_id, remote_change_set)
            try:
                await self.api.report_handoff_status(
                    run_id,
                    {
                        **binding,
                        "attempt_count": attempt_count,
                        "error_code": error_code,
                        "error_message": str(message),
                        "next_retry_at": next_retry_at.isoformat(),
                    },
                )
            except (AgentApiError, httpx.HTTPError) as report_error:
                logger.debug(
                    "Could not report handoff retry %s: %s",
                    run_id,
                    report_error,
                )
        logger.warning(
            "Handoff %s %s: %s",
            run_id,
            "will retry" if recoverable else "is blocked",
            message,
        )

    @staticmethod
    def _handoff_binding(
        run_id: UUID,
        remote_change_set: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "run_id": str(run_id),
            "snapshot_commit": remote_change_set.get("accepted_snapshot_commit")
            or remote_change_set["snapshot_commit"],
            "snapshot_tree": remote_change_set.get("accepted_snapshot_tree")
            or remote_change_set["snapshot_tree"],
            "validation_revision": remote_change_set.get("accepted_validation_revision")
            if remote_change_set.get("accepted_validation_revision") is not None
            else remote_change_set["validation_revision"],
            "change_set_revision": remote_change_set.get("accepted_change_set_revision")
            if remote_change_set.get("accepted_change_set_revision") is not None
            else remote_change_set["change_set_revision"],
        }

    async def _reconcile_handoff(self, remote_run: dict[str, Any]) -> None:
        run_id = UUID(str(remote_run["id"]))
        remote_change_set = remote_run.get("change_set")
        if not isinstance(remote_change_set, dict):
            return
        binding = self._handoff_binding(run_id, remote_change_set)
        local = self.store.change_set(run_id)
        if local is None:
            logger.error("Accepted run %s has no local change set", run_id)
            return
        remote_status = remote_run.get("handoff_status") or {}
        remote_retry_revision = int(remote_status.get("retry_revision") or 0)
        if remote_retry_revision:
            self.store.consume_remote_handoff_retry(run_id, remote_retry_revision)
        handoff = self.store.handoff(run_id)
        if handoff is not None and not self.store.handoff_retry_due(
            run_id, now=datetime.now(UTC)
        ):
            return
        if remote_run["state"] == "awaiting_acknowledgement":
            reason = (remote_run.get("pending_completion") or {}).get("reason")
            if reason != "handoff_ack_pending":
                return
            if local.state == "accepted":
                self.store.transition_change_set(
                    run_id,
                    expected_states=frozenset({"accepted"}),
                    next_state="applied",
                )
            await self.api.acknowledge_handoff(run_id, binding)
            self.ports.release(run_id)
            return
        if local.state == "review_ready":
            local = self.store.accept_change_set(
                run_id=run_id,
                snapshot_commit=str(binding["snapshot_commit"]),
                snapshot_tree=str(binding["snapshot_tree"]),
                validation_revision=int(binding["validation_revision"]),
                change_set_revision=int(binding["change_set_revision"]),
            )
        handoff = self.store.handoff(run_id)
        if remote_run["state"] == "handoff_blocked" and (
            handoff is None or handoff["state"] not in {"retry_requested", "applied"}
        ):
            return
        if handoff is not None and handoff["state"] == "blocked":
            if remote_run["state"] == "applying":
                await self.api.complete_handoff(
                    run_id,
                    {
                        **binding,
                        "status": "blocked",
                        "message": self._remote_safe(
                            str(handoff["error"] or handoff["last_error_message"])
                        ),
                    },
                )
            return
        if remote_run["state"] in {"accepted", "handoff_blocked"}:
            response = await self.api.start_handoff(run_id, binding)
            if response.get("state") == "handoff_blocked":
                return
        handoff = self.store.handoff(run_id)
        if handoff is not None and handoff["state"] == "applied":
            result_method = str(handoff["method"])
            applied_commit = str(handoff["applied_commit"])
        else:
            if local.state != "accepted":
                logger.error(
                    "Accepted server handoff %s conflicts with local state %s",
                    run_id,
                    local.state,
                )
                return
            try:
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
                return
            result_method = result.method
            applied_commit = result.applied_commit
        run_branch = self.store.run_branch(run_id)
        if run_branch is None:
            raise RuntimeError("Accepted handoff has no locally owned run branch")
        response = await self.api.complete_handoff(
            run_id,
            {
                **binding,
                "status": "applied",
                "method": result_method,
                "applied_commit": applied_commit,
                "branch_name": run_branch.branch_name,
                "upstream_ref": run_branch.upstream_ref,
                "base_commit": run_branch.base_commit,
            },
        )
        if local.state == "accepted":
            self.store.transition_change_set(
                run_id,
                expected_states=frozenset({"accepted"}),
                next_state="applied",
            )
        if (response.get("pending_completion") or {}).get("reason") == (
            "handoff_ack_pending"
        ):
            await self.api.acknowledge_handoff(run_id, binding)
            self.ports.release(run_id)

    @staticmethod
    def _publication_binding(remote_run: dict[str, Any]) -> dict[str, Any]:
        change_set = remote_run["change_set"]
        handoff = remote_run["handoff_status"]
        return {
            "run_id": str(remote_run["id"]),
            "snapshot_commit": change_set.get("accepted_snapshot_commit")
            or change_set["snapshot_commit"],
            "snapshot_tree": change_set.get("accepted_snapshot_tree")
            or change_set["snapshot_tree"],
            "validation_revision": change_set.get("accepted_validation_revision")
            if change_set.get("accepted_validation_revision") is not None
            else change_set["validation_revision"],
            "change_set_revision": change_set.get("accepted_change_set_revision")
            if change_set.get("accepted_change_set_revision") is not None
            else change_set["change_set_revision"],
            "branch_name": handoff["branch_name"],
            "upstream_ref": handoff["upstream_ref"],
            "base_commit": handoff["base_commit"],
        }

    async def _reconcile_publications(self) -> None:
        pending_publications = getattr(self.api, "pending_publications", None)
        if self.installation_id is None or pending_publications is None:
            return
        for remote_run in await pending_publications(self.installation_id):
            try:
                await self._reconcile_publication(remote_run)
            except (
                AgentApiError,
                httpx.HTTPError,
                OSError,
                RuntimeError,
                subprocess.SubprocessError,
            ) as error:
                publication = remote_run.get("publication_status") or {}
                if publication.get("state") in {"pushing", "creating_pr"}:
                    binding = self._publication_binding(remote_run)
                    try:
                        await self.api.complete_publication(
                            UUID(str(remote_run["id"])),
                            {
                                **binding,
                                "status": "blocked",
                                "error_code": "publication_failed",
                                "error_message": str(self._remote_safe(str(error)))[
                                    :512
                                ],
                                "remote_branch_present": publication.get(
                                    "remote_branch_present"
                                ),
                                "ahead_count": publication.get("ahead_count"),
                                "behind_count": publication.get("behind_count"),
                                "handoff_retention_days": (
                                    self.settings.worktrees.handoff_retention_days
                                ),
                            },
                        )
                    except (AgentApiError, httpx.HTTPError):
                        pass
                logger.error(
                    "Publication %s requires attention: %s",
                    remote_run.get("id", "unknown"),
                    self._remote_safe(str(error)),
                )

    async def _reconcile_publication(self, remote_run: dict[str, Any]) -> None:
        run_id = UUID(str(remote_run["id"]))
        publication = remote_run.get("publication_status")
        if not isinstance(publication, dict):
            return
        branch = self.store.run_branch(run_id)
        if branch is None:
            raise RuntimeError("Publication has no locally owned run branch")
        binding = self._publication_binding(remote_run)
        local_binding = (
            branch.branch_name,
            branch.upstream_ref,
            branch.base_commit,
            branch.feature_head,
        )
        remote_binding = (
            binding["branch_name"],
            binding["upstream_ref"],
            binding["base_commit"],
            binding["snapshot_commit"],
        )
        if local_binding != remote_binding:
            raise RuntimeError(
                "Publication binding differs from local branch ownership"
            )
        state = str(publication["state"])
        if state == "blocked":
            return
        if state == "requested":
            remote_run = await self.api.start_publication(run_id, binding)
            publication = remote_run.get("publication_status") or {}
            state = str(publication.get("state"))
        if state not in {
            "pushing",
            "creating_pr",
            "cancel_requested",
            "published",
            "merged",
            "cleanup_pending",
            "cleanup_blocked",
        }:
            return
        if state in {"cleanup_pending", "cleanup_blocked"}:
            await self._cleanup_publication(remote_run=remote_run, binding=binding)
            return
        mapping = next(
            (
                item
                for item in self.settings.project_mappings
                if item.project_id == branch.project_id
            ),
            None,
        )
        if mapping is None or mapping.remote_url is None:
            raise RuntimeError("Publication repository mapping is unavailable")
        result = publish_github_pull_request(
            repository=branch.repository_path,
            remote_name=branch.remote_name,
            remote_url=mapping.remote_url,
            upstream_ref=branch.upstream_ref,
            branch_name=branch.branch_name,
            accepted_head=branch.feature_head,
            title=str(remote_run.get("task_title") or "Tether Brain task"),
            run_id=str(run_id),
            create_pull_request=state
            not in {"cancel_requested", "published", "merged"},
        )
        payload = {
            **binding,
            "published_head": result.published_head,
            "provider": result.provider,
            "pull_request_url": result.pull_request_url,
            "pull_request_number": result.pull_request_number,
            "remote_branch_present": result.remote_branch_present,
            "ahead_count": result.ahead_count,
            "behind_count": result.behind_count,
            "provider_merged_at": result.provider_merged_at,
            "handoff_retention_days": (self.settings.worktrees.handoff_retention_days),
        }
        if result.state == "cancelled":
            await self.api.complete_publication(
                run_id, {**payload, "status": "cancelled"}
            )
            return
        if state == "pushing":
            await self.api.complete_publication(
                run_id, {**payload, "status": "creating_pr"}
            )
        if state not in {"published", "merged"} or (
            state == "published" and result.state == "published"
        ):
            remote_run = await self.api.complete_publication(
                run_id, {**payload, "status": "published"}
            )
            self.store.mark_run_branch_published(run_id, result.published_head)
        if result.state == "merged" and state != "merged":
            remote_run = await self.api.complete_publication(
                run_id, {**payload, "status": "merged"}
            )
            self.store.mark_run_branch_merged(run_id, result.published_head)
        elif state == "merged":
            self.store.mark_run_branch_merged(run_id, result.published_head)
        if result.state == "merged":
            await self._cleanup_publication(remote_run=remote_run, binding=binding)

    async def _cleanup_publication(
        self,
        *,
        remote_run: dict[str, Any],
        binding: dict[str, Any],
    ) -> None:
        publication = remote_run.get("publication_status") or {}
        eligible_raw = publication.get("cleanup_eligible_at")
        if not eligible_raw:
            return
        eligible_at = datetime.fromisoformat(str(eligible_raw))
        if eligible_at > datetime.now(UTC):
            return
        run_id = UUID(str(remote_run["id"]))
        payload = {
            **binding,
            "published_head": binding["snapshot_commit"],
            "provider": publication.get("provider"),
            "pull_request_url": publication.get("pull_request_url"),
            "pull_request_number": publication.get("pull_request_number"),
            "remote_branch_present": publication.get("remote_branch_present"),
            "ahead_count": publication.get("ahead_count"),
            "behind_count": publication.get("behind_count"),
            "provider_merged_at": publication.get("provider_merged_at"),
            "handoff_retention_days": self.settings.worktrees.handoff_retention_days,
        }
        if publication.get("state") != "cleanup_pending":
            remote_run = await self.api.complete_publication(
                run_id,
                {**payload, "status": "cleanup_pending"},
            )
            publication = remote_run.get("publication_status") or publication
        try:
            cleanup_merged_publication(
                store=self.store,
                run_id=str(run_id),
                accepted_head=str(binding["snapshot_commit"]),
                accepted_tree=str(binding["snapshot_tree"]),
            )
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            await self.api.complete_publication(
                run_id,
                {
                    **payload,
                    "status": "cleanup_blocked",
                    "error_code": "cleanup_failed",
                    "error_message": str(self._remote_safe(str(error)))[:512],
                },
            )
            return
        await self.api.complete_publication(
            run_id,
            {**payload, "status": "cleaned"},
        )

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
        agent_name: str = "agent",
        task_title: str = "task",
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
            requested_ref = project.get("ref")
            if project.get("is_primary") and mapping.access == "write":
                prepared_branch = prepare_run_branch(
                    store=self.store,
                    mapping=mapping,
                    run_id=run_id,
                    requested_ref=requested_ref,
                    agent_name=agent_name,
                    task_title=task_title,
                )
                requested_ref = prepared_branch.base_commit
                project["local_branch"] = prepared_branch.branch_name
            directory = self.worktrees.working_directory(
                mapping,
                run_id,
                requested_ref,
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
