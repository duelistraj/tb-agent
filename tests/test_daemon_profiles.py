import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest

from tether_agent.api import AgentApiError
from tether_agent.config import (
    ProfileConfig,
    ProjectMapping,
    load_effective_settings,
    write_profile_config,
)
from tether_agent.daemon import AgentDaemon
from tether_agent.paths import ProfilePaths
from tether_agent.state import StateStore


def initialized_daemon(tmp_path: Path) -> tuple[ProfilePaths, StateStore, AgentDaemon]:
    paths = ProfilePaths("default", tmp_path / "config", tmp_path / "state")
    write_profile_config(paths.config_file, ProfileConfig())
    store = StateStore(paths.state_file)
    store.set_secret("pat", "tb_pat_test")
    store.set_configuration_revision(1)
    daemon = AgentDaemon(load_effective_settings(paths, store), paths=paths)
    return paths, store, daemon


@pytest.mark.asyncio
async def test_daemon_reloads_new_configuration_revision(
    tmp_path: Path,
    git_repository: Path,
) -> None:
    paths, store, daemon = initialized_daemon(tmp_path)
    project_id = uuid4()
    write_profile_config(
        paths.config_file,
        ProfileConfig(
            revision=2,
            installation_name="Reloaded daemon",
            project_mappings=[
                ProjectMapping(
                    project_id=project_id,
                    local_path=git_repository,
                    remote_url="ssh://git@github.com/TetherBrain/example",
                )
            ],
        ),
    )
    store.set_configuration_revision(2)

    assert await daemon._reload_if_changed()

    assert daemon.settings.installation_name == "Reloaded daemon"
    assert daemon.settings.project_mappings[0].project_id == project_id
    assert daemon.approved_manifest_digest is None
    assert store.get_setting("daemon_status") == "reloading"
    await daemon.api.close()


class PendingApi:
    def __init__(self) -> None:
        self.register_calls = 0
        self.claim_calls = 0

    async def register(self, payload: dict) -> dict:
        self.register_calls += 1
        return {
            "id": str(uuid4()),
            "status": "pending_approval",
            "profiles": [],
        }

    async def claim(
        self,
        installation_id: object,
        *,
        worker_slot: int = 0,
        configured_capacity: int = 1,
    ) -> None:
        del installation_id, worker_slot, configured_capacity
        self.claim_calls += 1

    async def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_pending_capability_approval_pauses_claims(tmp_path: Path) -> None:
    _, store, daemon = initialized_daemon(tmp_path)
    api = PendingApi()
    await daemon.api.close()
    daemon.api = api

    task = asyncio.create_task(daemon.run_forever())
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert api.register_calls == 1
    assert api.claim_calls == 0
    assert store.get_setting("installation_status") == "pending_approval"


@pytest.mark.asyncio
async def test_registration_sends_configuration_revision(tmp_path: Path) -> None:
    _, _, daemon = initialized_daemon(tmp_path)
    captured: dict[str, object] = {}

    class Api(PendingApi):
        async def register(self, payload: dict) -> dict:
            captured.update(payload)
            return await super().register(payload)

    await daemon.api.close()
    daemon.api = Api()
    await daemon.register_once()

    assert captured["configuration_revision"] == 1


@pytest.mark.asyncio
async def test_terminal_review_releases_persisted_port_reservation(
    tmp_path: Path,
) -> None:
    _, store, daemon = initialized_daemon(tmp_path)
    run_id = uuid4()
    store.save_claim(run_id, 1, "lease-secret", 0)
    daemon.ports.allocate(run_id=run_id, worker_slot=0)
    daemon.api.run = AsyncMock(return_value={"state": "rejected"})

    await daemon._reconcile_terminal_resources()

    reservation = store.port_reservation(run_id)
    assert reservation is not None
    assert reservation.state == "released"
    assert store.active_run_ids() == []
    await daemon.api.close()


@pytest.mark.asyncio
async def test_terminal_registration_conflict_is_not_retried(tmp_path: Path) -> None:
    _, store, daemon = initialized_daemon(tmp_path)
    request = httpx.Request("POST", "https://tetherbrain.net/register")
    response = httpx.Response(
        409,
        request=request,
        json={
            "detail": {
                "code": "installation_credential_mismatch",
                "message": "Run tb-agent auth login for this profile.",
                "recoverable": False,
            }
        },
    )

    class Api(PendingApi):
        async def register(self, payload: dict) -> dict:
            del payload
            self.register_calls += 1
            raise AgentApiError(response)

    await daemon.api.close()
    api = Api()
    daemon.api = api

    with pytest.raises(RuntimeError, match="auth login"):
        await daemon.register()

    assert api.register_calls == 1
    assert store.get_setting("daemon_status") == "registration_blocked"


@pytest.mark.asyncio
async def test_control_plane_heartbeat_continues_independently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, daemon = initialized_daemon(tmp_path)
    daemon.installation_id = uuid4()
    daemon.approved_manifest_digest = "approved"
    liveness_calls = 0

    class Api:
        async def liveness(self, payload: dict[str, object]) -> dict[str, object]:
            nonlocal liveness_calls
            assert payload["installation_id"] == str(daemon.installation_id)
            liveness_calls += 1
            return {}

    await daemon.api.close()
    daemon.api = Api()
    monkeypatch.setattr("tether_agent.daemon.CONTROL_PLANE_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(daemon, "_refresh_catalogs", AsyncMock())
    stop = asyncio.Event()
    task = asyncio.create_task(daemon._control_plane_loop(stop))
    await asyncio.sleep(0.04)
    stop.set()
    await task

    assert liveness_calls >= 2


@pytest.mark.asyncio
async def test_reclaimed_run_resubmits_saved_result_without_running_codex(
    tmp_path: Path,
) -> None:
    _, store, daemon = initialized_daemon(tmp_path)
    run_id = uuid4()
    result = {
        "status": "completed",
        "message": "Already finished",
        "outputs": [],
        "completion_note": None,
        "effective_model_id": "gpt-test",
        "effective_reasoning_effort": "high",
    }
    store.save_claim(run_id, 1, "old-lease")
    store.save_pending_result(run_id, result)
    runtime = SimpleNamespace(run=AsyncMock(side_effect=AssertionError("must not run")))
    daemon.runtimes = SimpleNamespace(get=lambda _: runtime)
    completed_payloads: list[dict[str, object]] = []

    class Api:
        async def state(self, *args: object, **kwargs: object) -> dict[str, object]:
            del args, kwargs
            return {}

        async def complete(self, *args: object, **kwargs: object) -> dict[str, object]:
            completed_payloads.append({"args": args, "kwargs": kwargs})
            return {"state": "review"}

        async def heartbeat(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

    await daemon.api.close()
    daemon.api = Api()
    await daemon._execute(
        {
            "lease_token": "new-lease",
            "run": {
                "id": str(run_id),
                "lease_generation": 2,
                "runtime_kind": "codex_cli",
                "model_id": "gpt-test",
                "reasoning_effort": "high",
                "task_version": 7,
            },
        }
    )

    assert len(completed_payloads) == 1
    runtime.run.assert_not_awaited()
    assert store.pending_result(run_id) is None


def test_remote_safe_redacts_arbitrary_absolute_paths_but_preserves_urls(
    tmp_path: Path,
) -> None:
    _, _, daemon = initialized_daemon(tmp_path)

    value = daemon._remote_safe(
        "Read /home/person/private.txt and file:///tmp/secret; see https://example.com/a."
    )

    assert value == ("Read [local-path] and [local-path]; see https://example.com/a.")


@pytest.mark.asyncio
async def test_acknowledged_completion_clears_crash_recovery_result(
    tmp_path: Path,
) -> None:
    _, store, daemon = initialized_daemon(tmp_path)
    run_id = uuid4()
    store.save_claim(run_id, 1, "lease")
    store.save_pending_result(
        run_id,
        {"status": "completed", "message": "done", "outputs": []},
    )

    class Api:
        async def run(self, requested_run_id: object) -> dict[str, object]:
            assert requested_run_id == run_id
            return {"state": "review"}

    await daemon.api.close()
    daemon.api = Api()
    await daemon._reconcile_pending_results()

    assert store.pending_result(run_id) is None
    assert store.leased_run_ids() == []


@pytest.mark.asyncio
async def test_maintenance_reconciles_stale_active_run_before_acknowledging(
    tmp_path: Path,
) -> None:
    _, store, daemon = initialized_daemon(tmp_path)
    run_id = uuid4()
    store.save_claim(run_id, 1, "expired-lease")
    maintenance_revision = store.request_maintenance()

    class Api:
        async def run(self, requested_run_id: object) -> dict[str, object]:
            assert requested_run_id == run_id
            return {"state": "failed"}

        async def close(self) -> None:
            return None

    await daemon.api.close()
    daemon.api = Api()

    task = asyncio.create_task(daemon.run_forever())
    try:
        async with asyncio.timeout(1):
            while store.maintenance_ack_revision() < maintenance_revision:
                await asyncio.sleep(0.01)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert store.active_run_id() is None
    assert store.leased_run_ids() == []


@pytest.mark.asyncio
async def test_idle_reconciliation_preserves_unacknowledged_result(
    tmp_path: Path,
) -> None:
    _, store, daemon = initialized_daemon(tmp_path)
    run_id = uuid4()
    result = {"status": "completed", "message": "Saved work", "outputs": []}
    store.save_claim(run_id, 1, "expired-lease")
    store.save_pending_result(run_id, result)

    class Api:
        async def run(self, requested_run_id: object) -> dict[str, object]:
            assert requested_run_id == run_id
            return {"state": "awaiting_agent"}

    await daemon.api.close()
    daemon.api = Api()

    assert not await daemon._reconcile_idle_active_run()
    assert store.active_run_id() == run_id
    assert store.pending_result(run_id) == result


@pytest.mark.asyncio
async def test_idle_reconciliation_preserves_state_when_server_is_unavailable(
    tmp_path: Path,
) -> None:
    _, store, daemon = initialized_daemon(tmp_path)
    run_id = uuid4()
    store.save_claim(run_id, 1, "expired-lease")

    class Api:
        async def run(self, requested_run_id: object) -> dict[str, object]:
            assert requested_run_id == run_id
            request = httpx.Request("GET", f"https://tetherbrain.net/runs/{run_id}")
            raise httpx.ConnectError("offline", request=request)

    await daemon.api.close()
    daemon.api = Api()

    assert not await daemon._reconcile_idle_active_run()
    assert store.active_run_id() == run_id
