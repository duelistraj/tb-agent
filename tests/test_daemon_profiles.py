import asyncio
from pathlib import Path
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

    async def claim(self, installation_id: object) -> None:
        del installation_id
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
