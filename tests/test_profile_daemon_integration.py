import asyncio
import threading
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

import pytest

from tether_agent.config import (
    ProfileConfig,
    ProjectMapping,
    load_effective_settings,
    write_profile_config,
)
from tether_agent.daemon import AgentDaemon
from tether_agent.paths import ProfilePaths
from tether_agent.profile import ProfileManager
from tether_agent.state import StateStore


class FakeRuntimeRegistry:
    def capabilities(self) -> list[dict[str, str]]:
        return [
            {
                "runtime_kind": "codex_cli",
                "runtime_identity": "codex-cli/test",
                "runtime_version": "test",
            }
        ]

    async def catalogs(self) -> list[dict]:
        return [
            {
                "runtime_kind": "codex_cli",
                "default_model_id": "test-model",
                "models": [
                    {
                        "id": "test-model",
                        "display_name": "Test model",
                        "supported_reasoning_efforts": [],
                        "default_reasoning_effort": None,
                        "is_default": True,
                    }
                ],
            }
        ]


class FakeServerApi:
    def __init__(self) -> None:
        self.installation_id = uuid4()
        self.profile_id = uuid4()
        self.registration_count = 0
        self.claim_count = 0

    async def register(self, payload: dict) -> dict:
        self.registration_count += 1
        changed_mapping = bool(payload["capabilities"]["projects"])
        return {
            "id": str(self.installation_id),
            "status": "pending_approval" if changed_mapping else "active",
            "approved_manifest": None if changed_mapping else {"digest": "approved"},
            "profiles": [
                {
                    "id": str(self.profile_id),
                    "runtime_kind": "codex_cli",
                }
            ],
        }

    async def report_runtime_catalog(
        self,
        installation_id: object,
        payload: dict,
    ) -> dict:
        del installation_id, payload
        return {}

    async def claim(self, installation_id: object) -> None:
        del installation_id
        self.claim_count += 1

    async def liveness(self, payload: dict) -> dict:
        del payload
        return {}

    async def close(self) -> None:
        return None


async def wait_until(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() >= deadline:
            raise AssertionError("condition was not reached before timeout")
        await asyncio.sleep(0.02)


@pytest.mark.asyncio
async def test_running_daemon_reloads_workspace_and_pauses_claims_for_approval(
    tmp_path: Path,
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = ProfilePaths("default", tmp_path / "config", tmp_path / "state")
    write_profile_config(
        paths.config_file,
        ProfileConfig(poll_seconds=1.0),
    )
    store = StateStore(paths.state_file)
    store.set_secret("pat", "tb_pat_test")
    store.set_configuration_revision(1)
    server = FakeServerApi()
    runtimes = FakeRuntimeRegistry()
    monkeypatch.setattr(AgentDaemon, "_api", lambda self, settings: server)
    monkeypatch.setattr(
        "tether_agent.daemon.RuntimeRegistry",
        lambda **kwargs: runtimes,
    )
    daemon = AgentDaemon(load_effective_settings(paths, store), paths=paths)
    daemon_task = asyncio.create_task(daemon.run_forever())
    try:
        await wait_until(lambda: server.claim_count > 0)
        claims_before_change = server.claim_count
        project_id = uuid4()
        manager = ProfileManager(paths)

        mutation_errors: list[BaseException] = []

        def mutate_profile() -> None:
            try:
                manager.mutate(
                    lambda config: config.model_copy(
                        update={
                            "project_mappings": [
                                ProjectMapping(
                                    project_id=project_id,
                                    local_path=git_repository,
                                    remote_url=(
                                        "ssh://git@github.com/TetherBrain/example"
                                    ),
                                )
                            ]
                        }
                    ),
                    environment_keys=frozenset(),
                    dotenv_path=tmp_path / "missing",
                )
            except (OSError, RuntimeError, ValueError) as error:
                mutation_errors.append(error)

        mutation = threading.Thread(target=mutate_profile)
        mutation.start()
        await wait_until(lambda: not mutation.is_alive())
        mutation.join()
        assert not mutation_errors
        await wait_until(
            lambda: store.get_setting("daemon_status") == "pending_approval"
        )
        await asyncio.sleep(1.1)

        assert not daemon_task.done()
        assert server.registration_count >= 2
        assert server.claim_count == claims_before_change
        assert store.configuration_revision() == 2
        assert daemon.settings.project_mappings[0].project_id == project_id
    finally:
        daemon_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await daemon_task
