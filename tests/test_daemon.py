from pathlib import Path
from uuid import uuid4

import httpx

from tether_agent.config import DaemonSettings, ProjectMapping
from tether_agent.daemon import AgentDaemon


def daemon(
    tmp_path: Path,
    mappings: list[ProjectMapping],
) -> AgentDaemon:
    return AgentDaemon(
        DaemonSettings(
            access_token="test-token",
            state_path=tmp_path / "state.sqlite3",
            project_mappings=mappings,
        )
    )


def test_project_preparation_requires_and_uses_primary_mapping(
    tmp_path: Path,
) -> None:
    mapped_id = uuid4()
    mapping = ProjectMapping(
        project_id=mapped_id,
        local_path=tmp_path.resolve(),
        access="read",
    )
    subject = daemon(tmp_path, [mapping])

    directory, local_context = subject._prepare_projects(
        context={
            "items": [
                {
                    "kind": "project",
                    "payload": {
                        "id": str(mapped_id),
                        "name": "Primary",
                        "is_primary": True,
                        "mapping_requirement": "required",
                        "ref": None,
                    },
                },
            ]
        },
        run_id=uuid4(),
    )

    assert directory == mapping.local_path
    assert local_context["items"][0]["payload"]["local_checkout"] == str(
        mapping.local_path
    )


def test_required_mapping_conflict_becomes_a_durable_blocker_message() -> None:
    request = httpx.Request("POST", "https://example.test/context")
    response = httpx.Response(
        409,
        request=request,
        json={
            "detail": {
                "code": "required_project_mapping_missing",
                "projects": ["Tether Brain"],
            }
        },
    )

    message = AgentDaemon._required_mapping_error(
        httpx.HTTPStatusError(
            "conflict",
            request=request,
            response=response,
        )
    )

    assert message is not None
    assert "Tether Brain" in message


def test_remote_capability_manifest_never_contains_absolute_repository_path(
    tmp_path: Path,
) -> None:
    mapping = ProjectMapping(
        project_id=uuid4(),
        local_path=tmp_path / "private/customer/repository",
        access="write",
        remote_url="ssh://git@example.test/team/repository",
    )
    subject = daemon(tmp_path, [mapping])

    manifest = subject._capabilities()

    assert str(mapping.local_path) not in str(manifest)
    assert mapping.remote_url not in str(manifest)
    assert manifest["projects"] == [
        {
            "project_id": str(mapping.project_id),
            "access": "write",
            "mapping_revision": mapping.security_revision(),
        }
    ]


def test_remote_activity_payloads_redact_repository_and_worktree_paths(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "private/customer/repository"
    mapping = ProjectMapping(
        project_id=uuid4(),
        local_path=repository,
        access="write",
    )
    subject = daemon(tmp_path, [mapping])
    worktree = repository.parent / ".tether-worktrees/project/run"

    payload = subject._remote_safe(
        {
            "message": f"Changed {repository}/README.md",
            "outputs": [str(worktree / "result.patch")],
        }
    )

    serialized = str(payload)
    assert str(repository) not in serialized
    assert str(worktree) not in serialized
    assert "[local-path]" in serialized
