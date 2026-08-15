import subprocess
from pathlib import Path
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest

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


def test_completed_plan_markdown_path_is_redacted_before_upload(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "private/customer/repository"
    mapping = ProjectMapping(
        project_id=uuid4(),
        local_path=repository,
        access="read",
    )
    subject = daemon(tmp_path, [mapping])

    markdown = subject._remote_safe(
        f"Inspect `{repository}/backend/app/main.py` before implementation."
    )

    assert str(repository) not in markdown
    assert "[local-path]" in markdown


def test_suspended_plan_resume_uses_exact_server_normalized_answer(
    tmp_path: Path,
) -> None:
    subject = daemon(tmp_path, [])
    normalized = (
        "Answer to the suspended Codex planning question:\n"
        "Question: Which database?\nAnswer: PostgreSQL"
    )

    assert (
        subject._normalized_plan_answer({"normalized_answer": normalized}) == normalized
    )


def test_plan_base_resolves_only_the_selected_remote_branch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    remote = tmp_path / "upstream.git"
    repository.mkdir()
    subprocess.run(["git", "init", str(repository)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "test@example.test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Test"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repository), "branch", "-M", "main"], check=True)
    (repository / "README.md").write_text("captured\n")
    subprocess.run(["git", "-C", str(repository), "add", "README.md"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-m", "base"],
        check=True,
        capture_output=True,
    )
    stale_commit = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "clone", "--bare", str(repository), str(remote)], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "remote", "add", "upstream", str(remote)],
        check=True,
    )
    (repository / "README.md").write_text("new upstream content\n")
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-am", "upstream"], check=True
    )
    subprocess.run(
        ["git", "-C", str(repository), "push", "upstream", "main"], check=True
    )
    commit = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "update-ref",
            "refs/remotes/upstream/main",
            stale_commit,
        ],
        check=True,
    )
    mapping = ProjectMapping(
        project_id=uuid4(),
        local_path=repository,
        access="read",
        remote_url=str(remote),
        remote_name="upstream",
    )
    monkeypatch.setattr(
        "tether_agent.daemon.resolve_remote",
        lambda *_args, **_kwargs: ("upstream", "https://example.test/upstream.git"),
    )

    assert (
        AgentDaemon._resolve_plan_base(mapping=mapping, requested_ref="main") == commit
    )


def test_plan_base_rejects_missing_default_ref_or_selected_remote(
    tmp_path: Path,
) -> None:
    mapping = ProjectMapping(
        project_id=uuid4(),
        local_path=tmp_path,
        access="read",
    )

    with pytest.raises(RuntimeError, match="no configured default ref"):
        AgentDaemon._resolve_plan_base(mapping=mapping, requested_ref=None)
    with pytest.raises(RuntimeError, match="no unambiguous selected Git remote"):
        AgentDaemon._resolve_plan_base(mapping=mapping, requested_ref="main")


@pytest.mark.asyncio
async def test_plan_answer_wins_race_with_live_wait_suspension(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    subject = daemon(tmp_path, [])
    question_id = uuid4()
    monkeypatch.setattr("tether_agent.daemon.PLAN_QUESTION_LIVE_WAIT_SECONDS", 0)
    subject.api.suspend_question = AsyncMock(
        return_value={
            "outstanding_question": {
                "id": str(question_id),
                "state": "answered",
                "answers": {"database": ["PostgreSQL"]},
            }
        }
    )
    subject.api.consume_question = AsyncMock(return_value={})

    answers = await subject._wait_for_plan_answer(
        uuid4(),
        question_id,
        1,
        "lease-token",
    )

    assert answers == {"database": ["PostgreSQL"]}
    subject.api.consume_question.assert_awaited_once()
