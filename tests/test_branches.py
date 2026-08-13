import subprocess
from pathlib import Path
from uuid import uuid4

import pytest

from tether_agent.branches import prepare_run_branch
from tether_agent.config import ProjectMapping
from tether_agent.state import StateStore


def git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def initialized_remote(tmp_path: Path) -> tuple[Path, Path]:
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
    repository = tmp_path / "repository"
    subprocess.run(["git", "clone", "-q", str(remote), str(repository)], check=True)
    git(repository, "config", "user.name", "Test User")
    git(repository, "config", "user.email", "test@example.com")
    git(repository, "switch", "-c", "main")
    (repository / "tracked.txt").write_text("base\n")
    git(repository, "add", "tracked.txt")
    git(repository, "commit", "-qm", "base")
    git(repository, "push", "-qu", "origin", "main")
    subprocess.run(
        ["git", "-C", str(remote), "symbolic-ref", "HEAD", "refs/heads/main"],
        check=True,
    )
    return repository, remote


def test_existing_run_branch_reuses_captured_identity_when_title_and_upstream_move(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, remote = initialized_remote(tmp_path)
    monkeypatch.setattr(
        "tether_agent.branches.resolve_remote",
        lambda *_args, **_kwargs: ("origin", str(remote)),
    )
    store = StateStore(tmp_path / "state" / "state.sqlite3")
    run_id = uuid4()
    mapping = ProjectMapping(
        project_id=uuid4(),
        local_path=repository,
        remote_url="https://example.test/owner/repository.git",
        remote_name="origin",
    )

    prepared = prepare_run_branch(
        store=store,
        mapping=mapping,
        run_id=run_id,
        requested_ref="main",
        agent_name="Codex",
        task_title="First task",
    )
    (repository / "tracked.txt").write_text("upstream moved\n")
    git(repository, "add", "tracked.txt")
    git(repository, "commit", "-qm", "move upstream")
    git(repository, "push", "-q", "origin", "main")

    resumed = prepare_run_branch(
        store=store,
        mapping=mapping,
        run_id=run_id,
        requested_ref="main",
        agent_name="Codex",
        task_title="Second task with another title",
    )

    assert resumed == prepared
    assert resumed.base_commit != git(repository, "rev-parse", "main")
    assert git(repository, "rev-parse", resumed.branch_name) == prepared.base_commit
