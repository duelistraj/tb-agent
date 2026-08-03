from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from tether_agent.config import ProjectMapping, WorktreePolicy
from tether_agent.worktrees import WorktreeManager


def test_cleanup_never_removes_dirty_worktree(monkeypatch, tmp_path: Path) -> None:
    manager = WorktreeManager(WorktreePolicy())
    monkeypatch.setattr(manager, "is_dirty", lambda _: True)

    decision = manager.cleanup_decision(
        path=tmp_path,
        state="failed",
        accepted=False,
        pinned=False,
        finished_at=datetime.now(UTC) - timedelta(days=30),
    )

    assert decision.removable is False
    assert "uncommitted" in decision.reason


def test_review_worktree_is_retained_until_acceptance(
    monkeypatch, tmp_path: Path
) -> None:
    manager = WorktreeManager(WorktreePolicy(accepted_retention_hours=24))
    monkeypatch.setattr(manager, "is_dirty", lambda _: False)

    decision = manager.cleanup_decision(
        path=tmp_path,
        state="review",
        accepted=False,
        pinned=False,
        finished_at=datetime.now(UTC) - timedelta(days=30),
    )

    assert decision.removable is False
    assert "acceptance" in decision.reason


def test_manual_review_policy_keeps_accepted_worktree(
    monkeypatch, tmp_path: Path
) -> None:
    manager = WorktreeManager(
        WorktreePolicy(
            review_retention="manual",
            accepted_retention_hours=0,
        )
    )
    monkeypatch.setattr(manager, "is_dirty", lambda _: False)

    decision = manager.cleanup_decision(
        path=tmp_path,
        state="review",
        accepted=True,
        pinned=False,
        finished_at=datetime.now(UTC) - timedelta(days=30),
    )

    assert decision.removable is False
    assert decision.reason == "review work uses manual cleanup"


def test_worktree_paths_are_distinct_for_each_project(
    monkeypatch, tmp_path: Path
) -> None:
    manager = WorktreeManager(WorktreePolicy())
    shared_root = tmp_path / "worktrees"
    run_id = uuid4()
    first = ProjectMapping(
        project_id=uuid4(),
        local_path=(tmp_path / "first").resolve(),
        worktree_root=shared_root.resolve(),
    )
    second = ProjectMapping(
        project_id=uuid4(),
        local_path=(tmp_path / "second").resolve(),
        worktree_root=shared_root.resolve(),
    )
    monkeypatch.setattr("subprocess.run", lambda *_args, **_kwargs: None)

    first_path = manager.working_directory(first, run_id, None)
    second_path = manager.working_directory(second, run_id, None)

    assert first_path != second_path
    assert first_path == shared_root / str(first.project_id) / str(run_id)
    assert second_path == shared_root / str(second.project_id) / str(run_id)
