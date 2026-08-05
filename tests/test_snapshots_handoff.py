import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from tether_agent.changes import refresh_snapshot_state, validate_snapshot
from tether_agent.handoff import apply_accepted_snapshot
from tether_agent.snapshots import create_snapshot, head_commit, snapshot_is_current
from tether_agent.state import StateStore


def git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def initialized_repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    git(repository, "init", "-q")
    git(repository, "config", "user.name", "Test User")
    git(repository, "config", "user.email", "test@example.com")
    (repository / "tracked.txt").write_text("base\n")
    git(repository, "add", "tracked.txt")
    git(repository, "commit", "-qm", "base")
    return repository, head_commit(repository)


def snapshotted_change_set(tmp_path: Path):
    repository, base = initialized_repository(tmp_path)
    run_id = uuid4()
    worktree = tmp_path / "worktree"
    git(repository, "worktree", "add", "--detach", str(worktree), base)
    (worktree / "tracked.txt").write_text("agent\n")
    (worktree / "new.txt").write_text("new\n")
    store = StateStore(tmp_path / "state" / "state.sqlite3")
    store.begin_change_set(
        run_id=run_id,
        repository_path=repository,
        worktree_path=worktree,
        base_commit=base,
    )
    store.transition_change_set(
        run_id,
        expected_states=frozenset({"executing"}),
        next_state="snapshotting",
    )
    snapshot = create_snapshot(
        repository=repository,
        worktree=worktree,
        run_id=run_id,
        base_commit=base,
    )
    record = store.transition_change_set(
        run_id,
        expected_states=frozenset({"snapshotting"}),
        next_state="snapshot_ready",
        values={
            "snapshot_commit": snapshot.commit,
            "snapshot_tree": snapshot.tree,
        },
    )
    record = store.transition_change_set(
        run_id,
        expected_states=frozenset({"snapshot_ready"}),
        next_state="review_ready",
    )
    return repository, worktree, store, record, snapshot


def test_snapshot_has_exact_parent_ref_tree_and_run_trailer(tmp_path: Path) -> None:
    repository, worktree, _, _, snapshot = snapshotted_change_set(tmp_path)

    assert git(repository, "rev-parse", f"{snapshot.commit}^") == snapshot.base_commit
    assert git(repository, "rev-parse", snapshot.ref) == snapshot.commit
    assert (
        git(repository, "show", "-s", "--format=%T", snapshot.commit) == snapshot.tree
    )
    assert f"Tether-Brain-Run-ID: {snapshot.run_id}" in git(
        repository, "show", "-s", "--format=%B", snapshot.commit
    )
    assert snapshot_is_current(worktree=worktree, snapshot_tree=snapshot.tree)


def test_acceptance_requires_exact_snapshot_binding(tmp_path: Path) -> None:
    _, _, store, record, snapshot = snapshotted_change_set(tmp_path)

    with pytest.raises(RuntimeError, match="does not match"):
        store.accept_change_set(
            run_id=record.run_id,
            snapshot_commit="0" * len(snapshot.commit),
            snapshot_tree=snapshot.tree,
            validation_revision=0,
            change_set_revision=1,
        )

    accepted = store.accept_change_set(
        run_id=record.run_id,
        snapshot_commit=snapshot.commit,
        snapshot_tree=snapshot.tree,
        validation_revision=0,
        change_set_revision=1,
    )
    assert accepted.state == "accepted"


def test_manual_edit_after_snapshot_supersedes_review_revision(
    tmp_path: Path,
) -> None:
    _, worktree, store, record, _ = snapshotted_change_set(tmp_path)
    (worktree / "tracked.txt").write_text("manual edit after review\n")

    invalidated = refresh_snapshot_state(store, record)

    assert invalidated.state == "superseded"
    assert invalidated.validation_status == "snapshot_invalidated"
    assert invalidated.change_set_revision == 2


def test_validation_runs_in_immutable_snapshot_checkout(tmp_path: Path) -> None:
    _, _, store, record, _ = snapshotted_change_set(tmp_path)

    validated, log_path = validate_snapshot(
        store=store,
        record=record,
        command=[
            sys.executable,
            "-c",
            "from pathlib import Path; assert Path('tracked.txt').read_text() == 'agent\\n'",
        ],
    )

    assert validated.validation_status == "passed"
    assert validated.validation_revision == 1
    assert log_path.exists()


def test_fast_forward_handoff_applies_only_accepted_snapshot(tmp_path: Path) -> None:
    repository, _, store, record, snapshot = snapshotted_change_set(tmp_path)
    record = store.accept_change_set(
        run_id=record.run_id,
        snapshot_commit=snapshot.commit,
        snapshot_tree=snapshot.tree,
        validation_revision=0,
        change_set_revision=1,
    )

    result = apply_accepted_snapshot(
        store=store,
        change_set=record,
        checkout=repository,
    )

    assert result.method == "fast_forward"
    assert git(repository, "rev-parse", "HEAD") == snapshot.commit
    assert (repository / "tracked.txt").read_text() == "agent\n"
    assert (repository / "new.txt").read_text() == "new\n"


def test_cherry_pick_handoff_preserves_descendant_commit(tmp_path: Path) -> None:
    repository, _, store, record, snapshot = snapshotted_change_set(tmp_path)
    (repository / "independent.txt").write_text("current branch\n")
    git(repository, "add", "independent.txt")
    git(repository, "commit", "-qm", "independent")
    descendant = head_commit(repository)
    record = store.accept_change_set(
        run_id=record.run_id,
        snapshot_commit=snapshot.commit,
        snapshot_tree=snapshot.tree,
        validation_revision=0,
        change_set_revision=1,
    )

    result = apply_accepted_snapshot(
        store=store,
        change_set=record,
        checkout=repository,
    )

    assert result.method == "cherry_pick"
    assert result.applied_commit != snapshot.commit
    assert git(repository, "rev-parse", f"{result.applied_commit}^") == descendant
    assert (repository / "independent.txt").read_text() == "current branch\n"
    assert (repository / "tracked.txt").read_text() == "agent\n"


def test_cherry_pick_conflict_aborts_and_restores_checkout(tmp_path: Path) -> None:
    repository, _, store, record, snapshot = snapshotted_change_set(tmp_path)
    (repository / "tracked.txt").write_text("conflicting current branch\n")
    git(repository, "add", "tracked.txt")
    git(repository, "commit", "-qm", "conflict")
    captured_head = head_commit(repository)
    record = store.accept_change_set(
        run_id=record.run_id,
        snapshot_commit=snapshot.commit,
        snapshot_tree=snapshot.tree,
        validation_revision=0,
        change_set_revision=1,
    )

    with pytest.raises(RuntimeError):
        apply_accepted_snapshot(
            store=store,
            change_set=record,
            checkout=repository,
        )

    assert head_commit(repository) == captured_head
    assert (
        git(
            repository,
            "status",
            "--porcelain=v2",
            "--untracked-files=all",
            "--ignore-submodules=none",
        )
        == ""
    )
    assert store.handoff(record.run_id)["state"] == "blocked"


def test_dirty_target_checkout_is_never_mutated(tmp_path: Path) -> None:
    repository, _, store, record, snapshot = snapshotted_change_set(tmp_path)
    (repository / "manual.txt").write_text("manual\n")
    captured_head = head_commit(repository)
    record = store.accept_change_set(
        run_id=record.run_id,
        snapshot_commit=snapshot.commit,
        snapshot_tree=snapshot.tree,
        validation_revision=0,
        change_set_revision=1,
    )

    with pytest.raises(RuntimeError, match="not clean"):
        apply_accepted_snapshot(
            store=store,
            change_set=record,
            checkout=repository,
        )

    assert head_commit(repository) == captured_head
    assert (repository / "manual.txt").read_text() == "manual\n"
