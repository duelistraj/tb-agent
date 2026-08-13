import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from tether_agent.changes import refresh_snapshot_state, validate_snapshot
from tether_agent.handoff import apply_accepted_snapshot
from tether_agent.publication import cleanup_merged_publication
from tether_agent.snapshots import (
    create_snapshot,
    head_commit,
    restore_worktree_tree,
    snapshot_is_current,
    tree_for_worktree,
)
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
    branch_name = f"feat/test-agent/task-{run_id}"
    store.reserve_run_branch(
        run_id=run_id,
        project_id=uuid4(),
        repository_path=repository,
        branch_name=branch_name,
        remote_name="origin",
        upstream_ref="refs/remotes/origin/main",
        base_commit=base,
    )
    git(repository, "update-ref", f"refs/heads/{branch_name}", base, "0" * 40)
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


def test_restore_worktree_tree_discards_only_uncheckpointed_changes(
    tmp_path: Path,
) -> None:
    repository, base = initialized_repository(tmp_path)
    worktree = tmp_path / "worktree"
    git(repository, "worktree", "add", "--detach", str(worktree), base)
    (worktree / "tracked.txt").write_text("checkpoint\n")
    (worktree / "checkpoint.txt").write_text("saved\n")
    checkpoint_tree = tree_for_worktree(worktree)
    (worktree / "tracked.txt").write_text("partial retry work\n")
    (worktree / "checkpoint.txt").unlink()
    (worktree / "partial.txt").write_text("discard me\n")

    restore_worktree_tree(
        worktree=worktree,
        base_commit=base,
        expected_tree=checkpoint_tree,
    )

    assert (worktree / "tracked.txt").read_text() == "checkpoint\n"
    assert (worktree / "checkpoint.txt").read_text() == "saved\n"
    assert not (worktree / "partial.txt").exists()
    assert tree_for_worktree(worktree) == checkpoint_tree


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


def test_handoff_retry_schedule_survives_store_reopen(tmp_path: Path) -> None:
    _, _, store, record, snapshot = snapshotted_change_set(tmp_path)
    store.accept_change_set(
        run_id=record.run_id,
        snapshot_commit=snapshot.commit,
        snapshot_tree=snapshot.tree,
        validation_revision=0,
        change_set_revision=1,
    )
    next_retry_at = datetime.now(UTC) + timedelta(minutes=1)
    store.schedule_handoff_retry(
        record.run_id,
        attempt_count=2,
        next_retry_at=next_retry_at,
        error_code="server_transient",
        error_message="Tether Brain returned HTTP 500",
    )

    reopened = StateStore(store.path)
    handoff = reopened.handoff(record.run_id)

    assert handoff is not None
    assert handoff["state"] == "retry_scheduled"
    assert handoff["attempt_count"] == 2
    assert handoff["last_error_message"] == "Tether Brain returned HTTP 500"
    assert not reopened.handoff_retry_due(record.run_id, now=datetime.now(UTC))
    assert reopened.consume_remote_handoff_retry(record.run_id, 1)
    assert reopened.handoff_retry_due(record.run_id, now=datetime.now(UTC))


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


def test_handoff_promotes_only_run_branch_and_keeps_checkout_immutable(
    tmp_path: Path,
) -> None:
    repository, _, store, record, snapshot = snapshotted_change_set(tmp_path)
    original_branch = git(repository, "branch", "--show-current")
    original_head = head_commit(repository)
    (repository / "manual.txt").write_text("manual\n")
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

    branch = store.run_branch(record.run_id)
    assert branch is not None
    assert result.method == "feature_branch"
    assert result.applied_commit == snapshot.commit
    assert (
        git(repository, "rev-parse", f"refs/heads/{branch.branch_name}")
        == snapshot.commit
    )
    assert git(repository, "branch", "--show-current") == original_branch
    assert head_commit(repository) == original_head
    assert (repository / "manual.txt").read_text() == "manual\n"


def test_handoff_does_not_cherry_pick_onto_descendant_checkout(tmp_path: Path) -> None:
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

    branch = store.run_branch(record.run_id)
    assert branch is not None
    assert result.method == "feature_branch"
    assert result.applied_commit == snapshot.commit
    assert (
        git(repository, "rev-parse", f"refs/heads/{branch.branch_name}")
        == snapshot.commit
    )
    assert head_commit(repository) == descendant
    assert (repository / "independent.txt").read_text() == "current branch\n"
    assert (repository / "tracked.txt").read_text() == "base\n"


def test_modified_run_branch_blocks_without_mutating_checkout(tmp_path: Path) -> None:
    repository, _, store, record, snapshot = snapshotted_change_set(tmp_path)
    (repository / "tracked.txt").write_text("conflicting current branch\n")
    git(repository, "add", "tracked.txt")
    git(repository, "commit", "-qm", "conflict")
    captured_head = head_commit(repository)
    branch = store.run_branch(record.run_id)
    assert branch is not None
    git(repository, "update-ref", f"refs/heads/{branch.branch_name}", captured_head)
    record = store.accept_change_set(
        run_id=record.run_id,
        snapshot_commit=snapshot.commit,
        snapshot_tree=snapshot.tree,
        validation_revision=0,
        change_set_revision=1,
    )

    with pytest.raises(RuntimeError, match="modified"):
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


def test_cleanup_deletes_only_the_exact_merged_run_ref(tmp_path: Path) -> None:
    repository, worktree, store, record, snapshot = snapshotted_change_set(tmp_path)
    record = store.accept_change_set(
        run_id=record.run_id,
        snapshot_commit=snapshot.commit,
        snapshot_tree=snapshot.tree,
        validation_revision=0,
        change_set_revision=1,
    )
    apply_accepted_snapshot(store=store, change_set=record, checkout=repository)
    branch = store.run_branch(record.run_id)
    assert branch is not None
    store.mark_run_branch_published(record.run_id, snapshot.commit)
    store.mark_run_branch_merged(record.run_id, snapshot.commit)
    store.record_worktree(
        run_id=record.run_id,
        project_id=branch.project_id,
        repository_path=repository,
        path=worktree,
    )
    checkout_head = head_commit(repository)

    cleanup_merged_publication(
        store=store,
        run_id=str(record.run_id),
        accepted_head=snapshot.commit,
        accepted_tree=snapshot.tree,
    )

    assert not worktree.exists()
    assert head_commit(repository) == checkout_head
    assert (
        subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "--verify", snapshot.ref],
            check=False,
            capture_output=True,
        ).returncode
        != 0
    )
    assert (
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "rev-parse",
                "--verify",
                f"refs/heads/{branch.branch_name}",
            ],
            check=False,
            capture_output=True,
        ).returncode
        != 0
    )
    cleaned = store.run_branch(record.run_id)
    assert cleaned is not None and cleaned.state == "cleaned"


def test_cleanup_cas_blocks_a_feature_branch_modified_after_publication(
    tmp_path: Path,
) -> None:
    repository, _, store, record, snapshot = snapshotted_change_set(tmp_path)
    record = store.accept_change_set(
        run_id=record.run_id,
        snapshot_commit=snapshot.commit,
        snapshot_tree=snapshot.tree,
        validation_revision=0,
        change_set_revision=1,
    )
    apply_accepted_snapshot(store=store, change_set=record, checkout=repository)
    branch = store.run_branch(record.run_id)
    assert branch is not None
    store.mark_run_branch_published(record.run_id, snapshot.commit)
    store.mark_run_branch_merged(record.run_id, snapshot.commit)
    git(
        repository,
        "update-ref",
        f"refs/heads/{branch.branch_name}",
        snapshot.base_commit,
    )

    with pytest.raises(RuntimeError, match="changed after publication"):
        cleanup_merged_publication(
            store=store,
            run_id=str(record.run_id),
            accepted_head=snapshot.commit,
            accepted_tree=snapshot.tree,
        )

    assert (
        git(repository, "rev-parse", f"refs/heads/{branch.branch_name}")
        == snapshot.base_commit
    )
    assert git(repository, "rev-parse", snapshot.ref) == snapshot.commit


def test_handoff_is_idempotent_after_feature_ref_update(tmp_path: Path) -> None:
    repository, _, store, record, snapshot = snapshotted_change_set(tmp_path)
    captured_head = head_commit(repository)
    record = store.accept_change_set(
        run_id=record.run_id,
        snapshot_commit=snapshot.commit,
        snapshot_tree=snapshot.tree,
        validation_revision=0,
        change_set_revision=1,
    )

    first = apply_accepted_snapshot(store=store, change_set=record, checkout=repository)
    second = apply_accepted_snapshot(
        store=store, change_set=record, checkout=repository
    )

    assert head_commit(repository) == captured_head
    assert first == second
    assert first.applied_commit == snapshot.commit
