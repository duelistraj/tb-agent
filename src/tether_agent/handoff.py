"""Transactional promotion of accepted snapshots to run-owned feature refs."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from tether_agent.locking import LockUnavailable, ProfileLock
from tether_agent.snapshots import canonical_common_directory, snapshot_is_current
from tether_agent.state import ChangeSetRecord, StateStore


@dataclass(frozen=True, slots=True)
class HandoffResult:
    method: str
    applied_commit: str


def _git(repository: Path, *arguments: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=check,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def apply_accepted_snapshot(
    *,
    store: StateStore,
    change_set: ChangeSetRecord,
    checkout: Path,
) -> HandoffResult:
    if change_set.state != "accepted":
        raise RuntimeError("Only an explicitly accepted change set can be applied")
    if (
        change_set.snapshot_commit is None
        or change_set.snapshot_tree is None
        or change_set.accepted_snapshot_commit != change_set.snapshot_commit
        or change_set.accepted_snapshot_tree != change_set.snapshot_tree
        or change_set.accepted_revision != change_set.change_set_revision
    ):
        raise RuntimeError("The accepted revision binding is incomplete or stale")
    if not snapshot_is_current(
        worktree=change_set.worktree_path,
        snapshot_tree=change_set.snapshot_tree,
    ):
        raise RuntimeError("The reviewed worktree changed after snapshot creation")
    common_directory = canonical_common_directory(checkout)
    if common_directory != canonical_common_directory(change_set.repository_path):
        raise RuntimeError("The target checkout belongs to a different repository")
    branch = store.run_branch(change_set.run_id)
    if branch is None:
        raise RuntimeError(
            "This accepted run predates per-run branch handoff. Upgrade tb-agent "
            "and rerun the task; the mapped checkout will not be modified."
        )
    if canonical_common_directory(branch.repository_path) != common_directory:
        raise RuntimeError("The run-owned branch belongs to a different repository")
    lock = ProfileLock(
        common_directory / "tb-agent" / "repository.lock",
        label="repository handoff",
    )
    try:
        lock.acquire()
    except LockUnavailable as error:
        raise RuntimeError(
            "Another tb-agent process is updating this repository"
        ) from error
    try:
        previous = store.handoff(change_set.run_id)
        if previous is not None and previous["state"] == "applied":
            return HandoffResult(
                method=str(previous["method"]),
                applied_commit=str(previous["applied_commit"]),
            )
        if previous is not None and previous["state"] == "blocked":
            raise RuntimeError(
                "The previous handoff attempt is blocked and requires an explicit retry"
            )
        branch_ref = f"refs/heads/{branch.branch_name}"
        current_head = _git(checkout, "rev-parse", "--verify", branch_ref, check=False)
        if current_head not in {branch.base_commit, change_set.snapshot_commit}:
            raise RuntimeError(
                f"Run branch {branch.branch_name} was modified and will not be overwritten"
            )
        if previous is None or previous["state"] != "applying":
            store.begin_handoff(
                run_id=change_set.run_id,
                snapshot_commit=change_set.snapshot_commit,
                snapshot_tree=change_set.snapshot_tree,
                validation_revision=change_set.validation_revision,
                change_set_revision=change_set.change_set_revision,
                checkout_path=checkout,
                common_directory=common_directory,
                captured_head=branch.base_commit,
                captured_branch=branch.branch_name,
                captured_status="",
                captured_index_digest="",
                method="feature_branch",
            )
        if current_head == branch.base_commit:
            try:
                _git(
                    checkout,
                    "update-ref",
                    branch_ref,
                    change_set.snapshot_commit,
                    branch.base_commit,
                )
            except BaseException as error:
                store.finish_handoff(
                    change_set.run_id,
                    state="blocked",
                    error=str(error),
                )
                raise RuntimeError(
                    f"Run branch {branch.branch_name} changed during acceptance"
                ) from error
        store.promote_run_branch(change_set.run_id, change_set.snapshot_commit)
        store.finish_handoff(
            change_set.run_id,
            state="applied",
            applied_commit=change_set.snapshot_commit,
        )
        return HandoffResult(
            method="feature_branch",
            applied_commit=change_set.snapshot_commit,
        )
    finally:
        lock.release()
