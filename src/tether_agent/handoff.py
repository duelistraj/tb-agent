"""Transactional application of explicitly accepted Git snapshots."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from tether_agent.locking import LockUnavailable, ProfileLock
from tether_agent.snapshots import canonical_common_directory, snapshot_is_current
from tether_agent.state import ChangeSetRecord, StateStore


@dataclass(frozen=True, slots=True)
class HandoffResult:
    method: str
    applied_commit: str


def _git(checkout: Path, *arguments: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(checkout), *arguments],
        check=check,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _index_digest(checkout: Path) -> str:
    raw = _git(checkout, "rev-parse", "--path-format=absolute", "--git-path", "index")
    index_path = Path(raw)
    return sha256(index_path.read_bytes()).hexdigest() if index_path.exists() else ""


def _status(checkout: Path) -> str:
    return _git(
        checkout,
        "status",
        "--porcelain=v2",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )


def assert_clean_checkout(checkout: Path) -> None:
    if _status(checkout):
        raise RuntimeError(
            "The target checkout is not clean. Commit, stash, or remove staged, "
            "unstaged, untracked, conflicted, and dirty submodule changes first."
        )


def _branch(checkout: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(checkout), "symbolic-ref", "--quiet", "--short", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _is_ancestor(checkout: Path, ancestor: str, descendant: str) -> bool:
    return (
        subprocess.run(
            [
                "git",
                "-C",
                str(checkout),
                "merge-base",
                "--is-ancestor",
                ancestor,
                descendant,
            ],
            check=False,
            capture_output=True,
        ).returncode
        == 0
    )


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
    lock = ProfileLock(
        common_directory / "tb-agent" / "handoff.lock",
        label="repository handoff",
    )
    try:
        lock.acquire()
    except LockUnavailable as error:
        raise RuntimeError(
            "Another tb-agent process is applying changes to this repository"
        ) from error
    try:
        assert_clean_checkout(checkout)
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
        if previous is not None and previous["state"] == "applying":
            current_head = _git(checkout, "rev-parse", "HEAD")
            captured_head = str(previous["captured_head"])
            recovered = current_head == change_set.snapshot_commit
            if not recovered and current_head != captured_head:
                parent = _git(checkout, "rev-parse", f"{current_head}^")
                message = _git(checkout, "show", "-s", "--format=%B", current_head)
                recovered = (
                    parent == captured_head
                    and f"Tether-Brain-Run-ID: {change_set.run_id}" in message
                )
            if recovered:
                store.finish_handoff(
                    change_set.run_id,
                    state="applied",
                    applied_commit=current_head,
                )
                return HandoffResult(
                    method=str(previous["method"]),
                    applied_commit=current_head,
                )
            if current_head != captured_head:
                raise RuntimeError(
                    "The target checkout changed during handoff recovery"
                )
        captured_head = _git(checkout, "rev-parse", "HEAD")
        captured_branch = _branch(checkout)
        captured_status = _status(checkout)
        captured_index_digest = _index_digest(checkout)
        if captured_head == change_set.base_commit:
            method = "fast_forward"
        elif _is_ancestor(checkout, change_set.base_commit, captured_head):
            method = "cherry_pick"
        else:
            raise RuntimeError(
                "The run base is not an ancestor of the target branch. Rebase or "
                "merge the target branch before retrying the handoff."
            )
        store.begin_handoff(
            run_id=change_set.run_id,
            snapshot_commit=change_set.snapshot_commit,
            snapshot_tree=change_set.snapshot_tree,
            validation_revision=change_set.validation_revision,
            change_set_revision=change_set.change_set_revision,
            checkout_path=checkout,
            common_directory=common_directory,
            captured_head=captured_head,
            captured_branch=captured_branch,
            captured_status=captured_status,
            captured_index_digest=captured_index_digest,
            method=method,
        )
        try:
            if method == "fast_forward":
                _git(checkout, "merge", "--ff-only", change_set.snapshot_commit)
            else:
                _git(checkout, "cherry-pick", change_set.snapshot_commit)
            applied_commit = _git(checkout, "rev-parse", "HEAD")
            assert_clean_checkout(checkout)
        except BaseException as error:
            _git(checkout, "cherry-pick", "--abort", check=False)
            _git(checkout, "merge", "--abort", check=False)
            restored = (
                _git(checkout, "rev-parse", "HEAD") == captured_head
                and _branch(checkout) == captured_branch
                and _status(checkout) == captured_status
                and _index_digest(checkout) == captured_index_digest
            )
            message = str(error)
            if not restored:
                message = (
                    "Git handoff failed and the captured checkout state could not "
                    "be verified after rollback. Inspect the checkout manually. "
                    + message
                )
            store.finish_handoff(
                change_set.run_id,
                state="blocked",
                error=message,
            )
            raise RuntimeError(message) from error
        store.finish_handoff(
            change_set.run_id,
            state="applied",
            applied_commit=applied_commit,
        )
        return HandoffResult(method=method, applied_commit=applied_commit)
    finally:
        lock.release()
