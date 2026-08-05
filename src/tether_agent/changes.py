"""Commands that inspect and validate immutable local execution results."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path
from uuid import UUID

from tether_agent.snapshots import snapshot_is_current
from tether_agent.state import ChangeSetRecord, StateStore


def refresh_snapshot_state(
    store: StateStore, record: ChangeSetRecord
) -> ChangeSetRecord:
    if (
        record.state == "review_ready"
        and record.snapshot_tree is not None
        and not snapshot_is_current(
            worktree=record.worktree_path,
            snapshot_tree=record.snapshot_tree,
        )
    ):
        return store.transition_change_set(
            record.run_id,
            expected_states=frozenset({"review_ready"}),
            next_state="superseded",
            expected_revision=record.change_set_revision,
            values={"validation_status": "snapshot_invalidated"},
            increment_revision=True,
        )
    return record


def validate_snapshot(
    *,
    store: StateStore,
    record: ChangeSetRecord,
    command: list[str],
    on_started: Callable[[int], None] | None = None,
) -> tuple[ChangeSetRecord, Path]:
    record = refresh_snapshot_state(store, record)
    if record.snapshot_commit is None or record.snapshot_tree is None:
        raise RuntimeError("This result has no immutable snapshot")
    revision = store.begin_validation(record.run_id, command)
    if on_started is not None:
        try:
            on_started(revision)
        except BaseException:
            store.cancel_validation_start(record.run_id, revision)
            raise
    validation_root = (
        store.path.parent / "validations" / str(record.run_id) / str(revision)
    )
    checkout = validation_root / "checkout"
    log_path = validation_root / "validation.log"
    validation_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    exit_code = 1
    try:
        subprocess.run(
            [
                "git",
                "-C",
                str(record.repository_path),
                "worktree",
                "add",
                "--detach",
                str(checkout),
                record.snapshot_commit,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        effective_command = command or [
            "git",
            "diff",
            "--check",
            f"{record.base_commit}..{record.snapshot_commit}",
        ]
        with log_path.open("w", encoding="utf-8") as log:
            result = subprocess.run(
                effective_command,
                cwd=checkout,
                check=False,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
        exit_code = result.returncode
    finally:
        if checkout.exists():
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(record.repository_path),
                    "worktree",
                    "remove",
                    "--force",
                    str(checkout),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
    updated = store.finish_validation(
        record.run_id,
        revision=revision,
        exit_code=exit_code,
        log_path=log_path,
    )
    return updated, log_path


def snapshot_diff(record: ChangeSetRecord) -> str:
    if record.snapshot_commit is None:
        raise RuntimeError("This result has no immutable snapshot")
    result = subprocess.run(
        [
            "git",
            "-C",
            str(record.repository_path),
            "diff",
            "--stat",
            record.base_commit,
            record.snapshot_commit,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.rstrip()


def require_change_set(store: StateStore, run_id: UUID) -> ChangeSetRecord:
    record = store.change_set(run_id)
    if record is None:
        raise RuntimeError(f"No local change set exists for run {run_id}")
    return refresh_snapshot_state(store, record)
