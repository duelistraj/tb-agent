"""Immutable Git snapshots for locally executed changes."""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID


@dataclass(frozen=True, slots=True)
class Snapshot:
    run_id: UUID
    base_commit: str
    commit: str
    tree: str
    ref: str


def _git(
    repository: Path,
    *arguments: str,
    environment: dict[str, str] | None = None,
    input_text: str | None = None,
) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        input=input_text,
        env=environment,
    )
    return result.stdout.strip()


def canonical_common_directory(repository: Path) -> Path:
    raw = _git(repository, "rev-parse", "--path-format=absolute", "--git-common-dir")
    return Path(raw).resolve(strict=True)


def head_commit(repository: Path) -> str:
    return _git(repository, "rev-parse", "HEAD")


def tree_for_worktree(worktree: Path) -> str:
    descriptor, index_name = tempfile.mkstemp(prefix="tb-agent-index-")
    os.close(descriptor)
    Path(index_name).unlink(missing_ok=True)
    environment = {**os.environ, "GIT_INDEX_FILE": index_name}
    try:
        _git(worktree, "read-tree", "HEAD", environment=environment)
        _git(worktree, "add", "-A", environment=environment)
        return _git(worktree, "write-tree", environment=environment)
    finally:
        Path(index_name).unlink(missing_ok=True)


def create_snapshot(
    *,
    repository: Path,
    worktree: Path,
    run_id: UUID,
    base_commit: str,
) -> Snapshot:
    ref = f"refs/tb-agent/runs/{run_id}"
    existing = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "--verify", "--quiet", ref],
        check=False,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if existing:
        parent = _git(repository, "rev-parse", f"{existing}^")
        tree = _git(repository, "show", "-s", "--format=%T", existing)
        message = _git(repository, "show", "-s", "--format=%B", existing)
        if parent != base_commit or f"Tether-Brain-Run-ID: {run_id}" not in message:
            raise RuntimeError(f"Snapshot ref {ref} does not match run identity")
        return Snapshot(run_id, base_commit, existing, tree, ref)

    tree = tree_for_worktree(worktree)
    message = (
        f"Tether Brain result for run {run_id}\n\n"
        f"Tether-Brain-Run-ID: {run_id}\n"
    )
    environment = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Tether Brain Agent",
        "GIT_AUTHOR_EMAIL": "agent@tetherbrain.local",
        "GIT_COMMITTER_NAME": "Tether Brain Agent",
        "GIT_COMMITTER_EMAIL": "agent@tetherbrain.local",
    }
    commit = _git(
        repository,
        "commit-tree",
        tree,
        "-p",
        base_commit,
        environment=environment,
        input_text=message,
    )
    update = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "update-ref",
            ref,
            commit,
            "0" * 40,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if update.returncode != 0:
        existing = _git(repository, "rev-parse", "--verify", ref)
        if existing != commit:
            raise RuntimeError(f"Snapshot ref {ref} was created concurrently")
    return Snapshot(run_id, base_commit, commit, tree, ref)


def snapshot_is_current(*, worktree: Path, snapshot_tree: str) -> bool:
    return tree_for_worktree(worktree) == snapshot_tree
