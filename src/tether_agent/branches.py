"""Strict upstream synchronization and run-owned feature refs."""

from __future__ import annotations

import re
import subprocess
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from tether_agent.config import ProjectMapping
from tether_agent.locking import LockUnavailable, ProfileLock
from tether_agent.repositories import resolve_remote
from tether_agent.snapshots import canonical_common_directory
from tether_agent.state import StateStore

SLUG_PATTERN = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True, slots=True)
class PreparedRunBranch:
    branch_name: str
    remote_name: str
    upstream_ref: str
    base_commit: str


def _git(repository: Path, *arguments: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=check,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result.stdout.strip()


def _slug(value: str, *, fallback: str, limit: int) -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    slug = SLUG_PATTERN.sub("-", normalized.casefold()).strip("-")
    return (slug or fallback)[:limit].rstrip("-")


def run_branch_name(*, run_id: UUID, agent_name: str, task_title: str) -> str:
    branch = (
        f"feat/{_slug(agent_name, fallback='agent', limit=32)}/"
        f"{_slug(task_title, fallback='task', limit=48)}-{run_id}"
    )
    subprocess.run(
        ["git", "check-ref-format", "--branch", branch],
        check=True,
        capture_output=True,
        text=True,
    )
    return branch


def _default_branch(
    repository: Path, remote_name: str, requested_ref: str | None
) -> str:
    if requested_ref is not None:
        branch = requested_ref.removeprefix("refs/heads/").strip()
        if not branch or requested_ref.startswith("refs/remotes/"):
            raise RuntimeError("The configured default ref is not a remote branch")
        result = subprocess.run(
            ["git", "check-ref-format", f"refs/heads/{branch}"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError("The configured default ref is not a valid branch")
        return branch
    output = _git(repository, "ls-remote", "--symref", remote_name, "HEAD")
    candidates = {
        line.split()[1].removeprefix("refs/heads/")
        for line in output.splitlines()
        if line.startswith("ref: refs/heads/") and line.endswith("\tHEAD")
    }
    if len(candidates) != 1:
        raise RuntimeError(
            "The remote default branch is ambiguous. Configure default_ref explicitly."
        )
    return next(iter(candidates))


def prepare_run_branch(
    *,
    store: StateStore,
    mapping: ProjectMapping,
    run_id: UUID,
    requested_ref: str | None,
    agent_name: str,
    task_title: str,
) -> PreparedRunBranch:
    if mapping.remote_url is None:
        raise RuntimeError(
            "Writable execution requires an explicitly configured Git remote"
        )
    remote_name, remote_url = resolve_remote(
        mapping.local_path,
        remote=mapping.remote_url,
        remote_name=mapping.remote_name,
    )
    if remote_name is None or remote_url is None:
        raise RuntimeError(
            "Writable execution requires an explicitly configured Git remote"
        )
    common_directory = canonical_common_directory(mapping.local_path)
    lock = ProfileLock(
        common_directory / "tb-agent" / "repository.lock", label="repository"
    )
    try:
        lock.acquire()
    except LockUnavailable as error:
        raise RuntimeError(
            "Another tb-agent process is updating this repository"
        ) from error
    try:
        existing = store.run_branch(run_id)
        if existing is not None:
            identity = (
                existing.project_id,
                existing.repository_path.resolve(),
                existing.remote_name,
            )
            if identity != (
                mapping.project_id,
                mapping.local_path.resolve(),
                remote_name,
            ):
                raise RuntimeError("Run branch ownership does not match local state")
            branch_ref = f"refs/heads/{existing.branch_name}"
            current = _git(
                mapping.local_path, "rev-parse", "--verify", branch_ref, check=False
            )
            if current not in {existing.base_commit, existing.feature_head}:
                raise RuntimeError(
                    f"Run branch {existing.branch_name} was modified and will not be overwritten"
                )
            return PreparedRunBranch(
                branch_name=existing.branch_name,
                remote_name=existing.remote_name,
                upstream_ref=existing.upstream_ref,
                base_commit=existing.base_commit,
            )
        default_branch = _default_branch(mapping.local_path, remote_name, requested_ref)
        upstream_ref = f"refs/remotes/{remote_name}/{default_branch}"
        _git(
            mapping.local_path,
            "fetch",
            "--no-tags",
            remote_name,
            f"+refs/heads/{default_branch}:{upstream_ref}",
        )
        base_commit = _git(mapping.local_path, "rev-parse", "--verify", upstream_ref)
        branch_name = run_branch_name(
            run_id=run_id,
            agent_name=agent_name,
            task_title=task_title,
        )
        record = store.reserve_run_branch(
            run_id=run_id,
            project_id=mapping.project_id,
            repository_path=mapping.local_path,
            branch_name=branch_name,
            remote_name=remote_name,
            upstream_ref=upstream_ref,
            base_commit=base_commit,
        )
        branch_ref = f"refs/heads/{record.branch_name}"
        current = _git(
            mapping.local_path, "rev-parse", "--verify", branch_ref, check=False
        )
        if current:
            if current not in {record.base_commit, record.feature_head}:
                raise RuntimeError(
                    f"Run branch {record.branch_name} was modified and will not be overwritten"
                )
        else:
            _git(
                mapping.local_path,
                "update-ref",
                branch_ref,
                record.base_commit,
                "0" * 40,
            )
        return PreparedRunBranch(
            branch_name=record.branch_name,
            remote_name=record.remote_name,
            upstream_ref=record.upstream_ref,
            base_commit=record.base_commit,
        )
    finally:
        lock.release()
