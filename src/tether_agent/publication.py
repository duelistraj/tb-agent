"""Non-force GitHub publication and crash-safe remote reconciliation."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from tether_agent.locking import LockUnavailable, ProfileLock
from tether_agent.repositories import normalize_git_remote
from tether_agent.snapshots import canonical_common_directory, snapshot_is_current
from tether_agent.state import StateStore


@dataclass(frozen=True, slots=True)
class PublicationResult:
    state: str
    published_head: str
    provider: str
    pull_request_url: str | None
    pull_request_number: int | None
    remote_branch_present: bool
    ahead_count: int
    behind_count: int
    provider_merged_at: str | None = None


def _ref_head(repository: Path, ref: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "--verify", "--quiet", ref],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode not in {0, 1}:
        raise subprocess.CalledProcessError(
            result.returncode,
            result.args,
            output=result.stdout,
            stderr=result.stderr,
        )
    return result.stdout.strip() or None


def cleanup_merged_publication(
    *,
    store: StateStore,
    run_id: str,
    accepted_head: str,
    accepted_tree: str,
) -> None:
    """Remove only exact run-owned local artifacts after confirmed PR merge."""
    from uuid import UUID

    parsed_run_id = UUID(run_id)
    branch = store.run_branch(parsed_run_id)
    if branch is None:
        raise RuntimeError("Publication has no locally owned run branch")
    if branch.feature_head != accepted_head:
        raise RuntimeError("Cleanup head differs from the accepted run branch")
    common_directory = canonical_common_directory(branch.repository_path)
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
        branch_ref = f"refs/heads/{branch.branch_name}"
        local_head = _ref_head(branch.repository_path, branch_ref)
        if local_head not in {None, accepted_head}:
            raise RuntimeError(
                "Local feature branch changed after publication; cleanup was blocked"
            )
        rows = [
            row
            for row in store.worktree_rows()
            if str(row["run_id"]) == str(parsed_run_id)
        ]
        for row in rows:
            path = Path(str(row["path"]))
            project_id = UUID(str(row["project_id"]))
            if path.exists():
                if project_id == branch.project_id:
                    if not snapshot_is_current(
                        worktree=path, snapshot_tree=accepted_tree
                    ):
                        raise RuntimeError(
                            "Run worktree changed after review; cleanup was blocked"
                        )
                    subprocess.run(
                        [
                            "git",
                            "-C",
                            str(branch.repository_path),
                            "worktree",
                            "remove",
                            "--force",
                            str(path),
                        ],
                        check=True,
                        timeout=60,
                    )
                else:
                    status = _run(["git", "status", "--porcelain"], cwd=path)
                    if status:
                        raise RuntimeError(
                            "A linked run worktree contains changes; cleanup was blocked"
                        )
                    subprocess.run(
                        [
                            "git",
                            "-C",
                            str(Path(str(row["repository_path"]))),
                            "worktree",
                            "remove",
                            str(path),
                        ],
                        check=True,
                        timeout=60,
                    )
            store.delete_worktree(parsed_run_id, project_id)
        if local_head == accepted_head:
            _run(
                ["git", "update-ref", "-d", branch_ref, accepted_head],
                cwd=branch.repository_path,
            )
        snapshot_ref = f"refs/tb-agent/runs/{parsed_run_id}"
        snapshot_head = _ref_head(branch.repository_path, snapshot_ref)
        if snapshot_head not in {None, accepted_head}:
            raise RuntimeError("Immutable snapshot ref changed; cleanup was blocked")
        if snapshot_head == accepted_head:
            _run(
                ["git", "update-ref", "-d", snapshot_ref, accepted_head],
                cwd=branch.repository_path,
            )
        store.mark_run_branch_cleaned(parsed_run_id, accepted_head)
    finally:
        lock.release()


def _run(arguments: list[str], *, cwd: Path) -> str:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result.stdout.strip()


def _github_repository(remote_url: str) -> str | None:
    parsed = urlsplit(normalize_git_remote(remote_url))
    if parsed.hostname != "github.com":
        return None
    repository = parsed.path.strip("/")
    return repository if repository.count("/") == 1 else None


def _remote_head(repository: Path, remote_name: str, branch_name: str) -> str | None:
    output = _run(
        ["git", "ls-remote", "--heads", remote_name, f"refs/heads/{branch_name}"],
        cwd=repository,
    )
    lines = [line for line in output.splitlines() if line]
    if len(lines) > 1:
        raise RuntimeError("Remote branch lookup returned multiple refs")
    return lines[0].split()[0] if lines else None


def _ahead_behind(
    repository: Path, upstream_ref: str, branch_ref: str
) -> tuple[int, int]:
    raw = _run(
        [
            "git",
            "rev-list",
            "--left-right",
            "--count",
            f"{upstream_ref}...{branch_ref}",
        ],
        cwd=repository,
    )
    behind, ahead = (int(item) for item in raw.split())
    return ahead, behind


def _pull_requests(
    repository: Path, repository_name: str, branch_name: str
) -> list[dict]:
    raw = _run(
        [
            "gh",
            "pr",
            "list",
            "--repo",
            repository_name,
            "--head",
            branch_name,
            "--state",
            "all",
            "--json",
            "number,url,state,headRefOid,baseRefName,mergedAt",
        ],
        cwd=repository,
    )
    value = json.loads(raw)
    if not isinstance(value, list):
        raise TypeError("GitHub returned an invalid pull request list")
    return value


def publish_github_pull_request(
    *,
    repository: Path,
    remote_name: str,
    remote_url: str,
    upstream_ref: str,
    branch_name: str,
    accepted_head: str,
    title: str,
    run_id: str,
    create_pull_request: bool = True,
) -> PublicationResult:
    repository_name = _github_repository(remote_url)
    if repository_name is None:
        raise RuntimeError(
            "Automatic PR publication currently supports GitHub only. Push the "
            f"branch manually: git push {remote_name} {branch_name}"
        )
    local_ref = f"refs/heads/{branch_name}"
    local_head = _run(["git", "rev-parse", "--verify", local_ref], cwd=repository)
    if local_head != accepted_head:
        raise RuntimeError(
            "Local feature branch no longer matches the accepted snapshot"
        )
    base_branch = upstream_ref.rsplit("/", 1)[-1]
    _run(
        [
            "git",
            "fetch",
            "--no-tags",
            remote_name,
            f"+refs/heads/{base_branch}:{upstream_ref}",
        ],
        cwd=repository,
    )
    ahead_count, behind_count = _ahead_behind(repository, upstream_ref, local_ref)
    pull_requests = _pull_requests(repository, repository_name, branch_name)
    exact = [
        item
        for item in pull_requests
        if item.get("headRefOid") == accepted_head
        and item.get("baseRefName") == base_branch
        and item.get("state") in {"OPEN", "MERGED"}
    ]
    if len(exact) > 1:
        raise RuntimeError("Multiple matching pull requests exist for this run branch")
    remote_head = _remote_head(repository, remote_name, branch_name)
    if exact:
        pull_request = exact[0]
        if remote_head not in {None, accepted_head}:
            raise RuntimeError(
                "Remote feature branch diverged from the accepted snapshot"
            )
        if remote_head is None and pull_request["state"] != "MERGED":
            raise RuntimeError("The open pull request branch is missing remotely")
        return PublicationResult(
            state="merged" if pull_request["state"] == "MERGED" else "published",
            published_head=accepted_head,
            provider="github",
            pull_request_url=str(pull_request["url"]),
            pull_request_number=int(pull_request["number"]),
            remote_branch_present=remote_head is not None,
            ahead_count=ahead_count,
            behind_count=behind_count,
            provider_merged_at=pull_request.get("mergedAt"),
        )
    if pull_requests:
        raise RuntimeError(
            "An existing pull request for this branch does not match the accepted snapshot"
        )
    if not create_pull_request:
        return PublicationResult(
            state="cancelled",
            published_head=accepted_head,
            provider="github",
            pull_request_url=None,
            pull_request_number=None,
            remote_branch_present=remote_head is not None,
            ahead_count=ahead_count,
            behind_count=behind_count,
        )
    if remote_head is None:
        _run(
            [
                "git",
                "push",
                "--porcelain",
                remote_name,
                f"{local_ref}:refs/heads/{branch_name}",
            ],
            cwd=repository,
        )
        remote_head = _remote_head(repository, remote_name, branch_name)
    if remote_head != accepted_head:
        raise RuntimeError(
            "Remote feature branch diverged from the accepted snapshot; refusing to force-push"
        )
    _run(
        [
            "gh",
            "pr",
            "create",
            "--repo",
            repository_name,
            "--head",
            branch_name,
            "--base",
            base_branch,
            "--title",
            title,
            "--body",
            f"Tether Brain local task execution run: {run_id}",
        ],
        cwd=repository,
    )
    exact = [
        item
        for item in _pull_requests(repository, repository_name, branch_name)
        if item.get("headRefOid") == accepted_head
        and item.get("baseRefName") == base_branch
        and item.get("state") in {"OPEN", "MERGED"}
    ]
    if len(exact) != 1:
        raise RuntimeError("GitHub did not return the exact created pull request")
    pull_request = exact[0]
    return PublicationResult(
        state="merged" if pull_request["state"] == "MERGED" else "published",
        published_head=accepted_head,
        provider="github",
        pull_request_url=str(pull_request["url"]),
        pull_request_number=int(pull_request["number"]),
        remote_branch_present=True,
        ahead_count=ahead_count,
        behind_count=behind_count,
        provider_merged_at=pull_request.get("mergedAt"),
    )
