"""Conservative Git repository discovery for local project mappings."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

SCP_REMOTE_PATTERN = re.compile(r"^(?P<user>[^@/:]+)@(?P<host>[^/:]+):(?P<path>.+)$")


@dataclass(frozen=True, slots=True)
class RepositoryInfo:
    root: Path
    remote_url: str | None


def _git(root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip() or "Git rejected the repository path"
        raise ValueError(detail) from error
    return result.stdout.strip()


def normalize_git_remote(value: str) -> str:
    remote = value.strip()
    if not remote:
        raise ValueError("Git remote URL cannot be empty")
    scp_match = SCP_REMOTE_PATTERN.fullmatch(remote)
    if scp_match is not None:
        remote = (
            f"ssh://{scp_match.group('user')}@{scp_match.group('host')}/"
            f"{scp_match.group('path')}"
        )
    parsed = urlsplit(remote)
    if parsed.scheme:
        if not parsed.hostname:
            raise ValueError("Git remote URL must include a host")
        hostname = parsed.hostname.casefold()
        port = f":{parsed.port}" if parsed.port is not None else ""
        user = f"{parsed.username}@" if parsed.username else ""
        path = parsed.path.rstrip("/")
        path = path.removesuffix(".git")
        if not path:
            raise ValueError("Git remote URL must include a repository path")
        return urlunsplit(
            (parsed.scheme.casefold(), f"{user}{hostname}{port}", path, "", "")
        )
    local = Path(remote).expanduser()
    if local.is_absolute():
        return str(local.resolve(strict=False))
    raise ValueError(
        "Git remote is ambiguous. Pass an absolute local URL or a URL with a scheme."
    )


def git_remote_identity(value: str) -> str:
    """Return a transport-independent host and path identity for a Git remote."""

    normalized = normalize_git_remote(value)
    parsed = urlsplit(normalized)
    if parsed.hostname is None:
        return normalized
    authority = parsed.hostname.casefold()
    if parsed.port is not None:
        authority = f"{authority}:{parsed.port}"
    return f"{authority}{parsed.path}".casefold()


def _discovered_remote(root: Path) -> str | None:
    names = [item for item in _git(root, "remote").splitlines() if item]
    urls_by_name: dict[str, list[str]] = {}
    for name in names:
        values = [
            item
            for item in _git(root, "remote", "get-url", "--all", name).splitlines()
            if item
        ]
        urls_by_name[name] = list(dict.fromkeys(values))
    if "origin" in urls_by_name:
        origin = urls_by_name["origin"]
        if len(origin) == 1:
            return normalize_git_remote(origin[0])
        if len(origin) > 1:
            raise ValueError(
                "The origin remote has multiple URLs. Pass the intended URL with --remote."
            )
    all_urls = list(
        dict.fromkeys(value for values in urls_by_name.values() for value in values)
    )
    if len(all_urls) == 1:
        return normalize_git_remote(all_urls[0])
    if len(all_urls) > 1:
        raise ValueError(
            "The repository has multiple remotes. Pass the intended URL with --remote."
        )
    return None


def inspect_repository(
    path: Path,
    *,
    remote: str | None = None,
    allow_no_remote: bool = False,
) -> RepositoryInfo:
    candidate = path.expanduser().resolve(strict=True)
    root_text = _git(candidate, "rev-parse", "--show-toplevel")
    if _git(candidate, "rev-parse", "--is-inside-work-tree") != "true":
        raise ValueError(f"Path is not a Git worktree: {path}")
    root = Path(root_text).resolve(strict=True)
    filesystem_root = Path(root.anchor)
    if (
        root == filesystem_root
        or root == Path.home().resolve(strict=True)
        or len(root.parts) <= 2
    ):
        raise ValueError(f"Refusing unsafe broad repository mapping: {root}")
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ValueError("Repository path escapes its canonical Git root") from error
    selected_remote = (
        normalize_git_remote(remote) if remote else _discovered_remote(root)
    )
    if selected_remote is None and not allow_no_remote:
        raise ValueError(
            "The repository has no unambiguous remote. Pass --remote URL or "
            "--allow-no-remote explicitly."
        )
    return RepositoryInfo(root=root, remote_url=selected_remote)
