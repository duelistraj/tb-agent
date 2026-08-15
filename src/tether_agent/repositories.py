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
    remote_name: str | None
    remote_url: str | None
    default_ref: str | None


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


def _remotes(root: Path) -> dict[str, list[str]]:
    names = [item for item in _git(root, "remote").splitlines() if item]
    urls_by_name: dict[str, list[str]] = {}
    for name in names:
        values = [
            item
            for item in _git(root, "remote", "get-url", "--all", name).splitlines()
            if item
        ]
        urls_by_name[name] = list(dict.fromkeys(values))
    return urls_by_name


def detect_remote_default_ref(root: Path, remote_name: str | None) -> str | None:
    """Return one advertised remote HEAD branch without using local guesses."""

    if remote_name is None:
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-remote", "--symref", remote_name, "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    candidates = {
        match.group("branch")
        for line in result.stdout.splitlines()
        if (match := re.fullmatch(r"ref:\s+refs/heads/(?P<branch>[^\s]+)\s+HEAD", line))
    }
    if len(candidates) != 1:
        return None
    branch = next(iter(candidates))
    valid = subprocess.run(
        ["git", "check-ref-format", f"refs/heads/{branch}"],
        check=False,
        capture_output=True,
        text=True,
    )
    return branch if valid.returncode == 0 else None


def resolve_remote(
    root: Path,
    *,
    remote: str | None = None,
    remote_name: str | None = None,
) -> tuple[str | None, str | None]:
    urls_by_name = _remotes(root)
    if not urls_by_name:
        if remote is not None or remote_name is not None:
            raise ValueError("The selected Git remote is not configured locally")
        return None, None
    if remote_name is not None:
        values = urls_by_name.get(remote_name)
        if values is None:
            raise ValueError(f"Git remote '{remote_name}' does not exist")
        normalized_values = list(
            dict.fromkeys(normalize_git_remote(item) for item in values)
        )
        if remote is not None:
            selected_url = normalize_git_remote(remote)
            matches = [
                value
                for value in normalized_values
                if git_remote_identity(value) == git_remote_identity(selected_url)
            ]
            if len(matches) != 1:
                raise ValueError(f"Git remote '{remote_name}' does not match --remote")
            return remote_name, matches[0]
        if len(normalized_values) != 1:
            raise ValueError(
                f"Git remote '{remote_name}' has multiple URLs. Pass --remote as well."
            )
        return remote_name, normalized_values[0]
    if remote is not None:
        selected_url = normalize_git_remote(remote)
        matching_names = [
            name
            for name, values in urls_by_name.items()
            if any(
                git_remote_identity(value) == git_remote_identity(selected_url)
                for value in values
            )
        ]
        if len(matching_names) != 1:
            raise ValueError(
                "The selected Git URL does not identify exactly one local remote. "
                "Pass --remote-name."
            )
        return matching_names[0], selected_url
    if len(urls_by_name) != 1:
        raise ValueError(
            "The repository has multiple remotes. Pass --remote-name and --remote."
        )
    selected_name, values = next(iter(urls_by_name.items()))
    normalized_values = list(
        dict.fromkeys(normalize_git_remote(item) for item in values)
    )
    if len(normalized_values) != 1:
        raise ValueError(
            f"Git remote '{selected_name}' has multiple URLs. Pass --remote explicitly."
        )
    return selected_name, normalized_values[0]


def inspect_repository(
    path: Path,
    *,
    remote: str | None = None,
    remote_name: str | None = None,
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
    selected_remote_name, selected_remote = resolve_remote(
        root,
        remote=remote,
        remote_name=remote_name,
    )
    if selected_remote is None and not allow_no_remote:
        raise ValueError(
            "The repository has no unambiguous remote. Pass --remote URL or "
            "--allow-no-remote explicitly."
        )
    return RepositoryInfo(
        root=root,
        remote_name=selected_remote_name,
        remote_url=selected_remote,
        default_ref=detect_remote_default_ref(root, selected_remote_name),
    )
