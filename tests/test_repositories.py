import subprocess
from pathlib import Path

import pytest

from tether_agent.repositories import (
    detect_remote_default_ref,
    git_remote_identity,
    inspect_repository,
    normalize_git_remote,
)


def test_inspection_canonicalizes_root_and_remote(git_repository: Path) -> None:
    nested = git_repository / "nested"
    nested.mkdir()

    repository = inspect_repository(nested)

    assert repository.root == git_repository.resolve()
    assert repository.remote_name == "origin"
    assert repository.remote_url == "ssh://git@github.com/TetherBrain/example"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            "https://GitHub.com/TetherBrain/example.git/",
            "https://github.com/TetherBrain/example",
        ),
        (
            "git@GitHub.com:TetherBrain/example.git",
            "ssh://git@github.com/TetherBrain/example",
        ),
    ],
)
def test_remote_normalization(raw: str, expected: str) -> None:
    assert normalize_git_remote(raw) == expected


def test_remote_identity_matches_ssh_and_https_transports() -> None:
    assert git_remote_identity("git@github.com:TetherBrain/example.git") == (
        git_remote_identity("https://github.com/TetherBrain/example")
    )


def test_missing_and_ambiguous_remotes_require_explicit_choice(
    git_repository: Path,
) -> None:
    subprocess.run(
        ["git", "-C", str(git_repository), "remote", "remove", "origin"],
        check=True,
    )
    with pytest.raises(ValueError, match="allow-no-remote"):
        inspect_repository(git_repository)
    assert inspect_repository(git_repository, allow_no_remote=True).remote_url is None

    subprocess.run(
        [
            "git",
            "-C",
            str(git_repository),
            "remote",
            "add",
            "one",
            "https://example.test/one.git",
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(git_repository),
            "remote",
            "add",
            "two",
            "https://example.test/two.git",
        ],
        check=True,
    )
    with pytest.raises(ValueError, match="multiple remotes"):
        inspect_repository(git_repository)
    selected = inspect_repository(
        git_repository,
        remote="https://example.test/one.git",
    )
    assert selected.remote_url == "https://example.test/one"
    assert selected.remote_name == "one"


def test_non_repository_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a git repository"):
        inspect_repository(tmp_path, allow_no_remote=True)


def test_remote_default_ref_uses_the_advertised_remote_head(tmp_path: Path) -> None:
    source = tmp_path / "source"
    remote = tmp_path / "remote.git"
    source.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(source)], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "test@example.test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(source), "config", "user.name", "Test"], check=True
    )
    (source / "README.md").write_text("test\n")
    subprocess.run(["git", "-C", str(source), "add", "README.md"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "commit", "-m", "base"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "clone", "--bare", str(source), str(remote)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(source), "remote", "add", "upstream", str(remote)], check=True
    )

    assert detect_remote_default_ref(source, "upstream") == "main"


def test_remote_default_ref_does_not_guess_when_remote_head_is_unavailable(
    git_repository: Path,
) -> None:
    assert detect_remote_default_ref(git_repository, "origin") is None
    assert detect_remote_default_ref(git_repository, None) is None
