from pathlib import Path

import pytest

from tether_agent.publication import publish_github_pull_request


def test_github_auto_deleted_branch_is_valid_after_exact_pr_merge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accepted_head = "a" * 40
    branch_name = "feat/codex/task-run"
    monkeypatch.setattr(
        "tether_agent.publication._run",
        lambda arguments, cwd: (
            accepted_head if arguments[:3] == ["git", "rev-parse", "--verify"] else ""
        ),
    )
    monkeypatch.setattr(
        "tether_agent.publication._ahead_behind",
        lambda *_args: (1, 0),
    )
    monkeypatch.setattr(
        "tether_agent.publication._remote_head",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        "tether_agent.publication._pull_requests",
        lambda *_args: [
            {
                "number": 17,
                "url": "https://github.com/example/repository/pull/17",
                "state": "MERGED",
                "headRefOid": accepted_head,
                "baseRefName": "main",
                "mergedAt": "2026-08-08T10:00:00Z",
            }
        ],
    )

    result = publish_github_pull_request(
        repository=tmp_path,
        remote_name="origin",
        remote_url="https://github.com/example/repository.git",
        upstream_ref="refs/remotes/origin/main",
        branch_name=branch_name,
        accepted_head=accepted_head,
        title="Task",
        run_id="run",
    )

    assert result.state == "merged"
    assert result.published_head == accepted_head
    assert result.remote_branch_present is False


def test_cancellation_race_reports_existing_exact_pr_instead_of_hiding_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accepted_head = "b" * 40
    monkeypatch.setattr(
        "tether_agent.publication._run",
        lambda arguments, cwd: (
            accepted_head if arguments[:3] == ["git", "rev-parse", "--verify"] else ""
        ),
    )
    monkeypatch.setattr(
        "tether_agent.publication._ahead_behind",
        lambda *_args: (1, 0),
    )
    monkeypatch.setattr(
        "tether_agent.publication._remote_head",
        lambda *_args: accepted_head,
    )
    monkeypatch.setattr(
        "tether_agent.publication._pull_requests",
        lambda *_args: [
            {
                "number": 18,
                "url": "https://github.com/example/repository/pull/18",
                "state": "OPEN",
                "headRefOid": accepted_head,
                "baseRefName": "main",
                "mergedAt": None,
            }
        ],
    )

    result = publish_github_pull_request(
        repository=tmp_path,
        remote_name="origin",
        remote_url="https://github.com/example/repository.git",
        upstream_ref="refs/remotes/origin/main",
        branch_name="feat/codex/task-run",
        accepted_head=accepted_head,
        title="Task",
        run_id="run",
        create_pull_request=False,
    )

    assert result.state == "published"
    assert result.pull_request_number == 18


def test_publication_never_rewrites_or_force_pushes_the_accepted_branch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accepted_head = "c" * 40
    commands: list[list[str]] = []

    def run(arguments: list[str], *, cwd: Path) -> str:
        del cwd
        commands.append(arguments)
        return (
            accepted_head if arguments[:3] == ["git", "rev-parse", "--verify"] else ""
        )

    remote_heads = iter((None, accepted_head))
    pull_requests = iter(
        (
            [],
            [
                {
                    "number": 19,
                    "url": "https://github.com/example/repository/pull/19",
                    "state": "OPEN",
                    "headRefOid": accepted_head,
                    "baseRefName": "main",
                    "mergedAt": None,
                }
            ],
        )
    )
    monkeypatch.setattr("tether_agent.publication._run", run)
    monkeypatch.setattr(
        "tether_agent.publication._ahead_behind",
        lambda *_args: (2, 3),
    )
    monkeypatch.setattr(
        "tether_agent.publication._remote_head",
        lambda *_args: next(remote_heads),
    )
    monkeypatch.setattr(
        "tether_agent.publication._pull_requests",
        lambda *_args: next(pull_requests),
    )

    result = publish_github_pull_request(
        repository=tmp_path,
        remote_name="origin",
        remote_url="https://github.com/example/repository.git",
        upstream_ref="refs/remotes/origin/main",
        branch_name="feat/codex/task-run",
        accepted_head=accepted_head,
        title="Task",
        run_id="run",
    )

    push = next(command for command in commands if command[:2] == ["git", "push"])
    assert "--force" not in push
    assert "--force-with-lease" not in push
    assert push[-1] == "refs/heads/feat/codex/task-run:refs/heads/feat/codex/task-run"
    assert not any("rebase" in command or "reset" in command for command in commands)
    assert result.state == "published"
    assert result.ahead_count == 2
    assert result.behind_count == 3
