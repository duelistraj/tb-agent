"""Local worktree lifecycle with conservative, dirty-safe cleanup."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from tether_agent.config import ProjectMapping, WorktreePolicy


@dataclass(frozen=True)
class CleanupDecision:
    removable: bool
    reason: str


class WorktreeManager:
    def __init__(self, policy: WorktreePolicy) -> None:
        self.policy = policy

    def working_directory(
        self, mapping: ProjectMapping, run_id: UUID, requested_ref: str | None
    ) -> Path:
        if mapping.access == "read":
            return mapping.local_path
        root = mapping.worktree_root or mapping.local_path.parent / ".tether-worktrees"
        path = root / str(mapping.project_id) / str(run_id)
        if path.exists():
            return path
        root.mkdir(parents=True, exist_ok=True)
        command = ["git", "-C", str(mapping.local_path), "worktree", "add"]
        if requested_ref:
            command.extend(["--detach", str(path), requested_ref])
        else:
            command.extend(["--detach", str(path), "HEAD"])
        subprocess.run(command, check=True)
        return path

    def is_dirty(self, path: Path) -> bool:
        result = subprocess.run(
            ["git", "-C", str(path), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        )
        return bool(result.stdout.strip())

    def cleanup_decision(
        self,
        *,
        path: Path,
        state: str,
        accepted: bool,
        pinned: bool,
        finished_at: datetime,
        now: datetime | None = None,
    ) -> CleanupDecision:
        if pinned:
            return CleanupDecision(False, "worktree is pinned")
        if self.is_dirty(path):
            return CleanupDecision(
                False, "worktree has uncommitted or untracked changes"
            )
        current = now or datetime.now(UTC)
        if state == "review" and not accepted:
            return CleanupDecision(False, "review work is awaiting acceptance")
        if state == "review" and self.policy.review_retention == "manual":
            return CleanupDecision(False, "review work uses manual cleanup")
        hours = (
            self.policy.accepted_retention_hours
            if accepted
            else self.policy.cancelled_retention_hours
            if state == "cancelled"
            else self.policy.failed_retention_hours
        )
        if current < finished_at + timedelta(hours=hours):
            return CleanupDecision(False, "retention period has not expired")
        return CleanupDecision(True, "retention expired and worktree is clean")

    def remove(self, repository: Path, path: Path) -> None:
        if self.is_dirty(path):
            raise RuntimeError("Refusing to remove a dirty worktree")
        subprocess.run(
            ["git", "-C", str(repository), "worktree", "remove", str(path)],
            check=True,
        )
