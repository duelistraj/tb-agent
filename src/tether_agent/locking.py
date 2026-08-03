"""Portable advisory locks for one profile."""

from __future__ import annotations

import os
from pathlib import Path
from types import TracebackType
from typing import Self

from tether_agent.secure_files import (
    FILE_MODE,
    ensure_private_directory,
    secure_descriptor,
)


class LockUnavailable(RuntimeError):
    """Raised when another process holds a requested profile lock."""


class ProfileLock:
    def __init__(self, path: Path, *, label: str) -> None:
        self.path = path
        self.label = label
        self._descriptor: int | None = None

    def acquire(self, *, blocking: bool = False) -> None:
        if self._descriptor is not None:
            return
        ensure_private_directory(self.path.parent)
        if self.path.is_symlink():
            raise PermissionError(f"Refusing to use symlinked lock file: {self.path}")
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags, FILE_MODE)
        secure_descriptor(descriptor, self.path)
        if os.name == "nt" and os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            self._lock(descriptor, blocking=blocking)
        except BaseException:
            os.close(descriptor)
            raise
        self._descriptor = descriptor

    @staticmethod
    def _lock(descriptor: int, *, blocking: bool) -> None:
        if os.name == "nt":
            import msvcrt

            mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, mode, 1)
            except OSError as error:
                raise LockUnavailable("Profile lock is already held") from error
            return

        import fcntl

        operation = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(descriptor, operation)
        except BlockingIOError as error:
            raise LockUnavailable("Profile lock is already held") from error

    def release(self) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
            self._descriptor = None

    def __enter__(self) -> Self:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        self.release()

    @classmethod
    def is_locked(cls, path: Path) -> bool:
        probe = cls(path, label="profile")
        try:
            probe.acquire()
        except LockUnavailable:
            return True
        else:
            probe.release()
            return False
