"""Secure local file creation and atomic replacement helpers."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

DIRECTORY_MODE = 0o700
FILE_MODE = 0o600


def secure_descriptor(descriptor: int, path: Path, mode: int = FILE_MODE) -> None:
    if os.name == "nt":
        # Windows permissions are ACL-based. Python 3.14 exposes fchmod on
        # Windows, but applying it to the read-only descriptors used to verify
        # SQLite sidecars fails with Access Denied and does not secure the ACL.
        return
    if hasattr(os, "fchmod"):
        os.fchmod(descriptor, mode)
    else:
        path.chmod(mode)


def _owner_uid(path: Path) -> int | None:
    if not hasattr(os, "getuid"):
        return None
    return path.stat(follow_symlinks=False).st_uid


def ensure_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise PermissionError(f"Refusing to use symlinked profile directory: {path}")
    path.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode):
        raise PermissionError(f"Profile path is not a directory: {path}")
    owner_uid = _owner_uid(path)
    if owner_uid is not None and owner_uid != os.getuid():
        raise PermissionError(
            f"Profile directory is not owned by the current user: {path}"
        )
    path.chmod(DIRECTORY_MODE)


def validate_private_file(path: Path, *, allow_missing: bool = True) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return
        raise FileNotFoundError(path)
    if stat.S_ISLNK(metadata.st_mode):
        raise PermissionError(f"Refusing to use symlinked private file: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise PermissionError(f"Private path is not a regular file: {path}")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise PermissionError(f"Private file is not owned by the current user: {path}")
    # Windows exposes synthesized POSIX mode bits that do not represent the
    # file's ACL. Applying the Unix 0600 test there rejects files created by
    # this process even after chmod. Symlink and regular-file validation still
    # apply on Windows; ownership and mode enforcement apply where the OS
    # exposes real Unix ownership and permission semantics.
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise PermissionError(f"Private file permissions must be 0600: {path}")


def harden_private_file(path: Path, *, allow_missing: bool = True) -> None:
    """Restrict an existing, user-owned regular file to the private file mode."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return
        raise FileNotFoundError(path)
    if stat.S_ISLNK(metadata.st_mode):
        raise PermissionError(f"Refusing to use symlinked private file: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise PermissionError(f"Private path is not a regular file: {path}")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise PermissionError(f"Private file is not owned by the current user: {path}")
    if os.name == "nt":
        return

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode):
            raise PermissionError(f"Private path is not a regular file: {path}")
        if hasattr(os, "getuid") and opened_metadata.st_uid != os.getuid():
            raise PermissionError(
                f"Private file is not owned by the current user: {path}"
            )
        if (opened_metadata.st_dev, opened_metadata.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            raise PermissionError(f"Private file changed while securing it: {path}")
        secure_descriptor(descriptor, path)
    finally:
        os.close(descriptor)
    validate_private_file(path, allow_missing=False)


def atomic_write(
    path: Path,
    content: bytes,
    *,
    mode: int = FILE_MODE,
    private_parent: bool = True,
) -> None:
    if private_parent:
        ensure_private_directory(path.parent)
        validate_private_file(path)
    else:
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if path.is_symlink():
            raise PermissionError(f"Refusing to replace symlinked file: {path}")
        if path.exists():
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise PermissionError(f"Path is not a regular file: {path}")
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise PermissionError(f"File is not owned by the current user: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        secure_descriptor(descriptor, temporary, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        path.chmod(mode)
        if os.name != "nt":
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise
