"""Descriptor-based bounded reads for untrusted project files."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class SafeReadError(OSError):
    """A file could not be read within the declared safety boundary."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def read_bounded_bytes(
    path: Path,
    max_bytes: int,
    *,
    root: Path | None = None,
) -> bytes:
    """Read one regular non-symlink file through a bounded descriptor."""
    path = Path(path)
    if max_bytes < 0:
        raise ValueError("max_bytes must not be negative")
    if root is not None:
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(Path(root).resolve(strict=True))
        except FileNotFoundError:
            raise
        except (OSError, ValueError) as error:
            raise SafeReadError("outside_project_root") from error

    try:
        before = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as error:
        raise SafeReadError("stat_failed") from error
    if stat.S_ISLNK(before.st_mode):
        raise SafeReadError("symbolic_link")
    if not stat.S_ISREG(before.st_mode):
        raise SafeReadError("not_regular_file")
    if before.st_size > max_bytes:
        raise SafeReadError("too_large")

    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SafeReadError("not_regular_file")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise SafeReadError("file_changed")
        if opened.st_size > max_bytes:
            raise SafeReadError("too_large")
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > max_bytes:
            raise SafeReadError("too_large")
        return content
    except SafeReadError:
        raise
    except OSError as error:
        raise SafeReadError("read_failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_bounded_text(
    path: Path,
    max_bytes: int,
    *,
    root: Path | None = None,
) -> str:
    """Read one bounded file as strict UTF-8 text."""
    try:
        return read_bounded_bytes(path, max_bytes, root=root).decode("utf-8")
    except UnicodeDecodeError as error:
        raise SafeReadError("undecodable") from error

