"""Read repository sources through directory descriptors without following links."""

from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath


class SourceReadLimitError(ValueError):
    """A bounded source read encountered more bytes than its admitted limit."""


def read_source_bytes(root: Path, relative_path: str, *, max_bytes: int | None = None) -> bytes:
    if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 0):
        raise ValueError("source byte limit must be a nonnegative integer")
    parts = PurePosixPath(relative_path).parts
    if not parts or PurePosixPath(relative_path).is_absolute() or ".." in parts:
        raise ValueError("source path must be relative to the repository")
    directory = os.open(root.resolve(strict=True), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory,
            )
            os.close(directory)
            directory = child
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=directory,
        )
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("repository source is not a regular file")
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = source.read() if max_bytes is None else source.read(max_bytes + 1)
                if max_bytes is not None and len(raw) > max_bytes:
                    raise SourceReadLimitError("source exceeds the admitted byte limit")
                return raw
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)
