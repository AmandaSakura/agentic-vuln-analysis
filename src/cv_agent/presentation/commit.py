"""Local Linux publication with atomic no-replace rename and ordered syncing.

These guarantees require a filesystem implementing renameat2 and directory
fsync. They do not establish crash durability on every network filesystem.
The staging tree is owned by the exporter; symlinks and special files are not
accepted as staged evidence.
"""
from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import stat
import sys


class DirectoryCommitDurabilityError(OSError):
    """Publication succeeded; the final parent-directory sync did not.

    The complete output is visible and must not be retried at the same path or
    described as absent. Its survival after a filesystem crash is unconfirmed.
    """

    committed = True

    def __init__(self, output: Path, cause: OSError):
        self.output = output
        super().__init__(cause.errno or errno.EIO,
            "Complete output was published, but its directory durability is unconfirmed",
            os.fspath(output))


def fsync_directory(path: Path) -> None:
    """Synchronize a real directory, rejecting a symlink at this path."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _sync_tree(path: Path) -> None:
    for entry in sorted(path.iterdir(), key=lambda item: item.name):
        kind = entry.lstat().st_mode
        if stat.S_ISDIR(kind):
            _sync_tree(entry)
        elif stat.S_ISREG(kind):
            fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        else:
            raise OSError(errno.EINVAL, "Staged output must contain only regular files and directories",
                          os.fspath(entry))
    fsync_directory(path)


def _rename_no_replace(staging: Path, output: Path) -> None:
    if sys.platform != "linux":
        raise OSError(errno.ENOTSUP, "Atomic no-replace output commit requires Linux renameat2")
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as error:
        raise OSError(errno.ENOSYS, "Linux libc does not expose renameat2; output commit is unavailable") from error
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    # AT_FDCWD uses the supplied paths. RENAME_NOREPLACE checks destination
    # nonexistence inside the same atomic kernel operation as the rename.
    if renameat2(-100, os.fsencode(staging), -100, os.fsencode(output), 1) != 0:
        code = ctypes.get_errno()
        raise OSError(code, "Atomic no-replace output commit failed: " + os.strerror(code), os.fspath(output))


def commit_directory(staging: Path, output: Path) -> None:
    """Publish an exporter-owned staged set once, without replacing any target.

    All staged file contents and child directory entries are synchronized
    before publication. The parent is synchronized before and after the rename.
    Any precommit error leaves the output uncreated by this function. A final
    sync failure raises DirectoryCommitDurabilityError with committed=True.
    No replacing rename fallback is permitted on an unsupported platform.
    """
    if sys.platform != "linux":
        raise OSError(errno.ENOTSUP, "Atomic no-replace output commit requires Linux renameat2")
    if not stat.S_ISDIR(staging.lstat().st_mode):
        raise OSError(errno.EINVAL, "Output staging must be a real directory", os.fspath(staging))
    _sync_tree(staging)
    fsync_directory(output.parent)
    _rename_no_replace(staging, output)
    try:
        fsync_directory(output.parent)
    except OSError as error:
        raise DirectoryCommitDurabilityError(output, error) from error
