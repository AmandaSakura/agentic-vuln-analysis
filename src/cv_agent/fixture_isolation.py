"""Linux filesystem restrictions for registered validation callbacks."""

from __future__ import annotations

import ctypes
import os
import platform
import stat
from pathlib import Path


def restrict_fixture_filesystem(read_roots: tuple[Path, ...]) -> None:
    """Deny file reads outside registered roots and deny all filesystem writes.

    Landlock ABI 3 is required because earlier ABIs do not restrict truncation.
    Called only in the disposable child after inherited descriptors are closed.
    """
    if platform.machine() not in {"x86_64", "aarch64"}:
        raise RuntimeError("fixture filesystem isolation requires supported Linux syscalls")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(444, 0, 0, 1)
    if abi < 3:
        raise RuntimeError("fixture filesystem isolation requires Landlock ABI >= 3")

    class Ruleset(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    class PathRule(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int)]

    def checked(result: int, operation: str) -> int:
        if result < 0:
            error = ctypes.get_errno()
            raise OSError(error, f"fixture Landlock {operation}: {os.strerror(error)}")
        return result

    # ABI 3 filesystem rights: execute, read, write, creation, removal, rename,
    # and truncate. Only explicitly granted READ_FILE/READ_DIR remain available.
    attributes = Ruleset((1 << 15) - 1)
    ruleset = checked(libc.syscall(444, ctypes.byref(attributes), ctypes.sizeof(attributes), 0), "create")
    try:
        for root in read_roots:
            descriptor = os.open(Path(root).resolve(strict=True), os.O_PATH | os.O_CLOEXEC)
            try:
                access = 1 << 2  # READ_FILE
                if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                    access |= 1 << 3  # READ_DIR
                rule = PathRule(access, descriptor)
                checked(libc.syscall(445, ruleset, 1, ctypes.byref(rule), 0), "add read root")
            finally:
                os.close(descriptor)
        checked(libc.prctl(38, 1, 0, 0, 0), "set no_new_privs")
        checked(libc.syscall(446, ruleset, 0), "restrict")
    finally:
        os.close(ruleset)
