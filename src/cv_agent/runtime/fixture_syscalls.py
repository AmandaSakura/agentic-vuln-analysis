"""Pure syscall isolation shared by fixture and environment workers."""

from __future__ import annotations

import ctypes
import errno
import os


def _install_fixture_isolation(
    result_fd: int, *, retained_fds: tuple[int, ...] = (), accept_only: bool = False,
    deny_exec: bool = False,
) -> None:
    """Close inherited descriptors and deny selected syscalls before fixture code runs."""

    devnull_fd = os.open(os.devnull, os.O_RDWR)
    try:
        for fd in (0, 1, 2):
            if fd != result_fd:
                os.dup2(devnull_fd, fd)
    finally:
        if devnull_fd > 2 and devnull_fd != result_fd:
            os.close(devnull_fd)

    for raw_fd in os.listdir("/proc/self/fd"):
        fd = int(raw_fd)
        if fd > 2 and fd != result_fd and fd not in retained_fds:
            try:
                os.close(fd)
            except OSError:
                pass

    seccomp = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    seccomp.seccomp_rule_add.restype = ctypes.c_int
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_load.restype = ctypes.c_int
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.restype = None

    allow = 0x7FFF0000
    deny = 0x00050000 | errno.EPERM
    context = seccomp.seccomp_init(allow)
    if not context:
        raise RuntimeError("could not initialize fixture seccomp isolation")
    try:
        denied_syscalls = (
            b"socket",
            b"socketpair",
            b"connect",
            b"bind",
            b"listen",
            b"accept",
            b"accept4",
            b"sendto",
            b"sendmsg",
            b"recvfrom",
            b"recvmsg",
        )
        if deny_exec:
            denied_syscalls += (b"execve", b"execveat")
        for name in denied_syscalls:
            if accept_only and name in {
                b"accept", b"accept4", b"sendto", b"sendmsg", b"recvfrom", b"recvmsg",
            }:
                # Only the pre-bound loopback listener and result pipe survive.
                # New sockets and outgoing connections are still denied.
                continue
            syscall = seccomp.seccomp_syscall_resolve_name(name)
            if syscall < 0:
                if deny_exec and name in {b"execve", b"execveat"}:
                    raise RuntimeError(
                        f"could not resolve fixture seccomp syscall {name.decode()}"
                    )
                continue
            result = seccomp.seccomp_rule_add(context, deny, syscall, 0)
            if result != 0:
                raise RuntimeError(
                    f"could not add fixture seccomp rule for {name.decode()}"
                )
        if seccomp.seccomp_load(context) != 0:
            raise RuntimeError("could not load fixture seccomp isolation")
    finally:
        seccomp.seccomp_release(context)

    if deny_exec:
        # This must run after loading seccomp, before any target import or audit hook.
        # Successful execution replaces this worker, so the parent gets no result.
        try:
            os.execv("/bin/true", ["/bin/true"])
        except OSError as error:
            if error.errno != errno.EPERM:
                raise RuntimeError("fixture exec isolation self-test failed") from error
        else:
            raise RuntimeError("fixture exec isolation self-test unexpectedly returned")
