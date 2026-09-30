"""Read-denial diagnostics from an external tracer, never candidate proof.

The tracer remains outside the worker's filesystem and syscall restrictions.
Its log describes attempted syscalls only; an import failure prevents observing
later accesses. EACCES alone does not identify which security policy denied it.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
from typing import Any


_STRACE = Path("/usr/bin/strace")
_TRACE_LIMIT = 16 * 1024 * 1024
_SYSCALLS = (
    "open,openat,openat2,chdir,fchdir,clone,clone3,fork,vfork,"
    "landlock_restrict_self"
)
_PREFIX = re.compile(r"^(?:\[pid\s+(\d+)\]\s+|(\d+)\s+)?(.*)$")
_CALL = re.compile(r"^(\w+)\((.*)\)\s+=\s+(.*)$")
_QUOTED = re.compile(r'^"((?:[^"\\]|\\.)*)"$')


def trace_command(command: list[str], trace_path: Path) -> list[str]:
    """Create a private, new log and return argv for the installed tracer.

    The caller owns process launch, deadlines, and process-group termination.
    Existing logs are never replaced. No shell evaluates any command argument.
    """
    if not command or not all(isinstance(arg, str) for arg in command):
        raise ValueError("trace command requires nonempty string argv")
    if not _STRACE.is_file() or not os.access(_STRACE, os.X_OK):
        raise FileNotFoundError("isolation_read_tracer_unavailable:/usr/bin/strace")
    descriptor = os.open(
        trace_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600,
    )
    os.close(descriptor)
    return [str(_STRACE), "-f", "-qq", "-yy", "-xx", "-s", "4096", "-e",
            f"trace={_SYSCALLS}", "-o", str(trace_path), "--", *command]


def _c_text(text: str) -> str:
    """Decode strace C escapes as filesystem bytes, without evaluating code."""
    data = bytearray()
    index = 0
    escapes = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12,
               "r": 13, '"': 34, "\\": 92}
    while index < len(text):
        char = text[index]
        index += 1
        if char != "\\":
            data.extend(os.fsencode(char))
            continue
        if index == len(text):
            raise ValueError("unterminated C escape")
        char = text[index]
        index += 1
        if char == "x":
            digits = text[index:index + 2]
            if len(digits) != 2 or not re.fullmatch(r"[0-9a-fA-F]{2}", digits):
                raise ValueError("invalid hex escape")
            data.append(int(digits, 16))
            index += 2
        elif char in "01234567":
            digits = char
            while index < len(text) and len(digits) < 3 and text[index] in "01234567":
                digits += text[index]
                index += 1
            value = int(digits, 8)
            if value > 255:
                raise ValueError("invalid octal escape")
            data.append(value)
        elif char in escapes:
            data.append(escapes[char])
        else:
            raise ValueError("unknown C escape")
    return os.fsdecode(bytes(data))


def _arguments(text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    quote = False
    escaped = False
    nested: list[str] = []
    closing = {"(": ")", "[": "]", "{": "}", "<": ">"}
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            quote = not quote
            continue
        if quote:
            continue
        if char in closing:
            nested.append(closing[char])
        elif nested and char == nested[-1]:
            nested.pop()
        elif char == "," and not nested:
            parts.append(text[start:index].strip())
            start = index + 1
    if quote or escaped or nested:
        raise ValueError("unterminated syscall arguments")
    parts.append(text[start:].strip())
    return parts


def _quoted(token: str) -> str:
    if token.endswith("..."):
        raise ValueError("truncated path")
    match = _QUOTED.fullmatch(token)
    if match is None:
        raise ValueError("path is not a complete C string")
    path = _c_text(match[1])
    if "\x00" in path:
        raise ValueError("embedded NUL in path")
    return path


def _fd_path(token: str) -> Path | None:
    match = re.fullmatch(r"(?:AT_FDCWD|\d+)<(.+)>", token)
    if match is None:
        return None
    name = _c_text(match[1])
    if name.endswith(" (deleted)") or not name.startswith("/"):
        return None
    return Path(name)


def _absolute_path(requested: str, base: Path | None, pid: int | None) -> Path:
    path = Path(requested)
    if not path.is_absolute():
        if base is None:
            raise ValueError("relative path lacks observed cwd or dirfd")
        path = base / path
    # /proc/self identifies the tracee, not this parent doing the host probe.
    parts = path.parts
    if len(parts) >= 3 and parts[1] == "proc" and parts[2] in {"self", "thread-self"}:
        if pid is None or parts[2] == "thread-self":
            raise ValueError("dynamic proc path lacks a resolved tracee identity")
        path = Path("/proc") / str(pid) / Path(*parts[3:])
    return path.resolve()


def _granted(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or (root.is_dir() and path.is_relative_to(root)) for root in roots)


def _host_open(path: Path) -> tuple[bool, int | None]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as error:
        return False, error.errno
    os.close(descriptor)
    return True, None


def _joined_records(text: str) -> tuple[list[tuple[int, int | None, str]], list[str]]:
    """Join ordinary strace interleaving, retaining each syscall's start order."""
    records: list[tuple[int, int | None, str]] = []
    pending: dict[int | None, tuple[int, str, str]] = {}
    gaps: list[str] = []
    for index, line in enumerate(text.splitlines()):
        prefix = _PREFIX.fullmatch(line)
        assert prefix is not None
        pid = int(prefix[1] or prefix[2]) if prefix[1] or prefix[2] else None
        body = prefix[3]
        if body.endswith("<unfinished ...>"):
            start = re.match(r"(\w+)\(", body)
            if start is None or pid in pending:
                gaps.append("isolation_trace_incomplete_syscall")
            if start is not None:
                pending[pid] = (index, start[1], body.removesuffix("<unfinished ...>").rstrip())
            continue
        resumed = re.match(r"<\.\.\. (\w+) resumed>(.*)$", body)
        if resumed is not None:
            original = pending.pop(pid, None)
            if original is None or original[1] != resumed[1]:
                gaps.append("isolation_trace_incomplete_syscall")
            else:
                records.append((original[0], pid, original[2] + resumed[2]))
            continue
        records.append((index, pid, body))
    if pending:
        gaps.append("isolation_trace_incomplete_syscall")
    # A child can execute before its parent's clone return is printed. Ordering
    # by clone entry makes the inherited Landlock boundary available first.
    records.sort(key=lambda record: record[0])
    return records, gaps


def summarize_trace(trace_path: Path, read_roots: tuple[Path, ...]) -> dict[str, Any]:
    """Report observed read denials and explicit limits on their attribution."""
    summary: dict[str, Any] = {
        "observed_only": True, "read_denials": [], "gaps": [],
        "trace_sha256": None, "trace_size": None,
    }
    try:
        summary["trace_size"] = trace_path.stat().st_size
        if summary["trace_size"] > _TRACE_LIMIT:
            summary["gaps"] = ["isolation_trace_too_large"]
            return summary
        with trace_path.open("rb") as stream:
            encoded = stream.read(_TRACE_LIMIT + 1)
        if len(encoded) > _TRACE_LIMIT:
            summary["gaps"] = ["isolation_trace_too_large"]
            return summary
        summary["trace_size"] = len(encoded)
        summary["trace_sha256"] = hashlib.sha256(encoded).hexdigest()
        text = encoded.decode("utf-8", errors="surrogateescape")
        roots = tuple(root.resolve() for root in read_roots)
    except (OSError, RuntimeError):
        summary["gaps"] = ["isolation_trace_unreadable"]
        return summary

    def gap(name: str) -> None:
        if name not in summary["gaps"]:
            summary["gaps"].append(name)

    restricted: set[int | None] = set()
    cwd: dict[int | None, Path] = {}
    records: dict[tuple[int | None, str, str, str], dict[str, Any]] = {}
    if text and not text.endswith("\n"):
        gap("isolation_trace_truncated_log")
    joined, joining_gaps = _joined_records(text)
    for name in joining_gaps:
        gap(name)
    for _, pid, body in joined:
        if not body.strip():
            continue
        if body.startswith("strace:"):
            gap("isolation_trace_tracer_error")
            continue
        if body.startswith("<... "):
            gap("isolation_trace_incomplete_syscall")
            continue
        if body.startswith("+++ killed by"):
            gap("isolation_trace_process_killed")
            continue
        if body.startswith(("+++", "---")):
            continue
        call = _CALL.fullmatch(body)
        if call is None:
            gap("isolation_trace_unparsed_line")
            continue
        syscall, arguments, result = call.groups()
        if syscall == "landlock_restrict_self":
            if result == "0":
                restricted.add(pid)
            continue
        if syscall in {"clone", "clone3", "fork", "vfork"} and result.isdecimal():
            child = int(result)
            if pid in restricted:
                restricted.add(child)
            if pid in cwd:
                cwd[child] = cwd[pid]
            continue
        try:
            args = _arguments(arguments)
            if syscall in {"chdir", "fchdir"} and result == "0":
                target = (_absolute_path(_quoted(args[0]), cwd.get(pid), pid)
                          if syscall == "chdir" else _fd_path(args[0]))
                if target is None:
                    gap("isolation_trace_path_unresolved")
                else:
                    cwd[pid] = target
                continue
            if pid not in restricted or syscall not in {"open", "openat", "openat2"}:
                continue
            if not re.match(r"-1\s+EACCES(?:\s|$)", result):
                continue
            path_index, flags_index = (0, 1) if syscall == "open" else (1, 2)
            flags = args[flags_index]
            if syscall == "openat2":
                found_flags = re.search(r"(?:\{|,)\s*flags=([^,}]+)", flags)
                if found_flags is None:
                    gap("isolation_trace_open_flags_unresolved")
                    continue
                flags = found_flags[1]
            rights = set(flags.split("|"))
            if "O_RDONLY" not in rights or rights.intersection({
                "O_PATH", "O_RDWR", "O_WRONLY", "O_CREAT", "O_TRUNC", "O_TMPFILE",
            }):
                continue
            requested = _quoted(args[path_index])
            base = cwd.get(pid) if syscall == "open" else _fd_path(args[0])
            canonical = _absolute_path(requested, base, pid)
        except (ValueError, IndexError, OSError, RuntimeError) as error:
            gap("isolation_trace_truncated_path" if str(error) == "truncated path"
                else "isolation_trace_path_unresolved")
            continue
        key = (pid, syscall, requested, str(canonical))
        if key in records:
            records[key]["count"] += 1
            continue
        readable, host_errno = _host_open(canonical)
        attributed = readable and not _granted(canonical, roots)
        name = f"{'isolation_read_denied' if attributed else 'read_access_denied'}:{canonical}"
        records[key] = {
            "gap": name, "path": str(canonical), "canonical_path": str(canonical),
            "requested_path": requested, "host_open_succeeded": readable,
            "host_open_errno": host_errno, "syscall": syscall, "pid": pid, "count": 1,
        }
        gap(name)
    if not restricted:
        gap("isolation_trace_boundary_missing")
    summary["read_denials"] = list(records.values())
    return summary
