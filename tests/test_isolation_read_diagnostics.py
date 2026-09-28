"""Observed syscall denials must not be inferred from pre-call audit events."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from cv_agent.evaluation.diagnostics.isolation_read_diagnostics import (
    summarize_trace,
    trace_command,
)


def _trace(tmp_path: Path, text: str, roots: tuple[Path, ...] = ()) -> dict:
    path = tmp_path / "trace.log"
    path.write_text(text)
    return summarize_trace(path, roots)


def test_only_post_install_read_denials_are_isolation_gaps(tmp_path: Path):
    outside = tmp_path / "outside.txt"
    outside.write_text("not read by the diagnostic")
    text = (
        f'123 openat(AT_FDCWD</tmp>, "{outside}", O_RDONLY) = -1 EACCES (Permission denied)\n'
        '123 landlock_restrict_self(3, 0) = 0\n'
        f'123 openat(AT_FDCWD</tmp>, "{outside}", O_RDONLY|O_CLOEXEC) = -1 EACCES (Permission denied)\n'
        f'123 openat(AT_FDCWD</tmp>, "{outside}", O_RDONLY) = -1 EACCES (Permission denied)\n'
    )
    result = _trace(tmp_path, text)
    assert result["observed_only"] is True
    assert result["trace_sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert result["trace_size"] == len(text.encode())
    assert result["read_denials"] == [{
        "gap": f"isolation_read_denied:{outside}",
        "path": str(outside), "canonical_path": str(outside), "requested_path": str(outside),
        "host_open_succeeded": True, "host_open_errno": None,
        "syscall": "openat", "pid": 123, "count": 2,
    }]
    assert result["gaps"] == [f"isolation_read_denied:{outside}"]


@pytest.mark.parametrize("dirfd", ["AT_FDCWD", "7"])
def test_relative_yy_paths_decode_spaces_quotes_and_utf8(tmp_path: Path, dirfd: str):
    root = tmp_path / "space dir"
    root.mkdir()
    name = 'café "quoted".txt'
    (root / name).write_text("payload")
    encoded = r'caf\303\251 \"quoted\".txt'
    result = _trace(tmp_path, (
        '[pid 123] landlock_restrict_self(3, 0) = 0\n'
        f'[pid 123] openat({dirfd}<{root}>, "{encoded}", O_RDONLY) = -1 EACCES (Permission denied)\n'
    ))
    record = result["read_denials"][0]
    assert record["canonical_path"] == str(root / name)
    assert record["requested_path"] == name
    assert record["gap"] == f"isolation_read_denied:{root / name}"


def test_open_and_openat2_and_native_thread_denials(tmp_path: Path):
    outside = tmp_path / "native.txt"
    outside.write_text("payload")
    result = _trace(tmp_path, (
        '123 landlock_restrict_self(3, 0) = 0\n'
        '123 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD) = 124\n'
        f'124 open("{outside}", O_RDONLY) = -1 EACCES (Permission denied)\n'
        f'123 openat2(AT_FDCWD</tmp>, "{outside}", {{flags=O_RDONLY|O_CLOEXEC, resolve=0}}, 24) = -1 EACCES (Permission denied)\n'
    ))
    assert {(row["pid"], row["syscall"]) for row in result["read_denials"]} == {
        (124, "open"), (123, "openat2"),
    }


def test_interleaved_clones_and_open_resumes_preserve_restriction_lineage(tmp_path: Path):
    outside = tmp_path / "thread.txt"
    outside.write_text("payload")
    result = _trace(tmp_path, (
        '123 landlock_restrict_self(3, 0) = 0\n'
        '123 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD <unfinished ...>\n'
        f'124 openat(AT_FDCWD</tmp>, "{outside}", O_RDONLY <unfinished ...>\n'
        '123 <... clone resumed>) = 124\n'
        '124 <... openat resumed>) = -1 EACCES (Permission denied)\n'
    ))
    assert result["read_denials"][0]["pid"] == 124
    assert result["gaps"] == [f"isolation_read_denied:{outside}"]


def test_unrestricted_preexisting_thread_is_not_assumed_restricted(tmp_path: Path):
    outside = tmp_path / "thread.txt"
    outside.write_text("payload")
    result = _trace(tmp_path, (
        '123 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD) = 124\n'
        '123 landlock_restrict_self(3, 0) = 0\n'
        f'124 open("{outside}", O_RDONLY) = -1 EACCES (Permission denied)\n'
    ))
    assert result["read_denials"] == []
    assert result["gaps"] == []


def test_full_hex_path_and_yy_dirfd_annotation(tmp_path: Path):
    directory = tmp_path / "café path"
    directory.mkdir()
    (directory / "file").write_text("payload")
    encoded_directory = "".join(f"\\x{byte:02x}" for byte in os.fsencode(directory))
    encoded_name = r"\x66\x69\x6c\x65"
    result = _trace(tmp_path, (
        '123 landlock_restrict_self(3, 0) = 0\n'
        f'123 openat(7<{encoded_directory}>, "{encoded_name}", O_RDONLY) = -1 EACCES\n'
    ))
    assert result["read_denials"][0]["canonical_path"] == str(directory / "file")


@pytest.mark.parametrize("flags,result", [
    ("O_PATH", "-1 EACCES (Permission denied)"),
    ("O_WRONLY", "-1 EACCES (Permission denied)"),
    ("O_RDWR", "-1 EACCES (Permission denied)"),
    ("O_RDONLY|O_CREAT", "-1 EACCES (Permission denied)"),
    ("O_RDONLY|O_TRUNC", "-1 EACCES (Permission denied)"),
    ("O_RDONLY", "-1 ENOENT (No such file or directory)"),
    ("O_RDONLY", "-1 EPERM (Operation not permitted)"),
    ("O_RDONLY", "5</tmp/file>"),
])
def test_writes_missing_paths_and_other_results_are_not_read_denials(
    tmp_path: Path, flags: str, result: str,
):
    summary = _trace(tmp_path, (
        'landlock_restrict_self(3, 0) = 0\n'
        f'openat(AT_FDCWD</tmp>, "/tmp/file", {flags}) = {result}\n'
    ))
    assert summary["read_denials"] == []
    assert summary["gaps"] == []


def test_existing_grant_and_unreadable_host_path_do_not_claim_landlock(tmp_path: Path):
    existing = tmp_path / "existing.txt"
    existing.write_text("payload")
    missing = tmp_path / "missing.txt"
    summary = _trace(tmp_path, (
        '123 landlock_restrict_self(3, 0) = 0\n'
        f'123 open("{existing}", O_RDONLY) = -1 EACCES (Permission denied)\n'
        f'123 open("{missing}", O_RDONLY) = -1 EACCES (Permission denied)\n'
    ), (existing,))
    assert [row["gap"] for row in summary["read_denials"]] == [
        f"read_access_denied:{existing}", f"read_access_denied:{missing}",
    ]
    assert summary["read_denials"][1]["host_open_succeeded"] is False


def test_symlink_target_inside_grant_is_not_misattributed(tmp_path: Path):
    grant = tmp_path / "grant"
    grant.mkdir()
    target = grant / "target"
    target.write_text("payload")
    alias = tmp_path / "alias"
    alias.symlink_to(target)
    summary = _trace(tmp_path, (
        '123 landlock_restrict_self(3, 0) = 0\n'
        f'123 open("{alias}", O_RDONLY) = -1 EACCES (Permission denied)\n'
    ), (grant,))
    assert summary["read_denials"][0]["canonical_path"] == str(target)
    assert summary["read_denials"][0]["gap"] == f"read_access_denied:{target}"


@pytest.mark.parametrize("text,gap", [
    ('openat(AT_FDCWD</tmp>, "/tmp/file", O_RDONLY) = -1 EACCES\n', "isolation_trace_boundary_missing"),
    ('landlock_restrict_self(3, 0) = -1 EPERM\n', "isolation_trace_boundary_missing"),
    ('landlock_restrict_self(3, 0) = 0\nopenat(AT_FDCWD, "relative", O_RDONLY) = -1 EACCES\n', "isolation_trace_path_unresolved"),
    ('landlock_restrict_self(3, 0) = 0\nopenat(AT_FDCWD</tmp>, "/long"..., O_RDONLY) = -1 EACCES\n', "isolation_trace_truncated_path"),
    ('landlock_restrict_self(3, 0) = 0\nopenat(AT_FDCWD</tmp>, "/file", O_RDONLY <unfinished ...>\n', "isolation_trace_incomplete_syscall"),
    ('landlock_restrict_self(3, 0) = 0\n<... openat resumed>) = -1 EACCES\n', "isolation_trace_incomplete_syscall"),
    ('landlock_restrict_self(3, 0) = 0\nstrace: ptrace: Operation not permitted\n', "isolation_trace_tracer_error"),
    ('landlock_restrict_self(3, 0) = 0\n???\n', "isolation_trace_unparsed_line"),
])
def test_incomplete_diagnostics_are_explicit(tmp_path: Path, text: str, gap: str):
    summary = _trace(tmp_path, text)
    assert gap in summary["gaps"]
    assert summary["read_denials"] == []


def test_relative_open_uses_observed_chdir(tmp_path: Path):
    path = tmp_path / "file"
    path.write_text("payload")
    summary = _trace(tmp_path, (
        f'123 chdir("{tmp_path}") = 0\n'
        '123 landlock_restrict_self(3, 0) = 0\n'
        '123 open("file", O_RDONLY) = -1 EACCES\n'
    ))
    assert summary["read_denials"][0]["canonical_path"] == str(path)


def test_host_probe_is_read_only_nonblocking_and_never_reads_data(tmp_path: Path, monkeypatch):
    path = tmp_path / "file"
    path.write_text("payload")
    original_open = os.open
    probes = []

    def checked_open(name, flags, *args, **kwargs):
        probes.append((name, flags))
        return original_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", checked_open)
    monkeypatch.setattr(os, "read", lambda *_: pytest.fail("must not read file content"))
    summary = _trace(tmp_path, (
        'landlock_restrict_self(3, 0) = 0\n'
        f'open("{path}", O_RDONLY) = -1 EACCES\n'
    ))
    assert summary["read_denials"][0]["host_open_succeeded"] is True
    assert probes == [(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)]


def test_trace_size_and_missing_file_are_explicit(tmp_path: Path):
    path = tmp_path / "too-large.log"
    with path.open("wb") as stream:
        stream.truncate(16 * 1024 * 1024 + 1)
    assert summarize_trace(path, ())["gaps"] == ["isolation_trace_too_large"]
    assert summarize_trace(tmp_path / "missing.log", ())["gaps"] == ["isolation_trace_unreadable"]


def test_trace_command_is_data_and_covers_native_reads(tmp_path: Path):
    command = ["/python", "-m", "worker", "a shell-looking $(argument)"]
    result = trace_command(command, tmp_path / "trace with spaces.log")
    assert result[0] == "/usr/bin/strace"
    assert result[-len(command):] == command
    assert result[result.index("-o") + 1] == str(tmp_path / "trace with spaces.log")
    assert "-f" in result and "-yy" in result
    assert any("landlock_restrict_self" in arg and "openat2" in arg for arg in result)
    assert command == ["/python", "-m", "worker", "a shell-looking $(argument)"]
    assert (tmp_path / "trace with spaces.log").stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        trace_command(command, tmp_path / "trace with spaces.log")
