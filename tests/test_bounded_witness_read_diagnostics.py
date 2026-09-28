"""Diagnostic read observations must retain actual isolation failures."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from cv_agent.domain.evidence import ValidationStatus
from cv_agent.evaluation.diagnostics import bounded_execution_witness as witness
from test_bounded_execution_witness import NONCE, _manifest


def _setup(tmp_path: Path, body: str):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    source = textwrap.dedent(body).lstrip() + "\nclass Service:\n    def serve(self, model_uri):\n        pass\n"
    return _manifest(checkout, source)


def _run(tmp_path: Path, manifest, *, grants=()):
    return witness.run_witness(
        manifest,
        nonce=NONCE,
        diagnostic_only=True,
        diagnostic_read_grants=grants,
        diagnostic_trace_path=tmp_path / "diagnostic.strace",
    )


def _denials(result):
    return result.details["probe_event"]["read_diagnostics"]["read_denials"]


def test_denied_import_read_has_exact_gap_and_real_syscall(tmp_path: Path):
    external = tmp_path / "external.txt"
    external.write_text("offline fixture data")
    manifest = _setup(tmp_path, f"open({str(external)!r}).read()")
    result = _run(tmp_path, manifest)

    assert result.status == ValidationStatus.UNRESOLVED
    assert f"isolation_read_denied:{external}" in result.gaps
    event = result.details["probe_event"]
    assert event["phase"] == "import"
    assert result.details["reached_popen"] is False
    denial = next(item for item in _denials(result) if item["path"] == str(external))
    assert denial["gap"] == f"isolation_read_denied:{external}"
    assert denial["requested_path"] == str(external)
    assert denial["pid"] > 0
    assert denial["syscall"] in {"open", "openat", "openat2"}
    attempts = event["open_attempts"]
    attempt = next(item for item in attempts if item["path"] == str(external))
    assert attempt["phase"] == "import"
    assert "flags" in attempt and "thread" in attempt and "frames" in attempt


def test_caught_python_and_native_read_denials_are_both_reported(tmp_path: Path):
    python_file = tmp_path / "python-read.txt"
    native_file = tmp_path / "native-read.txt"
    python_file.write_text("python fixture")
    native_file.write_text("native fixture")
    manifest = _setup(tmp_path, f"""
        import ctypes
        import errno
        try:
            open({str(python_file)!r}).read()
        except PermissionError:
            pass
        libc = ctypes.CDLL(None, use_errno=True)
        libc.open.argtypes = [ctypes.c_char_p, ctypes.c_int]
        libc.open.restype = ctypes.c_int
        descriptor = libc.open({str(native_file).encode()!r}, 0)
        assert descriptor == -1 and ctypes.get_errno() == errno.EACCES
    """)
    result = _run(tmp_path, manifest)

    assert result.status == ValidationStatus.UNRESOLVED
    assert {str(python_file), str(native_file)} <= {item["path"] for item in _denials(result)}
    assert f"isolation_read_denied:{python_file}" in result.gaps
    assert f"isolation_read_denied:{native_file}" in result.gaps
    attempts = result.details["probe_event"]["open_attempts"]
    assert any(item["path"] == str(python_file) for item in attempts)
    assert not any(item["path"] == str(native_file) for item in attempts)
    assert result.details["probe_event"]["phase"] == "invoke"


def test_import_abort_reports_only_observed_reads(tmp_path: Path):
    first = tmp_path / "first.txt"
    future = tmp_path / "never-executed.txt"
    first.write_text("first")
    future.write_text("future")
    manifest = _setup(tmp_path, f"open({str(first)!r}).read()\nopen({str(future)!r}).read()")
    result = _run(tmp_path, manifest)

    assert f"isolation_read_denied:{first}" in result.gaps
    assert f"isolation_read_denied:{future}" not in result.gaps
    assert not any(item["path"] == str(future) for item in _denials(result))
    assert not any(item["path"] == str(future) for item in
                   result.details["probe_event"]["open_attempts"])


def test_exact_file_grant_keeps_sibling_read_and_granted_write_denied(tmp_path: Path):
    granted = tmp_path / "granted.txt"
    sibling = tmp_path / "sibling.txt"
    granted.write_text("allow this exact read")
    sibling.write_text("deny this sibling")
    manifest = _setup(tmp_path, f"""
        assert open({str(granted)!r}).read() == "allow this exact read"
        try:
            open({str(sibling)!r}).read()
        except PermissionError:
            pass
        else:
            raise AssertionError("sibling unexpectedly admitted")
        try:
            open({str(granted)!r}, "w").write("should never be written")
        except PermissionError:
            pass
        else:
            raise AssertionError("write unexpectedly admitted")
    """)
    grant = witness.IsolationReadGrant.from_path(granted, reason="synthetic exact-file positive control")
    result = _run(tmp_path, manifest, grants=(grant,))

    assert result.status == ValidationStatus.UNRESOLVED
    assert f"isolation_read_denied:{sibling}" in result.gaps
    assert f"isolation_read_denied:{granted}" not in result.gaps
    assert result.details["probe_event"]["kind"] == "no_event"
    assert result.details["probe_event"]["phase"] == "invoke"
    assert result.details["isolation_read_grants"]
    assert granted.read_text() == "allow this exact read"


def test_fake_open_event_missing_file_and_write_are_not_read_denials(tmp_path: Path):
    fake = tmp_path / "fake.txt"
    missing = tmp_path / "missing.txt"
    write_target = tmp_path / "write-only.txt"
    fake.write_text("fake audit event target")
    write_target.write_text("must stay unchanged")
    manifest = _setup(tmp_path, f"""
        import sys
        sys.audit("open", {str(fake)!r}, "r", 0)
        try:
            open({str(missing)!r}).read()
        except FileNotFoundError:
            pass
        try:
            open({str(write_target)!r}, "w").write("bad")
        except PermissionError:
            pass
    """)
    result = _run(tmp_path, manifest)

    assert result.status == ValidationStatus.UNRESOLVED
    assert result.details["probe_event"]["kind"] == "no_event"
    assert not _denials(result)
    assert not any(gap.startswith("isolation_read_denied:") for gap in result.gaps)
    assert write_target.read_text() == "must stay unchanged"
    attempts = result.details["probe_event"]["open_attempts"]
    assert any(item["path"] == str(fake) for item in attempts)


def test_unicode_space_and_relative_denial_paths_are_preserved(tmp_path: Path):
    external = tmp_path / "outside with space-é.txt"
    external.write_text("unicode fixture")
    manifest = _setup(tmp_path, f"""
        import os
        os.chdir({str(tmp_path)!r})
        open({external.name!r}).read()
    """)
    result = _run(tmp_path, manifest)

    assert f"isolation_read_denied:{external}" in result.gaps
    denial = next(item for item in _denials(result) if item["path"] == str(external))
    assert denial["requested_path"] == external.name
    assert result.details["probe_event"]["phase"] == "import"


def test_invoke_failure_retains_phase_and_read_gap(tmp_path: Path):
    external = tmp_path / "invoke-read.txt"
    external.write_text("invoke fixture")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    manifest = _manifest(checkout, f"""
        class Service:
            def serve(self, model_uri):
                open({str(external)!r}).read()
    """)
    result = _run(tmp_path, manifest)

    assert result.details["probe_event"]["phase"] == "invoke"
    assert f"isolation_read_denied:{external}" in result.gaps
    assert result.status == ValidationStatus.UNRESOLVED


@pytest.mark.parametrize("option", ["trace", "grant"])
def test_read_diagnostic_options_rejected_for_regular_witness(tmp_path: Path, option: str):
    manifest = _setup(tmp_path, "")
    external = tmp_path / "grant.txt"
    external.write_text("fixture")
    kwargs = ({"diagnostic_trace_path": tmp_path / "trace"} if option == "trace" else {
        "diagnostic_read_grants": (
            witness.IsolationReadGrant.from_path(external, reason="synthetic file"),
        ),
    })
    with pytest.raises(ValueError, match="diagnostic"):
        witness.run_witness(manifest, nonce=NONCE, **kwargs)


def test_directory_read_grant_rejected(tmp_path: Path):
    with pytest.raises(ValueError):
        witness.IsolationReadGrant.from_path(tmp_path, reason="must not admit a whole directory")


def test_old_trace_cannot_supply_new_run_denials(tmp_path: Path):
    external = tmp_path / "old-external.txt"
    external.write_text("old fixture")
    trace = tmp_path / "diagnostic.strace"
    old = ('123 landlock_restrict_self(3, 0) = 0\n'
           f'123 open("{external}", O_RDONLY) = -1 EACCES\n')
    trace.write_text(old)
    manifest = _setup(tmp_path, "")
    with pytest.raises(FileExistsError):
        _run(tmp_path, manifest)
    assert trace.read_text() == old


def test_terminated_worker_preserves_last_observed_phase(tmp_path: Path):
    manifest = _setup(tmp_path, "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)")
    result = _run(tmp_path, manifest)
    event = result.details["probe_event"]
    assert result.status == ValidationStatus.UNRESOLVED
    assert event["gap"] == "worker_terminated:SIGKILL"
    assert event["phase"] == "import"
    assert event["interpreter"]["matches_manifest"] is True
    assert event["read_diagnostics"]["gaps"] == ["isolation_trace_process_killed"]
    assert result.details["reached_popen"] is False


def test_stale_exact_file_grant_rejected_before_target_import(tmp_path: Path):
    external = tmp_path / "grant.txt"
    external.write_text("original fixture")
    manifest = _setup(tmp_path, f"open({str(external)!r}).read()")
    grant = witness.IsolationReadGrant.from_path(external, reason="synthetic identity check")
    external.write_text("changed fixture")
    result = _run(tmp_path, manifest, grants=(grant,))

    assert result.status == ValidationStatus.UNRESOLVED
    assert f"isolation_read_grant_stale:{external}" in result.gaps
    event = result.details.get("probe_event")
    assert event is None or (event["kind"] == "error" and event["phase"] == "preflight")
