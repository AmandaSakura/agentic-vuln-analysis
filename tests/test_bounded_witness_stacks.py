"""Timeout stacks are bounded diagnostics and cannot supply candidate proof."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cv_agent.domain.evidence import ValidationStatus
from cv_agent.evaluation.diagnostics import bounded_execution_witness as witness
from cv_agent.runtime.witness_resources import WitnessResourceProfile
from test_bounded_execution_witness import DIRECT, NONCE, _manifest


def _diagnostic_manifest(root: Path, source: str):
    return _manifest(root, source).model_copy(update={
        "resource_profile": WitnessResourceProfile(
            name="cpu_diagnostic", cpu_soft_seconds=10, cpu_hard_seconds=12,
            wall_seconds=4.0,
        ),
    })


def test_timeout_preserves_all_thread_stacks_without_syscall_tracing(tmp_path: Path) -> None:
    manifest = _diagnostic_manifest(tmp_path, """
        import threading
        import time

        def wait_in_another_thread():
            time.sleep(30)

        class Service:
            def serve(self, model_uri):
                threading.Thread(target=wait_in_another_thread, daemon=True).start()
                time.sleep(30)
    """)
    result = witness.run_witness(
        manifest, nonce=NONCE, diagnostic_only=True, diagnostic_stack_capture=True,
    )

    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert result.raw_status == "UNRESOLVED"
    assert result.details["claim_eligible"] is False
    event = result.details["probe_event"]
    assert event["kind"] == "error"
    assert event["gap"] == "worker_timeout"
    assert event["phase"] == "invoke"
    assert event["parent_kill_reason"] == "wall_timeout"
    assert event["resource_accounting"]["tracer"] is None
    stack = event["stack_dump"]
    assert stack["enabled"] is True
    assert stack["timeout_margin_seconds"] == 3.0
    assert stack["byte_count"] > 0
    assert stack["truncated"] is False
    assert stack["limit_bytes"] == 64000
    assert str(tmp_path / "sample.py") in stack["text"]
    assert "in serve" in stack["text"]
    assert "in wait_in_another_thread" in stack["text"]
    assert "Thread" in stack["text"]
    assert "read_diagnostics" not in event
    assert "open_attempts" not in event
    assert json.loads(result.model_dump_json())["status"] == "UNRESOLVED"
    assert not list(tmp_path.rglob("*.strace.log"))


def test_fast_authenticated_command_stays_diagnostic_with_empty_stack(tmp_path: Path) -> None:
    result = witness.run_witness(
        _diagnostic_manifest(tmp_path, DIRECT), nonce=NONCE,
        diagnostic_only=True, diagnostic_stack_capture=True,
    )

    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert result.raw_status == "UNRESOLVED"
    assert result.details["claim_eligible"] is False
    assert result.details["reached_popen"] is True
    assert result.details["probe_replay"]["ok"] is True
    event = result.details["probe_event"]
    assert event["authentic_subprocess_popen"] is True
    assert event["candidate_frame"]["qualname"] == "Service.serve"
    assert event["returncode"] == 0
    assert event["resource_accounting"]["tracer"] is None
    stack = event["stack_dump"]
    assert stack["enabled"] is True
    assert stack["text"] == ""
    assert stack["byte_count"] == 0
    assert stack["truncated"] is False


def test_no_trace_keeps_exact_read_grants_and_write_isolation(tmp_path: Path) -> None:
    granted = tmp_path / "reviewed.txt"
    sibling = tmp_path / "unreviewed.txt"
    granted.write_text("reviewed read")
    sibling.write_text("unreviewed read")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    manifest = _diagnostic_manifest(checkout, f"""
        class Service:
            def serve(self, model_uri):
                assert open({str(granted)!r}).read() == "reviewed read"
                try:
                    open({str(sibling)!r}).read()
                except PermissionError:
                    pass
                else:
                    raise AssertionError("unreviewed sibling read admitted")
                try:
                    open({str(granted)!r}, "w").write("changed")
                except PermissionError:
                    pass
                else:
                    raise AssertionError("reviewed file write admitted")
    """)
    grant = witness.IsolationReadGrant.from_path(
        granted, reason="offline exact-leaf diagnostic control",
    )
    result = witness.run_witness(
        manifest, nonce=NONCE, diagnostic_only=True,
        diagnostic_stack_capture=True, diagnostic_read_grants=(grant,),
    )

    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    event = result.details["probe_event"]
    assert event["kind"] == "no_event", event
    assert event["phase"] == "invoke"
    assert event["resource_accounting"]["tracer"] is None
    assert "read_diagnostics" not in event
    assert "open_attempts" not in event
    assert not any(gap.startswith("isolation_read_denied:") for gap in result.gaps)
    assert result.details["isolation_read_grants"] == [grant.model_dump(mode="json")]
    assert granted.read_text() == "reviewed read"
    assert sibling.read_text() == "unreviewed read"


def test_no_trace_stale_read_grant_rejected_before_source_exec(tmp_path: Path) -> None:
    granted = tmp_path / "reviewed.txt"
    granted.write_text("first identity")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    manifest = _diagnostic_manifest(checkout, """
        raise AssertionError("target must not execute with stale grant")
        class Service:
            def serve(self, model_uri):
                pass
    """)
    grant = witness.IsolationReadGrant.from_path(granted, reason="offline stale identity control")
    granted.write_text("changed identity")
    result = witness.run_witness(
        manifest, nonce=NONCE, diagnostic_only=True,
        diagnostic_stack_capture=True, diagnostic_read_grants=(grant,),
    )

    assert result.status == ValidationStatus.UNRESOLVED
    assert f"isolation_read_grant_stale:{granted}" in result.gaps
    assert "probe_event" not in result.details


def test_stack_capture_is_rejected_for_candidate_proof(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="diagnostic"):
        witness.run_witness(
            _manifest(tmp_path, DIRECT), nonce=NONCE, diagnostic_stack_capture=True,
        )


def test_default_candidate_proof_remains_positive_without_stack_capture(tmp_path: Path) -> None:
    result = witness.run_witness(_manifest(tmp_path, DIRECT), nonce=NONCE)
    assert result.status == ValidationStatus.CONFIRMED, result.model_dump()
    assert result.raw_status == "EXPANDED_OBSERVED"
    assert result.details["probe_replay"]["ok"] is True
    assert result.details["control_replay"]["ok"] is True
    assert not result.details["probe_event"].get("stack_dump", {}).get("enabled", False)
    assert result.details["resource_profile"] == WitnessResourceProfile.fixture_default().model_dump()


def test_stack_overflow_is_drained_and_cannot_corrupt_command_json(tmp_path: Path) -> None:
    # This synthetic target explicitly exercises the inherited diagnostic pipe.
    # Production target functions receive no stack FD or target-internal stub.
    manifest = _diagnostic_manifest(tmp_path, """
        import os
        import subprocess
        import sys

        class Service:
            def serve(self, model_uri):
                frame = sys._getframe()
                while frame.f_code.co_name != "_worker":
                    frame = frame.f_back
                    assert frame is not None
                stack_fd = frame.f_locals["stack_result_fd"]
                assert isinstance(stack_fd, int)
                pending = memoryview(b"S" * 160000)
                while pending:
                    pending = pending[os.write(stack_fd, pending):]
                subprocess.Popen(["bash", "-c", f"record {model_uri}"])
    """)
    result = witness.run_witness(
        manifest, nonce=NONCE, diagnostic_only=True, diagnostic_stack_capture=True,
    )

    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert result.details["reached_popen"] is True
    assert result.details["probe_replay"]["ok"] is True
    event = result.details["probe_event"]
    assert event["kind"] == "command_event"
    assert event["returncode"] == 0
    assert "parent_kill_reason" not in event
    stack = event["stack_dump"]
    assert stack["byte_count"] == 160000
    assert stack["limit_bytes"] == 64000
    assert stack["truncated"] is True
    assert stack["text"] == "S" * 64000
    assert json.loads(result.model_dump_json())["status"] == "UNRESOLVED"


def test_closed_stack_pipe_is_not_selected_again_after_eof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _diagnostic_manifest(tmp_path, """
        import os
        import subprocess
        import sys
        import time

        class Service:
            def serve(self, model_uri):
                frame = sys._getframe()
                while frame.f_code.co_name != "_worker":
                    frame = frame.f_back
                    assert frame is not None
                os.close(frame.f_locals["stack_result_fd"])
                time.sleep(0.3)
                subprocess.Popen(["bash", "-c", f"record {model_uri}"])
    """)
    real_select = witness.select.select
    real_read = witness.os.read
    stack_fd: int | None = None
    eof_seen = False
    selection_after_eof = False

    def track_read(fd: int, size: int) -> bytes:
        nonlocal eof_seen
        chunk = real_read(fd, size)
        if fd == stack_fd and chunk == b"":
            eof_seen = True
        return chunk

    def track_select(readable, writable, exceptional, timeout=None):
        nonlocal stack_fd, selection_after_eof
        if stack_fd is None and len(readable) == 2 and all(
            isinstance(fd, int) for fd in readable
        ):
            stack_fd = readable[1]
        if eof_seen:
            selection_after_eof = True
            assert stack_fd not in readable, "stack EOF left permanently readable in select"
        return real_select(readable, writable, exceptional, timeout)

    monkeypatch.setattr(witness.os, "read", track_read)
    monkeypatch.setattr(witness.select, "select", track_select)
    result = witness.run_witness(
        manifest, nonce=NONCE, diagnostic_only=True, diagnostic_stack_capture=True,
    )

    assert eof_seen and selection_after_eof
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert result.details["reached_popen"] is True
    assert result.details["probe_replay"]["ok"] is True
    assert result.details["probe_event"]["returncode"] == 0
    assert result.details["probe_event"]["stack_dump"]["text"] == ""


def test_cli_explicitly_disables_strace_and_enables_stack_capture(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    manifest = _diagnostic_manifest(checkout, DIRECT)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json())
    runtime = tmp_path / "runtime"
    output = tmp_path / "diagnostic.json"
    completed = subprocess.run(
        [sys.executable, "-m", "cv_agent.evaluation.diagnostics.run_bounded_witness_diagnostic",
         str(manifest_path), str(runtime), NONCE, str(output), "--no-strace", "--dump-stacks"],
        capture_output=True, text=True, check=False, timeout=12,
    )
    assert completed.returncode == 0, completed.stderr
    record = json.loads(output.read_text())
    assert record["strace_enabled"] is False
    assert record["stack_capture_enabled"] is True
    assert record["result"]["status"] == "UNRESOLVED"
    assert record["result"]["details"]["reached_popen"] is True
    assert record["result"]["details"]["probe_event"]["stack_dump"]["enabled"] is True
    assert record["resource_accounting"]["tracer"] is None
    assert not output.with_suffix(".strace.log").exists()
