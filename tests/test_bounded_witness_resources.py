"""Resource failures remain diagnostics, with target and tracer costs separated."""

from __future__ import annotations

from pathlib import Path

import pytest

from cv_agent.domain.evidence import ValidationStatus
from cv_agent.evaluation.diagnostics import bounded_execution_witness as witness
from cv_agent.runtime.witness_resources import WitnessResourceProfile
from test_bounded_execution_witness import DIRECT, NONCE, _manifest


def _profile(*, soft: int = 1, hard: int = 3, wall: float = 8.0) -> WitnessResourceProfile:
    return WitnessResourceProfile(name="cpu_diagnostic", cpu_soft_seconds=soft,
                                  cpu_hard_seconds=hard, wall_seconds=wall)


def _manifest_with_profile(tmp_path: Path, source: str, profile: WitnessResourceProfile):
    return _manifest(tmp_path, source).model_copy(update={"resource_profile": profile})


def _traced_run(tmp_path: Path, manifest):
    return witness.run_witness(
        manifest, nonce=NONCE, diagnostic_only=True,
        diagnostic_trace_path=tmp_path / "resource-diagnostic.strace",
    )


def test_manifest_default_budget_is_serialized_explicitly(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, DIRECT)
    profile = manifest.model_dump(mode="json")["resource_profile"]
    assert profile == {
        "name": "fixture_default", "cpu_soft_seconds": 5, "cpu_hard_seconds": 5,
        "address_space_bytes": 1500000000, "file_size_bytes": 1000000,
        "open_files": 64, "wall_seconds": 12.0,
    }


def test_default_worker_limits_remain_fixture_limits_and_are_reported(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, """
        import resource
        class Service:
            def serve(self, model_uri):
                assert resource.getrlimit(resource.RLIMIT_CPU) == (5, 5)
                assert resource.getrlimit(resource.RLIMIT_AS) == (1500000000, 1500000000)
                assert resource.getrlimit(resource.RLIMIT_NOFILE) == (64, 64)
                assert resource.getrlimit(resource.RLIMIT_FSIZE) == (1000000, 1000000)
    """)
    result = witness.run_witness(manifest, nonce=NONCE, diagnostic_only=True)

    assert result.status == ValidationStatus.UNRESOLVED
    event = result.details["probe_event"]
    assert event["kind"] == "no_event", event
    assert event["applied_resource_limits"]["cpu"] == [5, 5]
    assert event["applied_resource_limits"]["address_space"] == [1500000000, 1500000000]
    assert event["applied_resource_limits"]["open_files"] == [64, 64]
    assert event["applied_resource_limits"]["file_size"] == [1000000, 1000000]


def test_nondefault_budget_is_rejected_for_candidate_confirmation(tmp_path: Path) -> None:
    manifest = _manifest_with_profile(tmp_path, DIRECT, _profile())
    with pytest.raises(ValueError, match="diagnostic"):
        witness.run_witness(manifest, nonce=NONCE)


def test_kernel_cpu_exhaustion_is_source_distinct_and_accounts_target_and_tracer(
    tmp_path: Path,
) -> None:
    manifest = _manifest_with_profile(tmp_path, """
        class Service:
            def serve(self, model_uri):
                while True:
                    pass
    """, _profile())
    result = _traced_run(tmp_path, manifest)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert "cpu_limit_exceeded" in result.gaps
    event = result.details["probe_event"]
    assert event["phase"] == "invoke"
    assert event["gap"] == "cpu_limit_exceeded"
    assert event["cpu_limit_signal"]["si_code"] == 128
    assert event["cpu_limit_signal"]["si_pid"] == 0
    assert event["applied_resource_limits"]["cpu"] == [1, 3]
    assert event.get("parent_kill_reason") is None
    self_usage = event["target_self_usage"]
    assert self_usage["pid"] == event["target_pid"]
    own_cpu = self_usage["user_cpu_seconds"] + self_usage["system_cpu_seconds"]
    assert own_cpu >= 0.8
    accounting = event["resource_accounting"]
    target, tracer = accounting["target"], accounting["tracer"]
    assert target["self_reported_usage"] == self_usage
    assert target["self_report_is_final"] is True
    assert target["pid"] != tracer["pid"]
    assert tracer["cpu_accounting_complete"] is True
    assert tracer["total_cpu_seconds"] < own_cpu


def test_target_sent_sigxcpu_is_not_reported_as_cpu_exhaustion(tmp_path: Path) -> None:
    manifest = _manifest_with_profile(tmp_path, """
        import os, signal
        class Service:
            def serve(self, model_uri):
                os.kill(os.getpid(), signal.SIGXCPU)
                while True:
                    pass
    """, _profile(soft=4, hard=6))
    result = _traced_run(tmp_path, manifest)
    event = result.details["probe_event"]
    assert result.status == ValidationStatus.UNRESOLVED
    assert event["gap"] == "target_signal:SIGXCPU", event
    assert "cpu_limit_exceeded" not in result.gaps
    assert event["cpu_limit_signal"]["si_code"] == 0
    assert event["cpu_limit_signal"]["si_pid"] == event["target_pid"]
    assert event["phase"] == "invoke"


def test_nondefault_direct_expansion_remains_diagnostic_only(tmp_path: Path) -> None:
    manifest = _manifest_with_profile(tmp_path, DIRECT, _profile(soft=4, hard=6))
    result = _traced_run(tmp_path, manifest)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert result.raw_status == "UNRESOLVED"
    assert result.details["reached_popen"] is True
    assert result.details["probe_replay"]["ok"] is True
    assert result.details["claim_eligible"] is False
    assert result.details["probe_event"]["applied_resource_limits"]["cpu"] == [4, 6]


def test_wall_timeout_reports_parent_kill_and_preserves_last_phase(tmp_path: Path) -> None:
    manifest = _manifest_with_profile(tmp_path, """
        import time
        class Service:
            def serve(self, model_uri):
                time.sleep(30)
    """, _profile(soft=10, hard=12, wall=2.0))
    result = _traced_run(tmp_path, manifest)
    event = result.details["probe_event"]
    assert result.status == ValidationStatus.UNRESOLVED
    assert event["phase"] == "invoke", event
    assert event["gap"] == "worker_timeout"
    assert event["parent_kill_reason"] == "wall_timeout"
    assert "cpu_limit_exceeded" not in result.gaps
    target = event["resource_accounting"]["target"]
    assert target["self_report_is_final"] is False
    assert target["cpu_accounting_complete"] is False
    assert target["user_cpu_seconds"] is not None


def test_sigkill_does_not_get_attributed_to_cpu_budget(tmp_path: Path) -> None:
    manifest = _manifest_with_profile(tmp_path, """
        import os, signal
        class Service:
            def serve(self, model_uri):
                os.kill(os.getpid(), signal.SIGKILL)
    """, _profile(soft=4, hard=6))
    result = _traced_run(tmp_path, manifest)
    event = result.details["probe_event"]
    assert result.status == ValidationStatus.UNRESOLVED
    assert event["gap"] == "worker_terminated:SIGKILL", event
    assert event["phase"] == "invoke"
    assert event.get("parent_kill_reason") is None
    assert "cpu_limit_exceeded" not in result.gaps


def test_nonzero_worker_exit_cannot_promote_delivered_command_record(tmp_path: Path) -> None:
    # Simulate termination after the authentic event was written. The final
    # process status must still block the default proof path, as before.
    manifest = _manifest(tmp_path, """
        import os, sys, subprocess
        worker = sys.modules["__main__"]
        original_write = worker._write_result
        def write_then_fail(fd, payload):
            original_write(fd, payload)
            if payload.get("kind") == "command_event":
                os._exit(7)
        worker._write_result = write_then_fail
        class Service:
            def serve(self, model_uri):
                subprocess.Popen(["bash", "-c", f"record {model_uri}"])
    """)
    result = witness.run_witness(manifest, nonce=NONCE)
    assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
    assert result.details["probe_event"]["returncode"] == 7
    assert result.details["probe_event"]["kind"] == "error"
    assert "probe_replay" not in result.details
