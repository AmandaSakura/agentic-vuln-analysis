"""An already disappearing process group must not discard timeout evidence."""

from __future__ import annotations

import errno
import os
from pathlib import Path
import signal

import pytest

from cv_agent.domain.evidence import ValidationStatus
from cv_agent.evaluation.diagnostics import bounded_execution_witness as witness
from cv_agent.runtime.witness_resources import WitnessResourceProfile
from test_bounded_execution_witness import NONCE, _manifest


def test_timeout_group_disappearing_during_kill_preserves_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(tmp_path, """
        import time
        class Service:
            def serve(self, model_uri):
                time.sleep(30)
    """).model_copy(update={"resource_profile": WitnessResourceProfile(
        name="cpu_diagnostic", cpu_soft_seconds=10, cpu_hard_seconds=12,
        wall_seconds=2.0,
    )})
    real_killpg = os.killpg
    attempts: list[tuple[int, int]] = []

    def kill_then_disappear(pid: int, selected_signal: int) -> None:
        attempts.append((pid, selected_signal))
        # Actually terminate the synthetic process group before reporting the
        # race, so a failing cleanup path cannot leave the sleeper running.
        real_killpg(pid, selected_signal)
        raise ProcessLookupError(errno.ESRCH, "group disappeared while terminating")

    monkeypatch.setattr(witness.os, "killpg", kill_then_disappear)
    result = witness.run_witness(
        manifest, nonce=NONCE, diagnostic_only=True,
        diagnostic_trace_path=tmp_path / "cleanup.strace",
    )

    assert attempts and attempts[0][1] == signal.SIGKILL
    assert result.status == ValidationStatus.UNRESOLVED
    event = result.details["probe_event"]
    assert event["gap"] == "worker_timeout", event
    assert event["phase"] == "invoke"
    assert event["parent_kill_reason"] == "wall_timeout"
    assert event["resource_accounting"]["tracer"]["cpu_accounting_complete"] is True
