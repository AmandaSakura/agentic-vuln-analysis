"""Offline controls for the witness interpreter selected by a manifest."""

from __future__ import annotations

import platform
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from cv_agent.domain.evidence import ValidationStatus
from cv_agent.runtime.witness import kernel as witness

from test_bounded_execution_witness import DIRECT, NONCE, _manifest


def test_manifest_rejects_relative_python_executable(tmp_path: Path) -> None:
    data = _manifest(tmp_path, DIRECT).model_dump(mode="json")
    data["python_executable"] = "relative/bin/python"

    with pytest.raises(ValidationError, match="python_executable must be an absolute path"):
        witness.WitnessManifest.model_validate(data)


def test_explicit_current_venv_runs_worker_and_records_identity(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, DIRECT).model_copy(update={
        "python_executable": Path(sys.executable),
    })

    result = witness.run_witness(manifest, nonce=NONCE)

    assert result.status == ValidationStatus.CONFIRMED, result.model_dump()
    identity = result.details["probe_event"]["interpreter"]
    assert identity["executable"] == str(Path(sys.executable).absolute())
    assert identity["prefix"] == str(Path(sys.prefix).resolve())
    assert identity["version"] == platform.python_version()
    assert identity["matches_manifest"] is True


def test_wrong_interpreter_prefix_stops_before_target_import(tmp_path: Path) -> None:
    # This harmless launcher delegates to the test venv's Python. Its pathname
    # is a different pseudo-venv, so a path-only check would miss the mismatch.
    fake = tmp_path / "other-venv" / "bin" / "python"
    fake.parent.mkdir(parents=True)
    fake.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    fake.chmod(0o755)
    source = """
raise RuntimeError("target import must not run")

class Service:
    def serve(self, model_uri):
        pass
"""
    manifest = _manifest(tmp_path, source).model_copy(update={"python_executable": fake})

    result = witness.run_witness(manifest, nonce=NONCE)

    assert result.status == ValidationStatus.UNRESOLVED
    assert "worker_interpreter_mismatch" in result.gaps
    identity = result.details["probe_event"]["interpreter"]
    assert identity["matches_manifest"] is False
    assert identity["prefix"] == str(Path(sys.prefix).resolve())


def test_replay_uses_and_checks_bound_interpreter(tmp_path: Path) -> None:
    fake = tmp_path / "other-venv" / "bin" / "python"
    fake.parent.mkdir(parents=True)
    fake.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    fake.chmod(0o755)
    manifest = _manifest(tmp_path, DIRECT).model_copy(update={"python_executable": fake})
    runtime = tmp_path / "runtime"
    runtime.mkdir()

    result = witness._replay("record literal", manifest, runtime)

    assert result["ok"] is False
    assert result["gap"] == "replay_interpreter_mismatch"
