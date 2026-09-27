"""Stage 2 diagnostics must execute through proof gaps without emitting proof."""

from __future__ import annotations

import os
import py_compile
from pathlib import Path
import time

import pytest

from cv_agent.domain.evidence import ValidationStatus
from cv_agent.evaluation.diagnostics.bounded_execution_witness import (
    SourceFileBinding,
    run_witness,
)
from test_bounded_execution_witness import DIRECT, NONCE, QUOTED, _manifest


def test_diagnostic_mode_reaches_real_popen_through_unverified_assumptions(tmp_path: Path):
    manifest = _manifest(tmp_path, DIRECT)
    manifest = manifest.model_copy(update={
        "subject": manifest.subject.model_copy(update={
            "entry_condition_assumptions": {"unmodeled_condition()": True},
        }),
    })
    ordinary = run_witness(manifest, nonce=NONCE)
    assert ordinary.status == ValidationStatus.UNRESOLVED
    assert "probe_event" not in ordinary.details

    diagnostic = run_witness(manifest, nonce=NONCE, diagnostic_only=True)
    assert diagnostic.status == ValidationStatus.UNRESOLVED
    assert diagnostic.raw_status == "UNRESOLVED"
    assert "entry_condition_assumption_unverified:unmodeled_condition()" in diagnostic.gaps
    assert diagnostic.details["diagnostic_only"] is True
    assert diagnostic.details["reached_popen"] is True
    assert diagnostic.details["probe_event"]["authentic_subprocess_popen"] is True
    assert diagnostic.details["probe_replay"]["ok"] is True


def test_diagnostic_mode_never_promotes_even_when_regular_witness_confirms(tmp_path: Path):
    manifest = _manifest(tmp_path, DIRECT)
    assert run_witness(manifest, nonce=NONCE).status == ValidationStatus.CONFIRMED
    diagnostic = run_witness(manifest, nonce=NONCE, diagnostic_only=True)
    assert diagnostic.status == ValidationStatus.UNRESOLVED
    assert diagnostic.details["reached_popen"] is True
    assert diagnostic.details["probe_replay"]["ok"] is True


def test_diagnostic_mode_reports_import_failure_after_assumption_gap(tmp_path: Path):
    source = """
raise ImportError("synthetic import failure")
class Service:
    def serve(self, model_uri):
        pass
"""
    manifest = _manifest(tmp_path, source)
    manifest = manifest.model_copy(update={
        "subject": manifest.subject.model_copy(update={
            "entry_condition_assumptions": {"unmodeled_condition()": True},
        }),
    })
    result = run_witness(manifest, nonce=NONCE, diagnostic_only=True)
    assert result.status == ValidationStatus.UNRESOLVED
    assert "entry_condition_assumption_unverified:unmodeled_condition()" in result.gaps
    assert "target_or_isolation_error" in result.gaps
    assert result.details["reached_popen"] is False
    assert "ImportError" in result.details["probe_event"]["error"]


def test_import_time_popen_is_not_reported_as_serve_reaching_popen(tmp_path: Path):
    source = """
import subprocess
subprocess.Popen(["bash", "-c", "record import"])
class Service:
    def serve(self, model_uri):
        subprocess.Popen(["bash", "-c", f"record {model_uri}"])
"""
    result = run_witness(
        _manifest(tmp_path, source), nonce=NONCE, diagnostic_only=True,
    )
    assert result.status == ValidationStatus.UNRESOLVED
    assert result.details["observed_popen_event"] is True
    assert result.details["reached_popen"] is False
    assert "import_time_command_event" in result.gaps


def test_two_diagnostics_use_the_same_controlled_absolute_input(tmp_path: Path):
    manifest = _manifest(tmp_path, DIRECT)
    runtime = tmp_path / "shared-runtime"
    first = run_witness(
        manifest, nonce=NONCE, diagnostic_only=True, diagnostic_runtime_dir=runtime,
    )
    second = run_witness(
        manifest, nonce=NONCE, diagnostic_only=True, diagnostic_runtime_dir=runtime,
    )
    assert first.status == second.status == ValidationStatus.UNRESOLVED
    assert first.details["reached_popen"] is second.details["reached_popen"] is True
    assert first.details["probe_path"] == second.details["probe_path"]
    assert first.details["precondition_sha256"] == second.details["precondition_sha256"]
    with pytest.raises(ValueError, match="diagnostic-only"):
        run_witness(manifest, nonce=NONCE, diagnostic_runtime_dir=runtime)


def test_reused_probe_rejects_undeclared_or_symlinked_content(tmp_path: Path):
    manifest = _manifest(tmp_path, DIRECT).model_copy(update={
        "precondition_files": {"nested/MLmodel": "flavors: {}\n"},
    })
    runtime = tmp_path / "shared-runtime"
    first = run_witness(
        manifest, nonce=NONCE, diagnostic_only=True, diagnostic_runtime_dir=runtime,
    )
    assert first.details["reached_popen"] is True
    probe = Path(first.details["probe_path"])
    (probe / "extra.txt").write_text("undeclared")
    with pytest.raises(ValueError, match="undeclared content"):
        run_witness(manifest, nonce=NONCE, diagnostic_only=True,
                    diagnostic_runtime_dir=runtime)
    (probe / "extra.txt").unlink()
    (probe / "nested/MLmodel").unlink()
    (probe / "nested").rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (probe / "nested").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="parent cannot be a symlink"):
        run_witness(manifest, nonce=NONCE, diagnostic_only=True,
                    diagnostic_runtime_dir=runtime)


def test_large_manifest_and_early_worker_exit_return_unresolved_without_hang(tmp_path: Path):
    manifest = _manifest(tmp_path, DIRECT)
    extra_bindings = tuple(
        SourceFileBinding(
            module_name=f"unused_{number}", relative_path=f"unused_{number}.py",
            sha256="0" * 64,
        )
        for number in range(1800)
    )
    manifest = manifest.model_copy(update={
        "source_modules": (*manifest.source_modules, *extra_bindings),
        "python_executable": Path("/bin/true"),
    })
    started = time.monotonic()
    result = run_witness(manifest, nonce=NONCE, diagnostic_only=True)
    assert time.monotonic() - started < 10
    assert result.status == ValidationStatus.UNRESOLVED
    assert "worker_missing_or_invalid_result" in result.gaps


def test_diagnostic_runtime_rejects_shell_syntax_in_parent_path(tmp_path: Path):
    manifest = _manifest(tmp_path, DIRECT)
    with pytest.raises(ValueError, match="unsupported syntax"):
        run_witness(
            manifest, nonce=NONCE, diagnostic_only=True,
            diagnostic_runtime_dir=tmp_path / "bad;syntax",
        )


def test_worker_ignores_valid_looking_stale_checkout_bytecode(tmp_path: Path):
    manifest = _manifest(tmp_path, QUOTED)
    source_file = tmp_path / "sample.py"
    safe_source = source_file.read_text()
    expression = "shlex.quote(model_uri)"
    raw_expression = "model_uri" + " " * (len(expression) - len("model_uri"))
    unsafe_source = safe_source.replace(expression, raw_expression)
    assert len(unsafe_source) == len(safe_source)
    source_file.write_text(unsafe_source)
    py_compile.compile(str(source_file), doraise=True)
    original_stat = source_file.stat()
    source_file.write_text(safe_source)
    os.utime(source_file, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    result = run_witness(manifest, nonce=NONCE, diagnostic_only=True)
    assert result.status == ValidationStatus.UNRESOLVED
    assert result.details["reached_popen"] is True
    assert result.details["probe_replay"]["ok"] is True
    assert str(result.details["probe_path"]) in result.details["probe_replay"]["arguments"]
