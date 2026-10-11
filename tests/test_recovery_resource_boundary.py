"""Offline owned-worker controls for R12; no target source is executed."""
import importlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

import pytest


def boundary():
    return importlib.import_module("cv_agent.application.product_boundary")


def test_boundary_requires_finite_versioned_limits():
    module = boundary()
    limits = module.resource_limits({})
    assert limits["wall_seconds"] == 120
    assert limits["memory_bytes"] == 1024**3
    assert limits["max_files"] == 1000
    assert limits["max_source_bytes"] == 10 * 1024**2
    assert limits["max_candidates"] == 1000
    assert limits["max_ast_nodes"] == 200000
    assert limits["max_record_bytes"] == 64 * 1024**2


@pytest.mark.parametrize("limits", [
    {"wall_seconds": 0}, {"wall_seconds": float("inf")}, {"wall_seconds": float("nan")},
    {"memory_bytes": -1}, {"memory_bytes": 2 * 1024**3},
    {"memory_bytes": 32 * 1024**2},
    {"max_files": True}, {"max_candidates": 0}, {"unknown_policy": 1},
    {"version": "not-this-profile"},
])
def test_unbounded_or_ambiguous_limits_are_rejected(limits):
    with pytest.raises(ValueError):
        boundary().resource_limits(limits)


def install_owned_child(monkeypatch, script):
    """Replace only process construction with a known project-owned helper."""
    module = boundary()
    real_popen = subprocess.Popen
    launched = []

    def owned_popen(command, **kwargs):
        assert command[:3] == [sys.executable, "-m", "cv_agent.application.product_boundary"]
        assert command[3:] == ["--worker"]
        process = real_popen([sys.executable, "-c", script], **kwargs)
        launched.append((command, kwargs, process))
        return process

    monkeypatch.setattr(module.subprocess, "Popen", owned_popen)
    return launched


def test_timeout_kills_only_owned_worker_and_retains_unknown_denominators(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    launched = install_owned_child(monkeypatch, "import time; time.sleep(30)")
    result = boundary().run_bounded_review(source, tmp_path / "out", options={"limits": {"wall_seconds": 0.05}})
    assert result["run_state"] == "PARTIAL"
    assert result["reason_code"] == "WALL_TIME_LIMIT"
    assert result["phase"] == "worker"
    assert result["counts"] is None
    assert result["result"] is None
    assert len(launched) == 1
    assert launched[0][2].poll() is not None
    assert Path(result["boundary_artifact"]).is_file()
    assert result["accounting"]["model_requests"] == 0
    assert result["accounting"]["target_executions"] == 0


def test_worker_environment_drops_credentials_without_reading_their_values(tmp_path, monkeypatch):
    module = boundary()
    seen = []
    actual = dict(os.environ)
    actual.update({"OPENAI_API_KEY": "owned-placeholder", "AWS_SESSION_TOKEN": "owned-placeholder", "PYTHONPATH": "untrusted-path", "PYTHONHOME": "untrusted-home"})

    class Environment(dict):
        def __getitem__(self, key):
            if key in {"OPENAI_API_KEY", "AWS_SESSION_TOKEN"}:
                pytest.fail("credential value was loaded")
            seen.append(key)
            return super().__getitem__(key)

    monkeypatch.setattr(module.os, "environ", Environment(actual))
    env = module.worker_environment()
    assert "OPENAI_API_KEY" not in env and "AWS_SESSION_TOKEN" not in env
    assert "PYTHONPATH" not in env and "PYTHONHOME" not in env
    assert "PATH" in env


def test_worker_cwd_cannot_import_a_target_local_package(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    launched = install_owned_child(monkeypatch, "import json; print(json.dumps({'run_state':'FAILED','reason_code':'OWNED_CONTROL','phase':'worker','counts':None}))")
    result = boundary().run_bounded_review(source, tmp_path / "out", options={})
    assert Path(launched[0][1]["cwd"]) != source
    assert Path(launched[0][1]["cwd"]).parent == tmp_path
    assert result["reason_code"] == "OWNED_CONTROL"


def test_worker_signal_is_not_a_semantic_unknown(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    install_owned_child(monkeypatch, "import os,signal; os.kill(os.getpid(),signal.SIGXCPU)")
    result = boundary().run_bounded_review(source, tmp_path / "out", options={})
    assert result["reason_code"] == "CPU_TIME_LIMIT"
    assert result["run_state"] == "PARTIAL"
    assert result["counts"] is None


def test_existing_output_is_not_overwritten_or_reexecuted(tmp_path, monkeypatch):
    output = tmp_path / "out"
    output.mkdir()
    (output / "sentinel").write_text("preserve")
    monkeypatch.setattr(boundary().subprocess, "Popen", lambda *args, **kwargs: pytest.fail("existing output started worker"))
    with pytest.raises(FileExistsError):
        boundary().run_bounded_review(tmp_path, output, options={})
    assert (output / "sentinel").read_text() == "preserve"


def test_worker_success_uses_complete_public_artifact_without_pipe_findings(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "out"
    script = """import json, pathlib, sys
request=json.load(sys.stdin)
out=pathlib.Path(request['output']); out.mkdir()
value={'run_state':'COMPLETED','counts':{'candidate_count':1},'accounting':{'model_requests':0}}
(out/'result.json').write_text(json.dumps(value))
print(json.dumps({'run_state':'COMPLETED','reason_code':'WORKER_COMPLETED','phase':'completed','counts':value['counts'],'peak_rss_bytes':12345}))
"""
    launched = install_owned_child(monkeypatch, script)
    result = boundary().run_bounded_review(source, output, options={})
    assert result["run_state"] == "COMPLETED"
    assert result["result"]["counts"]["candidate_count"] == 1
    assert result["accounting"]["peak_rss_bytes"] == 12345
    assert not Path(launched[0][1]["cwd"]).exists()


def test_invalid_worker_output_keeps_error_and_private_records(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    install_owned_child(monkeypatch, "print('not-json')")
    result = boundary().run_bounded_review(source, tmp_path / "out", options={})
    assert result["run_state"] == "FAILED"
    assert result["reason_code"] == "WORKER_PROTOCOL_ERROR"
    assert Path(result["boundary_artifact"]).is_file()
    assert result["counts"] is None


def test_cancellation_kills_and_waits_for_owned_worker(tmp_path, monkeypatch):
    module = boundary()

    class OwnedProcess:
        returncode = None
        killed = False
        waited = False

        def communicate(self, *args, **kwargs):
            raise KeyboardInterrupt()

        def kill(self):
            self.killed = True
            self.returncode = -signal.SIGKILL

        def wait(self):
            self.waited = True
            return self.returncode

    owned = OwnedProcess()
    monkeypatch.setattr(module.subprocess, "Popen", lambda *args, **kwargs: owned)
    try:
        result = module.run_bounded_review(tmp_path, tmp_path / "out", options={})
    except KeyboardInterrupt:
        pytest.fail("cancellation escaped the bounded review API")
    assert result["run_state"] == "CANCELLED"
    assert result["reason_code"] == "REVIEW_CANCELLED"
    assert owned.killed and owned.waited
    assert result["counts"] is None


def test_cancellation_before_worker_ownership_is_explicit_and_starts_no_later_worker(tmp_path, monkeypatch):
    module = boundary()
    attempts = []

    def interrupted(*args, **kwargs):
        attempts.append(args)
        raise KeyboardInterrupt()

    monkeypatch.setattr(module.subprocess, "Popen", interrupted)
    try:
        result = module.run_bounded_review(tmp_path, tmp_path / "out", options={})
    except KeyboardInterrupt:
        pytest.fail("startup cancellation escaped the bounded review API")
    assert result["run_state"] == "CANCELLED"
    assert result["reason_code"] == "REVIEW_CANCELLED"
    assert result["counts"] is None
    assert len(attempts) == 1


def test_real_owned_worker_memory_limit_reports_resource_failure(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    script = """import sys, types
stub=types.ModuleType('cv_agent.application.service_v2')
def owned_review(*args, **kwargs):
    return bytearray(256 * 1024**2)
stub.run_review_v2=owned_review
sys.modules[stub.__name__]=stub
from cv_agent.application.product_boundary import _worker_main
raise SystemExit(_worker_main())
"""
    install_owned_child(monkeypatch, script)
    result = boundary().run_bounded_review(source, tmp_path / "out", options={"limits": {"memory_bytes": 64 * 1024**2}})
    assert result["run_state"] == "PARTIAL"
    assert result["reason_code"] == "MEMORY_LIMIT"
    assert result["counts"] is None
    assert result["accounting"]["peak_rss_bytes"] > 0


def test_real_owned_worker_cpu_limit_terminates_static_work(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    script = """import sys, types
stub=types.ModuleType('cv_agent.application.service_v2')
def owned_review(*args, **kwargs):
    while True:
        pass
stub.run_review_v2=owned_review
sys.modules[stub.__name__]=stub
from cv_agent.application.product_boundary import _worker_main
raise SystemExit(_worker_main())
"""
    install_owned_child(monkeypatch, script)
    result = boundary().run_bounded_review(source, tmp_path / "out", options={"limits": {"cpu_seconds": 1, "wall_seconds": 5}})
    assert result["run_state"] == "PARTIAL"
    assert result["reason_code"] == "CPU_TIME_LIMIT"
    assert result["counts"] is None


def test_nonzero_worker_exit_never_claims_completed(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    install_owned_child(monkeypatch, "import json,sys; print(json.dumps({'run_state':'COMPLETED','reason_code':'WORKER_COMPLETED'})); sys.exit(2)")
    result = boundary().run_bounded_review(source, tmp_path / "out", options={})
    assert result["run_state"] == "FAILED"
    assert result["result"] is None
