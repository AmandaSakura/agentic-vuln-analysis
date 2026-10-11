"""A finite owned worker for the explicitly selected offline product v2.

No command, module, provider, or target interpreter is supplied by the source
request. The child only imports this project's static review implementation.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import traceback


LIMIT_VERSION = "product-resource-limits-v2"
DEFAULT_LIMITS = {
    "version": LIMIT_VERSION,
    "max_files": 1000,
    "max_source_bytes": 10 * 1024**2,
    "max_candidates": 1000,
    "max_ast_nodes": 200000,
    "max_record_bytes": 64 * 1024**2,
    "wall_seconds": 120,
    "cpu_seconds": 120,
    "memory_bytes": 1024**3,
}
MAX_REQUEST_BYTES = 1024**2
MAX_WORKER_RESPONSE_BYTES = 16 * 1024
MAX_PUBLIC_RESULT_BYTES = 64 * 1024**2
ALLOWED_OPTIONS = frozenset({"summary_bytes", "context_manifest", "context_bytes", "limits"})


def resource_limits(overrides: dict | None = None) -> dict:
    """Versioned finite caps; callers may lower, never silently remove, a cap."""
    if overrides is None:
        overrides = {}
    if type(overrides) is not dict or set(overrides) - DEFAULT_LIMITS.keys():
        raise ValueError("resource limits contain unsupported policy fields")
    result = {**DEFAULT_LIMITS, **overrides}
    if result["version"] != LIMIT_VERSION:
        raise ValueError("resource limits do not match the selected version")
    for name, ceiling in DEFAULT_LIMITS.items():
        if name == "version":
            continue
        value = result[name]
        if name == "wall_seconds":
            valid = type(value) in (int, float) and math.isfinite(value) and 0 < value <= ceiling
        else:
            valid = type(value) is int and 1 <= value <= ceiling
        if name == "memory_bytes":
            valid = valid and value >= 64 * 1024**2
        if not valid:
            raise ValueError(f"{name} must be positive, finite and no larger than its profile cap")
    return result


def _credential_name(name: str) -> bool:
    upper = name.upper()
    return (upper.endswith(("_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_CREDENTIAL", "_CREDENTIALS"))
            or "API_KEY" in upper or "ACCESS_KEY" in upper
            or upper in {"AZURE_OPENAI_AD_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS",
                         "KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "CREDENTIALS",
                         "APIKEY", "ACCESSKEY", "AUTHORIZATION", "SSH_AUTH_SOCK"})


def worker_environment() -> dict[str, str]:
    # Filter by name before indexing the environment: excluded values are never read.
    return {name: os.environ[name] for name in os.environ
            if not _credential_name(name) and name not in {"PYTHONPATH", "PYTHONHOME"}}


def _private_file(path: Path, mode: str):
    stream = path.open(mode)
    os.chmod(path, 0o600)
    return stream


def _progress_references(output: Path) -> tuple[str, ...]:
    """Reference existing local records without pretending they are validated counts."""
    names = ("result.json", "progress.jsonl", "wal.jsonl", ".private/observations.jsonl", ".private/events.jsonl", ".private/progress.jsonl")
    references = [str(output / name) for name in names if (output / name).is_file()]
    # The service's private staging prefix belongs to this requested output.
    # Compare literal names: a user path containing glob characters cannot
    # broaden the match to unrelated review directories.
    prefix = "." + output.name + "-v2-"
    for stage in output.parent.iterdir():
        if not stage.is_symlink() and stage.name.startswith(prefix) and stage.is_dir():
            progress = stage / ".private/progress.jsonl"
            if progress.is_file():
                references.append(str(progress))
    return tuple(sorted(references))


def _failure(state: str, reason: str, output: Path, control: Path, *, elapsed: float,
             phase: str = "worker", error_type: str | None = None,
             peak_rss_bytes: int | None = None) -> dict:
    envelope = {"schema_version": "product-boundary-v2", "run_state": state,
        "reason_code": reason, "phase": phase, "counts": None, "result": None,
        "error_type": error_type,
        "durable_progress": list(_progress_references(output)),
        "progress_verified": False,
        "accounting": {"wall_seconds": elapsed, "peak_rss_bytes": peak_rss_bytes,
                       "model_requests": 0, "target_executions": 0},
        "boundary_artifact": str(control / "boundary.json")}
    with _private_file(control / "boundary.json", "w") as stream:
        json.dump(envelope, stream, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return envelope


def _stop_owned(process) -> None:
    try:
        process.kill()
    except ProcessLookupError:
        pass
    process.wait()


def run_bounded_review(source_root: Path, output: Path, *, options: dict) -> dict:
    """Run one static review in one owned Linux worker and return a typed envelope."""
    if type(options) is not dict or set(options) - ALLOWED_OPTIONS:
        raise ValueError("unsupported bounded review options")
    limits = resource_limits(options.get("limits"))
    output = Path(output).absolute()
    source_root = Path(source_root).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError("Output path already exists; select a new run directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    control = Path(tempfile.mkdtemp(prefix=f".{output.name}.worker-", dir=output.parent))
    os.chmod(control, 0o700)
    started = time.monotonic()
    if sys.platform != "linux":
        return _failure("BLOCKED", "RESOURCE_BOUNDARY_PLATFORM_UNSUPPORTED", output, control,
                        elapsed=time.monotonic() - started, phase="preflight")
    request = {"source_root": str(source_root), "output": str(output),
               "options": {**options, "limits": limits}}
    payload = json.dumps(request, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(payload) > MAX_REQUEST_BYTES:
        return _failure("BLOCKED", "REVIEW_REQUEST_TOO_LARGE", output, control,
                        elapsed=time.monotonic() - started, phase="input")
    with _private_file(control / "stdout.json", "wb") as stdout, _private_file(control / "stderr.log", "wb") as stderr:
        try:
            process = subprocess.Popen([sys.executable, "-m", "cv_agent.application.product_boundary", "--worker"],
                stdin=subprocess.PIPE, stdout=stdout, stderr=stderr, cwd=control,
                env=worker_environment(), start_new_session=True)
        except KeyboardInterrupt:
            return _failure("CANCELLED", "REVIEW_CANCELLED", output, control,
                            elapsed=time.monotonic() - started)
        except OSError as error:
            return _failure("FAILED", "WORKER_START_FAILED", output, control,
                            elapsed=time.monotonic() - started, error_type=type(error).__name__)
        try:
            process.communicate(input=payload, timeout=limits["wall_seconds"])
        except subprocess.TimeoutExpired:
            _stop_owned(process)
            return _failure("PARTIAL", "WALL_TIME_LIMIT", output, control,
                            elapsed=time.monotonic() - started)
        except KeyboardInterrupt:
            _stop_owned(process)
            return _failure("CANCELLED", "REVIEW_CANCELLED", output, control,
                            elapsed=time.monotonic() - started)
    elapsed = time.monotonic() - started
    if process.returncode == -signal.SIGXCPU:
        return _failure("PARTIAL", "CPU_TIME_LIMIT", output, control, elapsed=elapsed)
    if process.returncode == -signal.SIGXFSZ:
        return _failure("PARTIAL", "LOCAL_RECORD_FILE_LIMIT", output, control, elapsed=elapsed,
                        phase="presentation")
    if process.returncode is not None and process.returncode < 0:
        return _failure("FAILED", "WORKER_SIGNAL", output, control, elapsed=elapsed,
                        error_type=signal.Signals(-process.returncode).name)
    response_path = control / "stdout.json"
    if response_path.stat().st_size > MAX_WORKER_RESPONSE_BYTES:
        return _failure("FAILED", "WORKER_PROTOCOL_ERROR", output, control, elapsed=elapsed)
    try:
        response = json.loads(response_path.read_bytes())
    except (ValueError, UnicodeError):
        return _failure("FAILED", "WORKER_PROTOCOL_ERROR", output, control, elapsed=elapsed)
    if type(response) is not dict or response.get("run_state") not in {
        "COMPLETED", "PARTIAL", "BLOCKED", "FAILED", "CANCELLED",
    }:
        return _failure("FAILED", "WORKER_PROTOCOL_ERROR", output, control, elapsed=elapsed)
    if process.returncode != 0 or response.get("reason_code") != "WORKER_COMPLETED":
        failed_state = "FAILED" if response["run_state"] == "COMPLETED" else response["run_state"]
        reason = response.get("reason_code", "WORKER_FAILED")
        if process.returncode != 0 and reason == "WORKER_COMPLETED":
            reason = "WORKER_EXIT_FAILURE"
        return _failure(failed_state, reason, output, control,
            elapsed=elapsed, phase=response.get("phase", "worker"), error_type=response.get("error_type"),
            peak_rss_bytes=response.get("peak_rss_bytes"))
    result_path = output / "result.json"
    if not result_path.is_file() or result_path.stat().st_size > MAX_PUBLIC_RESULT_BYTES:
        return _failure("FAILED", "PUBLIC_RESULT_UNAVAILABLE", output, control, elapsed=elapsed, phase="presentation")
    try:
        result = json.loads(result_path.read_bytes())
    except (ValueError, UnicodeError, OSError):
        return _failure("FAILED", "PUBLIC_RESULT_INVALID", output, control, elapsed=elapsed, phase="presentation")
    if type(result) is not dict or result.get("run_state") != response["run_state"]:
        return _failure("FAILED", "WORKER_RESULT_MISMATCH", output, control, elapsed=elapsed, phase="presentation")
    envelope = {"schema_version": "product-boundary-v2", "run_state": result["run_state"],
        "reason_code": "WORKER_COMPLETED", "phase": "completed", "counts": result.get("counts"),
        "result": result, "durable_progress": list(_progress_references(output)),
        "progress_verified": False, "boundary_artifact": None,
        "accounting": {"wall_seconds": elapsed, "peak_rss_bytes": response.get("peak_rss_bytes"),
                       "model_requests": 0, "target_executions": 0},
        "resource_limits": limits}
    shutil.rmtree(control)
    return envelope


def _emit_worker_response(response: dict) -> None:
    response["peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    print(json.dumps(response, sort_keys=True, allow_nan=False), flush=True)


def _worker_main() -> int:
    """Fixed internal entry; no user-selected program can pass through this path."""
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("worker request exceeds its finite input limit")
        request = json.loads(raw)
        options = request["options"]
        if type(options) is not dict or set(options) - ALLOWED_OPTIONS:
            raise ValueError("worker request options are invalid")
        limits = resource_limits(options.get("limits"))
        resource.setrlimit(resource.RLIMIT_AS, (limits["memory_bytes"], limits["memory_bytes"]))
        resource.setrlimit(resource.RLIMIT_CPU, (limits["cpu_seconds"], limits["cpu_seconds"] + 1))
        from cv_agent.application.service_v2 import run_review_v2
        result = run_review_v2(Path(request["source_root"]), Path(request["output"]), **options)
        value = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
        if type(value) is not dict:
            raise TypeError("review result is not a public JSON object")
        _emit_worker_response({"run_state": value["run_state"], "reason_code": "WORKER_COMPLETED",
                               "phase": "completed", "counts": value.get("counts")})
        return 0
    except KeyboardInterrupt:
        _emit_worker_response({"run_state": "CANCELLED", "reason_code": "REVIEW_CANCELLED", "phase": "worker"})
        return 2
    except MemoryError:
        _emit_worker_response({"run_state": "PARTIAL", "reason_code": "MEMORY_LIMIT", "phase": "worker"})
        return 2
    except Exception as error:
        traceback.print_exc(file=sys.stderr)
        from cv_agent.application.errors import ProductDeliveryError
        delivery_failure=isinstance(error,ProductDeliveryError)
        _emit_worker_response({"run_state": "FAILED", "reason_code": error.reason_code if delivery_failure else "WORKER_INTERNAL_ERROR",
                               "phase": error.stage if delivery_failure else "worker", "error_type": type(error).__name__})
        return 2


if __name__ == "__main__":
    if sys.argv[1:] != ["--worker"]:
        raise SystemExit("This module exposes only its fixed internal worker entry.")
    raise SystemExit(_worker_main())
