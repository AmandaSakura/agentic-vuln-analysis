"""Measure domain snapshot copy entry calls in complete owned static v2 runs.

Instrumentation lives only in this audit process. Source/test files and the
ordinary product strategy stay unchanged. These counts exclude recursion inside
copy.deepcopy, Pydantic internals, plain dict/list copies and other modules.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import signal
import subprocess
import sys
import tempfile
import time
from uuid import uuid4


SCALES = (100, 500, 1000)
OWNED_TEXT = "import os\ndef review_mode(path):\n    os.chmod(path, 0o750)\n"
ROOT = Path(__file__).resolve().parents[2]
OUTPUT_ROOT = ROOT / "audit/product_recovery_20261001/copy_runs"
WALL_SECONDS = CPU_SECONDS = 120
ADDRESS_SPACE_BYTES = 1024**3


def source_manifest():
    files = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in sorted((ROOT / "src").rglob("*"))
             if path.is_file() and "__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"}}
    return {"algorithm": "full-src-manifest-sha256-v1", "files": files,
        "file_count": len(files), "aggregate_sha256": hashlib.sha256(
            json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}


def child(size: int, output: Path) -> dict:
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_BYTES, ADDRESS_SPACE_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS + 1))
    # Import the actual service before patching: module startup is outside the
    # reported counters, while its entire subsequent review remains measured.
    from cv_agent.application import service_v2 as service
    from cv_agent.domain import types as domain_types

    phase = "run_overhead"
    counts = Counter()
    seconds = defaultdict(float)
    phase_seconds = defaultdict(float)
    original_copy = domain_types.deepcopy
    originals = []
    before = source_manifest()

    def measured_copy(value, *args, **kwargs):
        caller = sys._getframe(1)
        owner = caller.f_locals.get("self")
        method = caller.f_code.co_name
        site = {"__getattribute__": "public_field_read", "_seal_containers": "construction_sealing",
                "model_copy": "explicit_deep_model_copy"}.get(method, "other_domain_copy")
        field = caller.f_locals.get("name", "-")
        if type(field) is not str:
            field = "-"
        key = (phase, site, type(owner).__name__ if owner is not None else "-", field)
        counts[key] += 1
        started = time.perf_counter()
        try:
            return original_copy(value, *args, **kwargs)
        finally:
            seconds[key] += time.perf_counter() - started

    @contextmanager
    def during(name):
        nonlocal phase
        previous = phase
        phase = name
        started = time.perf_counter()
        try:
            yield
        finally:
            phase_seconds[name] += time.perf_counter() - started
            phase = previous

    def wrap(owner, name, label):
        original = getattr(owner, name)

        def measured(*args, **kwargs):
            selected = label
            if phase.startswith("verification") and not label.startswith("verification"):
                selected = "verification_tool_replay" if name == "analyze_operation" else "verification_" + label
            with during(selected):
                return original(*args, **kwargs)

        originals.append((owner, name, original))
        setattr(owner, name, measured)

    domain_types.deepcopy = measured_copy
    for name, label in (
        ("freeze_source_snapshot", "source_snapshot"),
        ("discover_python_repository", "discovery_index"),
        ("discover_operations", "operation_inventory"),
        ("analyze_operation", "analysis_tool"),
        ("read_descriptor", "record_read"),
        ("reduce_observations", "property_reduction"),
        ("verify_bundle", "verification_package"),
        ("derive_packaged_documents", "verification_rebuild_source_documents"),
        ("derive_packaged_operations", "verification_rebuild_operations"),
        ("_write", "package_write"),
    ):
        wrap(service, name, label)
    wrap(service.EvidenceStore, "persist", "local_evidence_persistence")
    started = time.monotonic()
    result = None
    error = None
    try:
        with tempfile.TemporaryDirectory(prefix="cv-agent-owned-copy-") as directory:
            source = Path(directory)
            for number in range(size):
                (source / f"module_{number:04d}.py").write_text(OWNED_TEXT, encoding="utf-8")
            result = service.run_review_v2(source, output)
    except MemoryError:
        error = {"run_state": "PARTIAL", "reason_code": "MEMORY_LIMIT"}
    except KeyboardInterrupt:
        error = {"run_state": "CANCELLED", "reason_code": "REVIEW_CANCELLED"}
    except Exception as failure:
        error = {"run_state": "FAILED", "reason_code": "OWNED_PROFILE_FAILED", "error_type": type(failure).__name__}
    finally:
        elapsed = time.monotonic() - started
        domain_types.deepcopy = original_copy
        for owner, name, original in reversed(originals):
            setattr(owner, name, original)
    after = source_manifest()
    rows = [{"phase": key[0], "site": key[1], "model": key[2], "field": key[3],
             "calls": counts[key], "original_copy_seconds_instrumented": seconds[key]}
            for key in sorted(counts)]
    by_site, by_phase = Counter(), Counter()
    for row in rows:
        by_site[row["site"]] += row["calls"]
        by_phase[row["phase"]] += row["calls"]
    value = result.model_dump(mode="json") if result is not None else None
    return {"size": size, "run_state": value["run_state"] if value else error["run_state"],
        "reason_code": "OWNED_PROFILE_COMPLETED" if value else error["reason_code"],
        "counts": value["counts"] if value else None,
        "accounting": value["accounting"] if value else None,
        "deepcopy_entry_calls": sum(counts.values()), "deepcopy_by_site": dict(by_site),
        "deepcopy_by_phase": dict(by_phase), "deepcopy_rows": rows,
        "instrumented_phase_seconds": dict(phase_seconds),
        "instrumented_wall_seconds": elapsed,
        "peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        "kernel_limits": {"wall_seconds": WALL_SECONDS, "cpu_seconds": CPU_SECONDS, "address_space_bytes": ADDRESS_SPACE_BYTES},
        "source_before": before, "source_after": after, "source_unchanged": before["files"] == after["files"],
        "instrumentation": "domain.types.deepcopy entry calls only, after actual service imports. Includes public field reads, container sealing and explicit deep copies; excludes recursive copy.deepcopy entries, other modules, Pydantic internals and plain collection copies. Phase wrappers preserve original functions and values. Wall/copy timings include instrumentation and do not estimate causal product speedup. Nested phase timings overlap and must not be summed.",
        "source_generation_sha256": hashlib.sha256(OWNED_TEXT.encode()).hexdigest(),
        "generated_source_bytes": len(OWNED_TEXT.encode()) * size,
        "target_executions": 0, "model_requests": 0, "output": str(output)}


def main():
    from cv_agent.application.product_boundary import worker_environment

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
    run = OUTPUT_ROOT / stamp
    run.mkdir(parents=True)
    before = source_manifest()
    receipt = {"version": "owned-public-copy-profile-v1", "python": platform.python_version(),
        "source_before": before, "profiles": [],
        "concurrent_load": "Parent complete offline pytest suite on the same host.",
        "scope": "Complete actual v2 review of generated literal-mode750 sources, one instrumented observation per size. No synthetic field-access loop, no existing test data, no source/test mutation, no copy optimization.",
        "inference_limit": "Resident RSS is not virtual address-space usage or a resource-limit guarantee; copied bytes and all-system copy work are not measured."}
    for size in SCALES:
        control = run / f"control_{size}"
        control.mkdir(mode=0o700)
        request = json.dumps({"output": str(run / f"review_{size}")}).encode()
        with (control / "stdout.json").open("wb") as stdout, (control / "stderr.log").open("wb") as stderr:
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--owned-worker", str(size)],
                stdin=subprocess.PIPE, stdout=stdout, stderr=stderr, cwd=control,
                env=worker_environment(), start_new_session=True)
            try:
                process.communicate(input=request, timeout=WALL_SECONDS)
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as failure:
                process.kill(); process.wait()
                receipt["profiles"].append({"size": size, "run_state": "PARTIAL" if isinstance(failure, subprocess.TimeoutExpired) else "CANCELLED",
                    "reason_code": "WALL_TIME_LIMIT" if isinstance(failure, subprocess.TimeoutExpired) else "REVIEW_CANCELLED",
                    "counts": None, "deepcopy_entry_calls": None, "control": str(control)})
                continue
        raw = control / "stdout.json"
        if process.returncode == 0 and raw.stat().st_size <= 1024**2:
            profile = json.loads(raw.read_text())
            receipt["profiles"].append(profile)
        else:
            receipt["profiles"].append({"size": size, "run_state": "PARTIAL" if process.returncode == -signal.SIGXCPU else "FAILED",
                "reason_code": "CPU_TIME_LIMIT" if process.returncode == -signal.SIGXCPU else "OWNED_WORKER_LOST",
                "counts": None, "deepcopy_entry_calls": None, "control": str(control)})
        (run / "measurement.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        print(f"copy profile scale={size} complete", flush=True)
    receipt["source_after"] = source_manifest()
    receipt["source_unchanged"] = before["files"] == receipt["source_after"]["files"]
    (run / "measurement.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(str(run / "measurement.json"), flush=True)


if __name__ == "__main__":
    if sys.argv[1:]:
        if len(sys.argv) != 3 or sys.argv[1] != "--owned-worker" or int(sys.argv[2]) not in SCALES:
            raise SystemExit("Only fixed owned scale workers are supported")
        request = json.load(sys.stdin)
        print(json.dumps(child(int(sys.argv[2]), Path(request["output"])), sort_keys=True), flush=True)
    else:
        main()
