"""Owned static scale and digest instrumentation; no real model/target execution.

Run with the project's installed interpreter. Generated input files live outside
protected project data trees. Each invocation preserves a separate result run.
The timings include instrumentation overhead and are descriptive observations.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import resource
import tempfile
import time
from types import SimpleNamespace
from uuid import uuid4

from cv_agent.application.product_boundary import DEFAULT_LIMITS, run_bounded_review
from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.retrieval.index import FrozenRepositoryIndex
from cv_agent.tools import identity


SCALES = (100, 500, 1000)
OWNED_TEXT = "import os\ndef review_mode(path):\n    os.chmod(path, 0o750)\n"
ROOT = Path(__file__).resolve().parents[2]
OUTPUT_ROOT = ROOT / "audit/product_recovery_20261001/scale_runs"


def digest_measurement(size: int, *, sealed: bool = False) -> dict:
    documents = [CodeDocument(repository_id="owned-scale", path=f"module_{number:04d}.py",
        text=OWNED_TEXT, language="python", adapter_tier="ast", defines=(f"module_{number:04d}.review_mode",),
        import_aliases={"os": "os"}, imports=("os",), calls=("os.chmod",)) for number in range(size)]
    original_json = identity.json
    original_dump = CodeDocument.model_dump
    counters = {"digest_calls": 0, "json_serializations": 0,
                "serialized_bytes": 0, "document_serializations": 0}

    def dumps(value, *args, **kwargs):
        serialized = original_json.dumps(value, *args, **kwargs)
        counters["json_serializations"] += 1
        counters["serialized_bytes"] += len(serialized.encode("utf-8"))
        return serialized

    def model_dump(document, *args, **kwargs):
        counters["document_serializations"] += 1
        return original_dump(document, *args, **kwargs)

    identity.json = SimpleNamespace(dumps=dumps)
    CodeDocument.model_dump = model_dump
    started = time.perf_counter()
    index = FrozenRepositoryIndex(documents) if sealed else RepositoryIndex(documents)
    index_seconds = time.perf_counter() - started
    started = time.perf_counter()
    try:
        digests = []
        for _ in range(size):
            counters["digest_calls"] += 1
            digests.append(identity.repository_source_digest(index))
    finally:
        measured_seconds = time.perf_counter() - started
        identity.json = original_json
        CodeDocument.model_dump = original_dump
    assert len(set(digests)) == 1
    assert counters["json_serializations"] == (1 if sealed else size)
    return {"source_files": size, "indexed_documents": size,
        "source_bytes": len(OWNED_TEXT.encode("utf-8")) * size,
        "index_seconds": index_seconds, "digest_seconds": measured_seconds,
        "peak_process_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        "digest": digests[0], **counters,
        "scope": "fresh owned lexical indices; N identical source-digest consumer calls",
        "index_type": "FrozenRepositoryIndex" if sealed else "RepositoryIndex",
        "cache_build_included_in_index_seconds": sealed,
        "instrumentation": "Counts model_dump and JSON UTF8 bytes; elapsed includes instrumentation overhead."}


def scale_measurement(size: int, run_directory: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="cv-agent-owned-scale-") as directory:
        source = Path(directory)
        for number in range(size):
            (source / f"module_{number:04d}.py").write_text(OWNED_TEXT, encoding="utf-8")
        output = run_directory / f"review_{size}"
        envelope = run_bounded_review(source, output, options={})
        result = envelope["result"]
        output_bytes = sum(path.stat().st_size for path in output.rglob("*") if path.is_file()) if output.exists() else None
        return {"generated_files": size, "generated_source_bytes": len(OWNED_TEXT.encode()) * size,
            "run_state": envelope["run_state"], "reason_code": envelope["reason_code"],
            "boundary_accounting": envelope["accounting"], "resource_limits": DEFAULT_LIMITS,
            "counts": result.get("counts") if result else None,
            "phase_accounting": result.get("accounting") if result else None,
            "output_bytes": output_bytes, "output": str(output),
            "boundary_artifact": envelope["boundary_artifact"],
            "source_removed_after_run": True,
            "source_generation_sha256": hashlib.sha256(OWNED_TEXT.encode()).hexdigest()}


def main() -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
    run_directory = OUTPUT_ROOT / stamp
    run_directory.mkdir(parents=True)
    result = {"measurement_version": "owned-static-scale-v1", "created_utc": stamp,
        "python": platform.python_version(), "platform": platform.platform(),
        "scales": list(SCALES), "project_model_requests": 0, "target_executions": 0,
        "inference_limit": "Single owned workload observations; no cold/warm causal speedup or real-repository generalization claim.",
        "digest_measurements": [], "sealed_digest_measurements": [], "review_measurements": []}
    receipt = run_directory / "measurement.json"
    for size in SCALES:
        result["digest_measurements"].append(digest_measurement(size))
        result["sealed_digest_measurements"].append(digest_measurement(size, sealed=True))
        receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(f"digest scale={size} complete", flush=True)
    if importlib.util.find_spec("cv_agent.application.service_v2") is None:
        result["review_scale_status"] = "SERVICE_V2_NOT_AVAILABLE"
    else:
        result["review_scale_status"] = "MEASURED"
        for size in SCALES:
            result["review_measurements"].append(scale_measurement(size, run_directory))
            receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
            print(f"review scale={size} complete", flush=True)
    receipt.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(str(receipt), flush=True)


if __name__ == "__main__":
    main()
