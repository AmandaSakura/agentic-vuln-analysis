"""Run one positive-only witness in diagnostic mode and save its raw gaps."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import time
from pathlib import Path

from cv_agent.evaluation.diagnostics.bounded_execution_witness import (
    WitnessManifest,
    IsolationReadGrant,
    run_witness,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("runtime_dir", type=Path)
    parser.add_argument("nonce")
    parser.add_argument("output", type=Path)
    parser.add_argument("--read-grants", type=Path,
                        help="JSON list of reviewed, identity-bound leaf read grants")
    args = parser.parse_args()
    if not args.runtime_dir.is_absolute():
        raise ValueError("shared diagnostic runtime path must be absolute")
    if args.output.exists():
        raise FileExistsError(args.output)
    manifest_bytes = args.manifest.read_bytes()
    manifest = WitnessManifest.model_validate_json(manifest_bytes)
    grant_bytes = args.read_grants.read_bytes() if args.read_grants else b"[]"
    grants = tuple(IsolationReadGrant.model_validate(item) for item in json.loads(grant_bytes))
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.monotonic()
    result = run_witness(
        manifest,
        nonce=args.nonce,
        diagnostic_only=True,
        diagnostic_runtime_dir=args.runtime_dir,
        diagnostic_read_grants=grants,
        diagnostic_trace_path=args.output.with_suffix(".strace.log").absolute(),
    )
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    record = {
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "source_digest": manifest.subject.source_digest,
        "read_policy_sha256": hashlib.sha256(grant_bytes).hexdigest(),
        "elapsed_seconds": time.monotonic() - start,
        "child_cpu_seconds": {
            "user": usage_after.ru_utime - usage_before.ru_utime,
            "system": usage_after.ru_stime - usage_before.ru_stime,
        },
        "result": result.model_dump(mode="json"),
    }
    args.output.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    print(result.status.value, list(result.gaps), args.output)


if __name__ == "__main__":
    main()
