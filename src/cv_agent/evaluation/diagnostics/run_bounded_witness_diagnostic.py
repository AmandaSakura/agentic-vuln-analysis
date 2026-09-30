"""Run one positive-only witness in diagnostic mode and save its raw gaps."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import time
from pathlib import Path

from cv_agent.runtime.witness.kernel import (
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
    parser.add_argument("--no-strace", action="store_true",
                        help="keep isolation and the command audit hook without syscall tracing")
    parser.add_argument("--dump-stacks", action="store_true",
                        help="capture all-thread Python stacks three seconds before the worker deadline")
    parser.add_argument('--verify-obligations', action='store_true',
                        help='verify runtime assumptions/preexec and run the benign target control')
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
        diagnostic_only=not args.verify_obligations,
        diagnostic_runtime_dir=args.runtime_dir,
        diagnostic_read_grants=grants,
        diagnostic_trace_path=(None if args.no_strace else
                               args.output.with_suffix(".strace.log").absolute()),
        diagnostic_stack_capture=args.dump_stacks,
        verify_obligations=args.verify_obligations,
    )
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    record = {
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "source_digest": manifest.subject.source_digest,
        "read_policy_sha256": hashlib.sha256(grant_bytes).hexdigest(),
        "resource_profile": manifest.resource_profile.model_dump(mode="json"),
        "strace_enabled": not args.no_strace,
        "stack_capture_enabled": args.dump_stacks,
        'verification_mode': args.verify_obligations,
        "elapsed_seconds": time.monotonic() - start,
        "child_cpu_seconds": {
            "user": usage_after.ru_utime - usage_before.ru_utime,
            "system": usage_after.ru_stime - usage_before.ru_stime,
        },
        "resource_accounting": result.details.get("probe_event", {}).get("resource_accounting"),
        "result": result.model_dump(mode="json"),
    }
    args.output.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    print(result.status.value, list(result.gaps), args.output)


if __name__ == "__main__":
    main()
