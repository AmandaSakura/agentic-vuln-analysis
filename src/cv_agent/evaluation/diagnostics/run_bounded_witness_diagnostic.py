"""Run one positive-only witness in diagnostic mode and save its raw gaps."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cv_agent.evaluation.diagnostics.bounded_execution_witness import (
    WitnessManifest,
    run_witness,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("runtime_dir", type=Path)
    parser.add_argument("nonce")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if not args.runtime_dir.is_absolute():
        raise ValueError("shared diagnostic runtime path must be absolute")
    if args.output.exists():
        raise FileExistsError(args.output)
    manifest_bytes = args.manifest.read_bytes()
    manifest = WitnessManifest.model_validate_json(manifest_bytes)
    result = run_witness(
        manifest,
        nonce=args.nonce,
        diagnostic_only=True,
        diagnostic_runtime_dir=args.runtime_dir,
    )
    record = {
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "source_digest": manifest.subject.source_digest,
        "result": result.model_dump(mode="json"),
    }
    args.output.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    print(result.status.value, list(result.gaps), args.output)


if __name__ == "__main__":
    main()
