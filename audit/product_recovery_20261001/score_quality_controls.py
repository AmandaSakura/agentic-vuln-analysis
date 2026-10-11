"""Invoke the public product CLI on source-only controls; score afterwards."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile")
    args = parser.parse_args()
    cli = args.cli.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    reference = json.loads((HERE / "quality_reference.json").read_text())
    environment = {"PATH": str(cli.parent) + ":/usr/bin:/bin", "LANG": "C.UTF-8",
                   "PYTHONNOUSERSITE": "1", "UV_OFFLINE": "1"}
    observations = []
    confusion = Counter()
    with tempfile.TemporaryDirectory(prefix="cv-agent-owned-quality-") as external:
        work = Path(external)
        for case in reference["cases"]:
            source_root = work / "inputs" / case["case_id"]
            shutil.copytree(HERE / "quality_controls" / case["case_id"], source_root)
            assert hashlib.sha256((source_root / case["source_path"]).read_bytes()).hexdigest() == case["source_sha256"]
            command = [str(cli), "review", str(source_root), "--output", str(work / "outputs" / case["case_id"])]
            if args.profile is not None:
                command += ["--profile", args.profile]
            start = time.monotonic()
            completed = subprocess.run(command, cwd=work, env=environment, capture_output=True, text=True, timeout=60)
            elapsed = time.monotonic() - start
            (args.output / (case["case_id"] + ".stdout.json")).write_text(completed.stdout)
            (args.output / (case["case_id"] + ".stderr.txt")).write_text(completed.stderr)
            result = json.loads(completed.stdout)
            findings = [finding for finding in result.get("findings", ())
                        if finding["subject"].get("property_id") == case["property_id"]
                        and finding["subject"].get("entry_path", "").split("::", 1)[0] == case["source_path"]
                        and finding["subject"].get("entry_line") == case["selected_line"]]
            actual = findings[0]["property_state"] if len(findings) == 1 else "MISSING_OR_DUPLICATE"
            confusion[(case["expected_state"], actual)] += 1
            selected = findings[0] if len(findings) == 1 else None
            observations.append({"case_id": case["case_id"], "expected": case["expected_state"], "actual": actual,
                                 "matched_exact_selected_location": len(findings) == 1,
                                 "return_code": completed.returncode, "run_state": result.get("run_state"),
                                 "model_requests": result.get("accounting", {}).get("model_requests"),
                                 "candidate_count": result.get("counts", {}).get("candidate_total", result.get("counts", {}).get("candidate_count")),
                                 "wall_seconds": elapsed, "selected_finding": selected})
    report = {"protocol": reference["protocol"], "reference": "quality_reference.json",
              "input_labels": "not supplied", "human_independent": False, "held_out_claim_eligible": False,
              "case_count": len(observations), "exact_state_matches": sum(x["expected"] == x["actual"] for x in observations),
              "wrong_strong_states": sum(x["actual"] in {"SUPPORTED", "REFUTED", "CONFLICT"}
                                         and x["actual"] != x["expected"] for x in observations),
              "missing_or_duplicate_locations": sum(not x["matched_exact_selected_location"] for x in observations),
              "confusion": [{"expected": key[0], "actual": key[1], "count": count}
                            for key, count in sorted(confusion.items())], "observations": observations}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("case_count", "exact_state_matches", "wrong_strong_states", "missing_or_duplicate_locations", "confusion")}, indent=2))


if __name__ == "__main__":
    main()
