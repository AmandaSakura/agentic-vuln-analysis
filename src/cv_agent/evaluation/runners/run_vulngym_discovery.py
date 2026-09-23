"""Build a complete source-only candidate inventory for the frozen VulnGym split."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
from uuid import uuid4

from cv_agent.agents.discovery import discover_python_repository
from cv_agent.code_adapters.source_files import read_source_bytes
from cv_agent.evaluation.preparation.prepare_vulngym_checkouts import (
    ensure_checkout,
    remove_checkout,
)
from cv_agent.runtime.paths import PROJECT_ROOT
from cv_agent.runtime.provenance import git_identity
from cv_agent.runtime.snapshots import snapshot_sources


FORBIDDEN_DETECTOR_FIELDS = {
    "entry_id", "report_id", "critical_operation", "entry_point", "verify",
    "ground_truth", "expected_label", "vulnerability_label", "labels",
}


def validate_detector_manifest(manifest: dict) -> None:
    if manifest.get("role") != "heldout_candidate_inputs" or manifest.get("claim_eligible") is not False:
        raise ValueError("Discovery requires the frozen label-free candidate manifest")
    if set(manifest) - {"dataset_identity", "role", "claim_eligible", "split_version", "subjects"}:
        raise ValueError("Unexpected field in detector manifest")
    seen = set()
    for subject in manifest.get("subjects", []):
        if set(subject) != {"repository_url", "commit"}:
            raise ValueError("Detector subjects may contain only repository URL and pinned commit")
        identity = (subject["repository_url"].lower().rstrip("/"), subject["commit"])
        if identity in seen:
            raise ValueError(f"Duplicate detector subject: {identity}")
        seen.add(identity)
    serialized = json.dumps(manifest).lower()
    if any(field in serialized for field in FORBIDDEN_DETECTOR_FIELDS):
        raise ValueError("Evaluator label fields are forbidden in detector inputs")
    if not seen:
        raise ValueError("Detector manifest has no source subjects")


def save_json(path: Path, value) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def verify_source_snapshot(source_root: Path, report: dict) -> None:
    for relative, expected in report["source_sha256"].items():
        actual = hashlib.sha256(read_source_bytes(source_root, relative)).hexdigest()
        if actual != expected:
            raise ValueError(f"Pinned source changed during discovery: {relative}")


def run(manifest_path: Path, *, root: Path = PROJECT_ROOT, output: Path | None = None) -> Path:
    manifest = json.loads(manifest_path.read_text())
    validate_detector_manifest(manifest)
    if output is not None and output.exists():
        inventory_path = output / "inventory.json"
        if not inventory_path.exists():
            raise FileExistsError(f"Output directory exists without inventory: {output}")
        inventory = json.loads(inventory_path.read_text())
        if inventory.get("run_state") == "complete":
            return output
        if inventory.get("run_state") == "interrupted":
            if inventory.get("dataset_identity") != manifest["dataset_identity"]:
                raise ValueError("Dataset identity mismatch on resume")
            inventory["run_state"] = "running"
            inventory.pop("error_type", None)
            save_json(inventory_path, inventory)
        else:
            raise ValueError(f"Run in state {inventory.get('run_state')} cannot be resumed")
    else:
        output = output or root / "artifacts/vulngym_discovery" / uuid4().hex
        output.mkdir(parents=True, exist_ok=False)
        source_hashes = snapshot_sources(root, output)
        inventory = {
            "dataset_identity": manifest["dataset_identity"],
            "dataset_role": manifest["role"],
            "claim_eligible": False,
            "candidate_protocol": "source_only_static_discovery",
            "selection_protocol": "complete inventory of all discovered candidates; no first-N or reference-based selection",
            "systems": [],
            "run_state": "running",
            "subjects": [],
        }
        save_json(output / "inventory.json", inventory)
        save_json(output / "results.json", [])
        save_json(output / "metadata.json", {
            "manifest": manifest,
            "source_sha256": source_hashes,
            "model_requests": 0,
            "claim_eligible": False,
        })
    try:
        completed = {
            (s["repository_url"].lower().rstrip("/"), s["commit"])
            for s in inventory["subjects"]
        }
        total = len(manifest["subjects"])
        for position, subject in enumerate(manifest["subjects"], start=1):
            identity_key = (subject["repository_url"].lower().rstrip("/"), subject["commit"])
            if identity_key in completed:
                continue
            source_root = ensure_checkout(
                subject["repository_url"], subject["commit"],
                root / "data/vulngym-evaluation-git",
                root / "data/vulngym-heldout-subjects",
            )
            try:
                identity = git_identity(source_root)
                if identity.revision != subject["commit"] or identity.dirty:
                    raise ValueError(f"Source checkout differs from frozen commit: {source_root}")
                repository_id = f"subject-{position:03d}"
                discovery = discover_python_repository(source_root, repository_id)
                verify_source_snapshot(source_root, discovery.report)
                candidates = [candidate.model_dump(mode="json") for candidate in discovery.candidates]
            finally:
                final_identity = git_identity(source_root)
                if final_identity.revision == subject["commit"] and not final_identity.dirty:
                    remove_checkout(
                        subject["repository_url"], subject["commit"],
                        root / "data/vulngym-evaluation-git",
                        root / "data/vulngym-heldout-subjects",
                    )
            inventory["subjects"].append({
                "repository_id": repository_id,
                "repository_url": subject["repository_url"],
                "commit": subject["commit"],
                "source_prefix": ".",
                "discovery": discovery.report,
                "candidates": candidates,
                "selected_case_ids": [candidate["case_id"] for candidate in candidates],
            })
            save_json(output / "inventory.json", inventory)
            print(f"discovered {position}/{total}: {subject['repository_url']}@{subject['commit']} "
                  f"{len(candidates)} candidates", flush=True)
        inventory["run_state"] = "complete"
        save_json(output / "inventory.json", inventory)
    except (Exception, KeyboardInterrupt) as error:
        inventory["run_state"] = "interrupted"
        inventory["error_type"] = type(error).__name__
        save_json(output / "inventory.json", inventory)
        raise
    return output


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run VulnGym candidate discovery")
    parser.add_argument("manifest", type=Path, nargs="?", default=PROJECT_ROOT / "configs/datasets/vulngym_heldout_inputs_v4.json")
    parser.add_argument("--output", type=Path, default=None, help="Output directory to create or resume")
    args = parser.parse_args()
    run(args.manifest, output=args.output)


if __name__ == "__main__":
    main()
