"""Freeze a repository-disjoint VulnGym source split and evaluator references."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cv_agent.evaluation.datasets.heldout_manifest import repository_key
from cv_agent.runtime.paths import PROJECT_ROOT


def build_split(inputs: dict[str, Any], labels: dict[str, dict[str, Any]],
                exclusions: list[dict[str, str]], split_version: int) -> tuple[dict, dict, dict]:
    excluded = {repository_key(row["repository_url"]) for row in exclusions}
    if not excluded:
        raise ValueError("At least one prior-exposure repository must be excluded")

    source_subjects = inputs["subjects"]
    source_pairs = {
        (repository_key(subject["repository_url"]), subject["commit"])
        for subject in source_subjects
    }
    present_repositories = {repository for repository, _ in source_pairs}
    if excluded - present_repositories:
        raise ValueError("An excluded repository is absent from the source manifest")

    subjects = [subject for subject in source_subjects
                if repository_key(subject["repository_url"]) not in excluded]
    admitted_pairs = {
        (repository_key(subject["repository_url"]), subject["commit"])
        for subject in subjects
    }
    if not subjects:
        raise ValueError("Repository exclusions removed every source subject")

    retained_labels = {}
    seen_entries = set()
    for entry_id, row in labels.items():
        if entry_id in seen_entries:
            raise ValueError(f"Duplicate evaluator entry: {entry_id}")
        seen_entries.add(entry_id)
        pair = (repository_key(row["repo_url"]), row["commit"])
        if pair not in source_pairs:
            raise ValueError(f"Evaluator entry is outside the frozen input manifest: {entry_id}")
        if pair in admitted_pairs:
            retained_labels[entry_id] = row

    detector = {
        "dataset_identity": inputs["dataset_identity"],
        "role": "heldout_candidate_inputs",
        "claim_eligible": False,
        "split_version": split_version,
        "subjects": subjects,
    }
    evaluator = {
        entry_id: retained_labels[entry_id]
        for entry_id in sorted(retained_labels)
    }
    summary = {
        "split_version": split_version,
        "claim_eligible": False,
        "source_subjects": len(source_subjects),
        "retained_subjects": len(subjects),
        "retained_repositories": len({repository_key(row["repository_url"]) for row in subjects}),
        "source_positive_entries": len(labels),
        "retained_positive_entries": len(evaluator),
        "excluded_positive_entries": len(labels) - len(evaluator),
        "excluded_repositories": exclusions,
        "limitations": [
            "References retain the dataset-supplied verification status and have not been independently reproduced.",
            "No verified fixed counterparts are prepared; false-positive rate is not estimable.",
            "This split supports repository-disjoint source discovery analysis only.",
        ],
    }
    return detector, evaluator, summary


def write_frozen(path: Path, value: Any, *, overwrite: bool = False) -> None:
    rendered = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if path.exists() and not overwrite:
        if path.read_text() != rendered:
            raise FileExistsError(f"Refusing to replace a different frozen artifact: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(rendered)
    temporary.replace(path)


def prepare(config_path: Path, root: Path = PROJECT_ROOT, *, force: bool = False) -> dict:
    config = json.loads(config_path.read_text())
    inputs = json.loads((root / config["source_inputs"]).read_text())
    labels = json.loads((root / config["source_labels"]).read_text())
    detector, evaluator, summary = build_split(
        inputs, labels, config["previously_evaluated_repositories"], config["split_version"]
    )
    write_frozen(root / config["detector_output"], detector, overwrite=force)
    output = root / config["evaluator_output"]
    write_frozen(output / "labels.json", evaluator, overwrite=force)
    write_frozen(output / "summary.json", summary, overwrite=force)
    return summary


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Prepare frozen VulnGym evaluation split")
    parser.add_argument("config", type=Path, nargs="?", default=PROJECT_ROOT / "configs/preparation/vulngym_evaluation_v4.json")
    parser.add_argument("--force", action="store_true", help="Overwrite existing frozen artifacts if split changed")
    args = parser.parse_args()
    print(json.dumps(prepare(args.config, force=args.force), indent=2))


if __name__ == "__main__":
    main()
