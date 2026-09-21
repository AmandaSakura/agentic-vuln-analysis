"""Recheck frozen v2 repair admission against existing local source checkouts."""
from __future__ import annotations

import hashlib
import json

from cv_agent.evaluation.preparation.prepare_python_heldout_pairs import CONFIG_PATH, GIT_CACHE, LABELS_PATH, PROJECT_ROOT, fixed_commit_repair_evidence, repo_slug, save_json


def main() -> None:
    config = json.loads(CONFIG_PATH.read_text())
    labels = json.loads(LABELS_PATH.read_text())
    results = []
    for pair in config["pairs"]:
        repository_url = pair["repository_url"]
        # Require local inputs so this audit cannot trigger repository downloads.
        cache = GIT_CACHE / repo_slug(repository_url)
        if not cache.is_dir():
            raise FileNotFoundError(cache)
        cases = {case["revision_role"]: case for case in pair["cases"]}
        for case in cases.values():
            checkout = PROJECT_ROOT / case["checkout"]
            if not checkout.is_dir():
                raise FileNotFoundError(checkout)
        evidence = fixed_commit_repair_evidence(
            labels[pair["entry_id"]],
            repository_url=repository_url,
            vulnerable_checkout=cases["vulnerable"]["checkout"],
            fixed_checkout=cases["fixed"]["checkout"],
            fixed_commit=cases["fixed"]["commit"],
        )
        results.append({"pair_id": pair["pair_id"], **evidence})
    report = {
        "config": CONFIG_PATH.relative_to(PROJECT_ROOT).as_posix(),
        "config_sha256": hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(),
        "scope": "source-level repair admission only; no behavioral or model validation",
        "passed": all(item["verified"] for item in results),
        "pairs": results,
    }
    save_json(PROJECT_ROOT / "artifacts/python_heldout_pair_preparation_v2/repair_reaudit.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not report["passed"]:
        raise SystemExit("Frozen v2 pair repair admission failed")


if __name__ == "__main__":
    main()
