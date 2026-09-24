"""Score a completed full inventory against evaluator-only VulnGym references."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cv_agent.evaluation.discovery import score_discovery


def score(run_dir: Path, references_path: Path) -> dict:
    inventory = json.loads((run_dir / "inventory.json").read_text())
    if inventory.get("run_state") != "complete":
        raise ValueError("Cannot score an incomplete source inventory")
    references = json.loads(references_path.read_text())
    report = score_discovery(
        inventory, json.loads((run_dir / "results.json").read_text()), list(references.values())
    )
    report["evaluation_stage"] = "source_discovery_only"
    report["claim_eligible"] = False
    destination = run_dir / "reference_score.json"
    with destination.open("x") as stream:
        stream.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("references", type=Path)
    args = parser.parse_args()
    print(json.dumps(score(args.run_dir, args.references), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
