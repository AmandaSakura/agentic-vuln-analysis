from __future__ import annotations

from collections.abc import Mapping, Sequence

from .python_heldout_pair_config import (
    PythonHeldoutPairExperimentConfig,
    heldout_truth,
    planned_heldout_cells,
)


def heldout_pair_acceptance_issues(
    rows: Sequence[Mapping[str, object]],
    usage: Mapping[str, object],
    config: PythonHeldoutPairExperimentConfig,
) -> list[str]:
    issues: list[str] = []
    expected = {
        (case.case_id, system.value): (pair.pair_id, case.revision_role)
        for pair, case, system in planned_heldout_cells(config)
    }
    expected_abstentions = {
        (cell.case_id, cell.system.value) for cell in config.expected_abstentions
    }
    observed: dict[tuple[str, str], Mapping[str, object]] = {}
    seen: dict[tuple[str, str], int] = {}
    for index, row in enumerate(rows, start=1):
        key = (str(row.get("case_id")), str(row.get("system")))
        if key in seen:
            issues.append(
                f"Duplicate held-out result cell {key[0]} {key[1]} at rows "
                f"{seen[key]} and {index}"
            )
            continue
        seen[key] = index
        observed[key] = row
    missing = sorted(set(expected) - set(observed))
    extras = sorted(set(observed) - set(expected))
    if missing:
        issues.append(f"Missing held-out result cells: {missing[:5]}")
    if extras:
        issues.append(f"Unexpected held-out result cells: {extras[:5]}")
    for key, row in observed.items():
        if key not in expected:
            continue
        pair_id, revision_role = expected[key]
        if row.get("pair_id") != pair_id or row.get("revision_role") != revision_role:
            issues.append(f"Result metadata mismatch for {key[0]} {key[1]}")
        status = row.get("status")
        if status != "completed":
            if (
                key in expected_abstentions
                and status == "abstained"
                and row.get("predicted_label") == "ABSTAIN"
            ):
                continue
            issues.append(f"{key[0]} {key[1]} did not complete: {status}")
            continue
        expected_label = heldout_truth(revision_role)
        if row.get("predicted_label") != expected_label:
            issues.append(
                f"{key[0]} {key[1]} predicted {row.get('predicted_label')} expected {expected_label}"
            )
    requests = int(usage.get("requests", 0) or 0)
    if len(rows) > 0 and requests <= 0:
        issues.append("No model requests were recorded")
    return issues
