from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairExperimentConfig, heldout_truth, planned_heldout_cells


@dataclass(frozen=True)
class AcceptanceIssue:
    category: Literal["run_integrity", "detection_quality"]
    message: str


def evaluate_heldout_pair_acceptance(
    rows: Sequence[Mapping[str, object]],
    usage: Mapping[str, object],
    config: PythonHeldoutPairExperimentConfig,
) -> tuple[AcceptanceIssue, ...]:
    """Categorize existing checks while retaining their exact issue order."""
    issues: list[AcceptanceIssue] = []
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
            issues.append(AcceptanceIssue(
                "run_integrity",
                f"Duplicate held-out result cell {key[0]} {key[1]} at rows "
                f"{seen[key]} and {index}"
            ))
            continue
        seen[key] = index
        observed[key] = row
    missing = sorted(set(expected) - set(observed))
    extras = sorted(set(observed) - set(expected))
    if missing:
        issues.append(AcceptanceIssue("run_integrity", f"Missing held-out result cells: {missing[:5]}"))
    if extras:
        issues.append(AcceptanceIssue("run_integrity", f"Unexpected held-out result cells: {extras[:5]}"))
    for key, row in observed.items():
        if key not in expected:
            continue
        pair_id, revision_role = expected[key]
        if row.get("pair_id") != pair_id or row.get("revision_role") != revision_role:
            issues.append(AcceptanceIssue("run_integrity", f"Result metadata mismatch for {key[0]} {key[1]}"))
        status = row.get("status")
        if status != "completed":
            if (
                key in expected_abstentions
                and status == "abstained"
                and row.get("predicted_label") == "ABSTAIN"
            ):
                continue
            category = (
                "detection_quality"
                if status == "abstained" and row.get("predicted_label") == "ABSTAIN"
                else "run_integrity"
            )
            issues.append(AcceptanceIssue(category, f"{key[0]} {key[1]} did not complete: {status}"))
            continue
        expected_label = heldout_truth(revision_role)
        if row.get("predicted_label") != expected_label:
            category = (
                "detection_quality"
                if row.get("predicted_label") in ("SAFE", "VULNERABLE")
                else "run_integrity"
            )
            issues.append(AcceptanceIssue(
                category,
                f"{key[0]} {key[1]} predicted {row.get('predicted_label')} expected {expected_label}"
            ))
    requests = int(usage.get("requests", 0) or 0)
    if len(rows) > 0 and requests <= 0:
        issues.append(AcceptanceIssue("run_integrity", "No model requests were recorded"))
    return tuple(issues)


def heldout_pair_acceptance_issues(
    rows: Sequence[Mapping[str, object]],
    usage: Mapping[str, object],
    config: PythonHeldoutPairExperimentConfig,
) -> list[str]:
    """Preserve the legacy flat acceptance result and ordering."""
    return [issue.message for issue in evaluate_heldout_pair_acceptance(rows, usage, config)]


def review_heldout_pair_rows(
    rows: Sequence[Mapping[str, object]],
    usage: Mapping[str, object],
    config: PythonHeldoutPairExperimentConfig,
) -> dict[str, object]:
    """Review supplied records without reading sources or rewriting artifacts.

    The two categories describe the existing acceptance policy, including its
    declared abstention exceptions. They do not add new admission requirements.
    """
    issues = evaluate_heldout_pair_acceptance(rows, usage, config)
    return {
        "legacy_passed": not issues,
        "legacy_issues": [issue.message for issue in issues],
        "run_integrity_issues": [
            issue.message for issue in issues if issue.category == "run_integrity"
        ],
        "detection_quality_issues": [
            issue.message for issue in issues if issue.category == "detection_quality"
        ],
    }
