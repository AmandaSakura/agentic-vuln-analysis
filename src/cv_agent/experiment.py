from __future__ import annotations

from .harness import validate_project_harness
from .metrics import evaluate_ternary
from .synthetic import cross_file_fixture, guarded_delete_fixture
from .types import SystemVersion, VerdictLabel
from .workflow import AgentPipeline, PipelineConfig


def run_synthetic_experiment() -> dict:
    validate_project_harness()
    fixtures = [cross_file_fixture(), guarded_delete_fixture()]
    labels = {
        fixtures[0][1].case_id: True,
        fixtures[1][1].case_id: False,
    }
    systems: dict[str, dict] = {}
    for system in SystemVersion:
        predictions: dict[str, VerdictLabel] = {}
        traces: dict[str, dict] = {}
        for index, candidate in fixtures:
            verdict = AgentPipeline(index, PipelineConfig(system=system)).run(candidate)
            predictions[candidate.case_id] = verdict.label
            traces[candidate.case_id] = {
                "label": verdict.label,
                "confidence": verdict.confidence,
                "path": verdict.path,
                "experts": [vote.expert for vote in verdict.votes],
            }
        matrix = evaluate_ternary(labels, predictions)
        systems[system.value] = {
            "predictions": predictions,
            "traces": traces,
            "confusion": {
                "tp": matrix.true_positive,
                "fp": matrix.false_positive,
                "tn": matrix.true_negative,
                "fn": matrix.false_negative,
                "abstain_positive": matrix.abstain_positive,
                "abstain_negative": matrix.abstain_negative,
            },
            "strict_recall": matrix.strict_recall,
            "population_false_positive_rate": matrix.population_false_positive_rate,
            "coverage": matrix.coverage,
        }
    return {
        "dataset": "controlled-two-case-smoke",
        "purpose": "validate directional wiring only; not a reported benchmark result",
        "systems": systems,
    }
