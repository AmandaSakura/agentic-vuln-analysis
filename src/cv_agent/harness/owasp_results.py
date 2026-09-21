"""Validate OWASP metrics, retrieval budgets, and non-claim provenance."""

from __future__ import annotations

from collections.abc import Mapping

from ..types import SystemVersion
from .defaults import OWASP_HARNESS
from .results import _mapping, _require_keys, _validate_run_identity


def validate_owasp_result_payload(payload: Mapping[str, object]) -> None:
    if payload.get("harness_id") != OWASP_HARNESS.harness_id:
        raise ValueError("OWASP result carries the wrong harness id")
    if payload.get("claim_eligible") is not OWASP_HARNESS.claim_eligible:
        raise ValueError("OWASP result carries the wrong claim eligibility")
    if payload.get("dataset_role") != OWASP_HARNESS.dataset_role.value:
        raise ValueError("OWASP result carries the wrong dataset role")
    if payload.get("candidate_protocol") != OWASP_HARNESS.candidate_protocol:
        raise ValueError("OWASP result carries the wrong candidate protocol")
    _require_keys(
        payload,
        {
            "run_identity",
            "claim_assessment",
            "candidate_protocol",
            "systems",
            "diagnostics",
            "primary_v4_vs_v3_fpr_reduction_percent",
            "primary_v4_vs_v3_covered_fpr_reduction_percent",
            "primary_v4_vs_v3_population_false_alert_reduction_percent",
            "primary_v4_vs_v3_strict_recall_delta_percentage_points",
            "primary_v4_vs_v3_coverage_delta_percentage_points",
            "v5_vs_v4_label_disagreement_count",
        },
        "root",
    )
    systems = _mapping(payload["systems"], "systems")
    if set(systems) != {system.value for system in SystemVersion}:
        raise ValueError("OWASP result must contain exactly V1 through V5")
    system_metric_keys = {
        "coverage",
        "abstain_rate",
        "strict_recall",
        "covered_recall",
        "population_false_positive_rate",
        "conservative_false_positive_rate",
        "covered_false_positive_rate",
        "precision",
    }
    for system, value in systems.items():
        system_result = _mapping(value, f"systems.{system}")
        primary = _mapping(system_result.get("primary_subset"), f"systems.{system}.primary_subset")
        _require_keys(primary, system_metric_keys, f"systems.{system}.primary_subset")
    diagnostics = _mapping(payload["diagnostics"], "diagnostics")
    _require_keys(
        diagnostics,
        {
            "retrieval_contract",
            "context_token_count",
            "max_context_token_count_per_case",
            "expert_call_count_by_name",
            "verdict_path_by_label_count",
            "v5_vs_v4_expert_calls_saved",
        },
        "diagnostics",
    )
    expected_contract = {
        spec.system.value: {
            "mode": spec.retrieval.value,
            **spec.budget.model_dump(mode="json"),
            "total_context_tokens": spec.budget.total_context_tokens,
        }
        for spec in OWASP_HARNESS.systems
    }
    if diagnostics["retrieval_contract"] != expected_contract:
        raise ValueError("OWASP result retrieval contract differs from the project harness")
    max_context = _mapping(
        diagnostics["max_context_token_count_per_case"],
        "diagnostics.max_context_token_count_per_case",
    )
    if set(max_context) != set(expected_contract):
        raise ValueError("OWASP result context maxima must cover exactly V1 through V5")
    for system, maximum in max_context.items():
        if int(maximum) > expected_contract[system]["total_context_tokens"]:
            raise ValueError(f"system {system} exceeded its context-token contract")
    if payload["v5_vs_v4_label_disagreement_count"] != 0:
        raise ValueError("V4 and V5 labels diverged; the scheduling ablation is invalid")
    _validate_run_identity(payload)
    assessment = _mapping(payload["claim_assessment"], "claim_assessment")
    if assessment["eligible"] is not False:
        raise ValueError("development OWASP results cannot pass claim assessment")
