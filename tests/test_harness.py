import pytest
from pydantic import ValidationError

from cv_agent.harness import (
    COMMAND_POLICIES,
    OWASP_HARNESS,
    VULNGYM_RETRIEVAL_HARNESS,
    DatasetRole,
    RetrievalBudget,
    describe_project_harness,
    validate_owasp_harness,
    validate_owasp_result_payload,
    validate_project_harness,
    validate_vulngym_result_payload,
)
from cv_agent.cli import build_parser
from cv_agent.owasp_rag import evaluate_owasp_rag
from cv_agent.retrieval import RepositoryIndex, context_token_count
from cv_agent.types import Candidate, CodeDocument, OwaspLabel, SystemVersion
from cv_agent.workflow import PipelineConfig


def _run_identity() -> dict[str, object]:
    return {
        "code": {"revision": "code-revision", "dirty": False},
        "datasets": {
            "fixture": {"revision": "dataset-revision", "dirty": False}
        },
        "uv_lock_tracked_by_code_revision": True,
    }


def _owasp_retrieval_contract() -> dict[str, object]:
    return {
        spec.system.value: {
            "mode": spec.retrieval.value,
            **spec.budget.model_dump(mode="json"),
            "total_context_tokens": spec.budget.total_context_tokens,
        }
        for spec in OWASP_HARNESS.systems
    }


def test_project_harness_is_internally_consistent():
    validate_project_harness()
    description = describe_project_harness()
    assert description["status"] == "PASS"
    assert description["owasp"]["dataset_role"] == DatasetRole.DEVELOPMENT.value
    assert description["owasp"]["claim_eligible"] is False


def test_every_cli_command_is_registered_in_project_harness():
    parser = build_parser()
    subparsers_action = next(
        action for action in parser._actions if hasattr(action, "choices") and action.choices
    )
    assert set(subparsers_action.choices) == {
        policy.command for policy in COMMAND_POLICIES
    }


def test_comparable_retrieval_budget_drift_is_rejected():
    v2 = OWASP_HARNESS.system_spec(SystemVersion.V2_TEXT_SINGLE)
    changed_v2 = v2.model_copy(
        update={
            "budget": RetrievalBudget(
                top_k=v2.budget.top_k,
                base_context_tokens=v2.budget.base_context_tokens,
                augmentation_context_tokens=v2.budget.augmentation_context_tokens - 1,
                graph_hops=v2.budget.graph_hops,
            )
        }
    )
    changed_systems = tuple(
        changed_v2 if spec.system == SystemVersion.V2_TEXT_SINGLE else spec
        for spec in OWASP_HARNESS.systems
    )
    invalid = OWASP_HARNESS.model_copy(update={"systems": changed_systems})
    with pytest.raises(ValueError, match="V2 and V3 must share"):
        validate_owasp_harness(invalid)


def test_v4_v5_expert_or_policy_drift_is_rejected():
    v4 = OWASP_HARNESS.system_spec(SystemVersion.V4_GRAPH_MULTI)
    v5 = OWASP_HARNESS.system_spec(SystemVersion.V5_GRAPH_FAST_SLOW)
    changed_v4 = v4.model_copy(update={"expert_order": ("scan", "authz", "taint")})
    changed_v5 = v5.model_copy(update={"expert_order": ("scan", "authz", "taint")})
    changed_systems = tuple(
        changed_v4
        if spec.system == SystemVersion.V4_GRAPH_MULTI
        else changed_v5
        if spec.system == SystemVersion.V5_GRAPH_FAST_SLOW
        else spec
        for spec in OWASP_HARNESS.systems
    )
    invalid = OWASP_HARNESS.model_copy(update={"systems": changed_systems})
    with pytest.raises(ValueError, match="supports scan, taint, authz"):
        validate_owasp_harness(invalid)


def test_base_context_budget_drift_is_rejected():
    v1 = OWASP_HARNESS.system_spec(SystemVersion.V1_LOCAL_SINGLE)
    changed_v1 = v1.model_copy(
        update={
            "budget": v1.budget.model_copy(
                update={"base_context_tokens": v1.budget.base_context_tokens + 1}
            )
        }
    )
    changed_systems = tuple(
        changed_v1 if spec.system == SystemVersion.V1_LOCAL_SINGLE else spec
        for spec in OWASP_HARNESS.systems
    )
    invalid = OWASP_HARNESS.model_copy(update={"systems": changed_systems})
    with pytest.raises(ValueError, match="identical local base-context"):
        validate_owasp_harness(invalid)


def test_pipeline_rejects_local_budget_overrides():
    with pytest.raises(ValidationError):
        PipelineConfig(system=SystemVersion.V2_TEXT_SINGLE, top_k=99)


def test_text_and_graph_share_identical_base_and_separate_augmentation():
    documents = [
        CodeDocument(
            repository_id="repo",
            path="entry.py",
            text="def entry(request):\n    return target(request)\n",
            defines=("entry",),
            calls=("target",),
        ),
        CodeDocument(
            repository_id="repo",
            path="target.py",
            text="def target(value):\n    return eval(value)\n",
            defines=("target",),
        ),
    ]
    candidate = Candidate(
        candidate_id="entry",
        case_id="entry",
        repository_id="repo",
        path="entry.py",
        line=1,
        query=documents[0].text,
    )
    index = RepositoryIndex(documents)
    v2 = OWASP_HARNESS.system_spec(SystemVersion.V2_TEXT_SINGLE)
    v3 = OWASP_HARNESS.system_spec(SystemVersion.V3_GRAPH_SINGLE)
    text_context = index.retrieve_context(candidate, mode=v2.retrieval, budget=v2.budget)
    graph_context = index.retrieve_context(candidate, mode=v3.retrieval, budget=v3.budget)

    assert text_context[0].retrieval == graph_context[0].retrieval == "local"
    assert text_context[0].path == graph_context[0].path == candidate.path
    assert text_context[0].text == graph_context[0].text
    assert all(item.path != candidate.path for item in text_context[1:])
    assert all(item.path != candidate.path for item in graph_context[1:])
    assert context_token_count(text_context) <= v2.budget.total_context_tokens
    assert context_token_count(graph_context) <= v3.budget.total_context_tokens


def test_owasp_result_schema_rejects_missing_headline_companion():
    labels = {
        "positive": OwaspLabel(
            case_id="positive", category="cmdi", vulnerable=True, cwe=78
        ),
        "negative": OwaspLabel(
            case_id="negative", category="cmdi", vulnerable=False, cwe=78
        ),
    }
    system_predictions = {
        "positive": "VULNERABLE",
        "negative": "ABSTAIN",
    }
    metrics = evaluate_owasp_rag(
        labels,
        {system.value: dict(system_predictions) for system in SystemVersion},
    )
    payload = {
        "harness_id": OWASP_HARNESS.harness_id,
        "claim_eligible": False,
        "dataset_role": "development",
        "run_identity": _run_identity(),
        "claim_assessment": {
            "eligible": False,
            "reasons": ["development"],
        },
        "candidate_protocol": OWASP_HARNESS.candidate_protocol,
        "diagnostics": {
            "retrieval_contract": _owasp_retrieval_contract(),
            "context_token_count": {},
            "max_context_token_count_per_case": {
                system.value: 0 for system in SystemVersion
            },
            "expert_call_count_by_name": {},
            "verdict_path_by_label_count": {},
            "v5_vs_v4_expert_calls_saved": 0,
        },
        **metrics,
    }
    validate_owasp_result_payload(payload)
    payload.pop("primary_v4_vs_v3_coverage_delta_percentage_points")
    with pytest.raises(ValueError, match="coverage_delta"):
        validate_owasp_result_payload(payload)


def test_vulngym_result_schema_requires_all_retrieval_modes():
    payload = {
        "harness_id": VULNGYM_RETRIEVAL_HARNESS.harness_id,
        "claim_eligible": False,
        "dataset_role": "oracle-diagnostic",
        "run_identity": _run_identity(),
        "claim_assessment": {
            "eligible": False,
            "reasons": ["oracle"],
        },
        "candidate_protocol": VULNGYM_RETRIEVAL_HARNESS.candidate_protocol,
        "retrieval_contract": {
            **VULNGYM_RETRIEVAL_HARNESS.budget.model_dump(mode="json"),
            "total_context_tokens": VULNGYM_RETRIEVAL_HARNESS.budget.total_context_tokens,
            "modes": [
                mode.value for mode in VULNGYM_RETRIEVAL_HARNESS.retrieval_modes
            ],
            "critical_hit_policy": VULNGYM_RETRIEVAL_HARNESS.critical_hit_policy,
        },
        "overall": {
            mode: {"hit_count": 0, "hit_rate": 0.0}
            for mode in ("local", "text", "graph", "hybrid")
        },
        "cross_file": {},
        "same_file": {},
        "resolved_entry_count": 0,
        "resolved_critical_count": 0,
    }
    validate_vulngym_result_payload(payload)
    payload["overall"].pop("hybrid")
    with pytest.raises(ValueError, match="every registered retrieval mode"):
        validate_vulngym_result_payload(payload)
