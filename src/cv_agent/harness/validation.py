"""Validate declared experiment contracts and describe the project harness."""

from __future__ import annotations

from cv_agent.domain.types import SystemVersion
from cv_agent.harness.defaults import COMMAND_POLICIES, FULL_SYSTEM_HARNESS, OWASP_HARNESS, VULNGYM_RETRIEVAL_HARNESS
from cv_agent.harness.models import AgentRuntimeMode, AgentSystemVersion, DatasetRole, EndToEndHarness, ExperimentHarness, RetrievalEvaluationHarness, RetrievalMode, SystemHarness


def _same_comparable_budget(left: SystemHarness, right: SystemHarness) -> bool:
    return (
        left.budget.top_k == right.budget.top_k
        and left.budget.base_context_tokens == right.budget.base_context_tokens
        and left.budget.augmentation_context_tokens
        == right.budget.augmentation_context_tokens
    )


def validate_owasp_harness(harness: ExperimentHarness = OWASP_HARNESS) -> None:
    if {spec.system for spec in harness.systems} != set(SystemVersion):
        raise ValueError("OWASP harness must define every SystemVersion exactly once")
    if len(harness.systems) != len(SystemVersion):
        raise ValueError("OWASP harness contains duplicate system definitions")
    if harness.dataset_role != DatasetRole.FINAL_TEST and harness.claim_eligible:
        raise ValueError("development or oracle datasets cannot be claim eligible")
    if not harness.candidate_protocol.strip() or not harness.primary_scope_rationale.strip():
        raise ValueError("candidate protocol and primary-scope rationale are required")

    v1 = harness.system_spec(SystemVersion.V1_LOCAL_SINGLE)
    v2 = harness.system_spec(SystemVersion.V2_TEXT_SINGLE)
    v3 = harness.system_spec(SystemVersion.V3_GRAPH_SINGLE)
    v4 = harness.system_spec(SystemVersion.V4_GRAPH_MULTI)
    v5 = harness.system_spec(SystemVersion.V5_GRAPH_FAST_SLOW)

    if len({spec.budget.base_context_tokens for spec in harness.systems}) != 1:
        raise ValueError("every system must receive the identical local base-context budget")
    if v1.retrieval != RetrievalMode.LOCAL or v1.budget.augmentation_context_tokens != 0:
        raise ValueError("V1 must use only the fixed local base context")
    if any(
        spec.expert_order != ("scan",)
        or spec.full_review_policy != "single"
        or spec.early_quorum_after is not None
        for spec in (v1, v2, v3)
    ):
        raise ValueError("V1, V2, and V3 must execute only the scan expert")
    if v2.retrieval != RetrievalMode.TEXT or v3.retrieval != RetrievalMode.GRAPH:
        raise ValueError("V2 and V3 must isolate text versus graph retrieval")
    if not _same_comparable_budget(v2, v3):
        raise ValueError("V2 and V3 must share top_k, base, and augmentation budgets")
    if any(spec.retrieval != RetrievalMode.GRAPH for spec in (v3, v4, v5)):
        raise ValueError("V3, V4, and V5 must share graph retrieval")
    if not (v3.budget == v4.budget == v5.budget):
        raise ValueError("V3, V4, and V5 must share the complete retrieval budget")
    if v4.expert_order != v5.expert_order or v4.full_review_policy != v5.full_review_policy:
        raise ValueError("V4 and V5 must use identical experts and full-review policy")
    if v4.expert_order != ("scan", "taint", "verify"):
        raise ValueError("the OWASP workflow requires scan, taint, then routed verification")
    if v4.quorum != v5.quorum:
        raise ValueError("V4 and V5 must use the same majority quorum")
    if v4.early_quorum_after is not None or v5.early_quorum_after != 2:
        raise ValueError("only V5 may exit after the first two expert votes")
    if v5.early_quorum_after < v5.quorum:
        raise ValueError("V5 cannot attempt early exit before enough votes exist")
    if v4.full_review_policy != "majority" or v1.full_review_policy != "single":
        raise ValueError("single and multi-expert systems use the wrong adjudication policy")
    required = {
        "coverage",
        "abstain_rate",
        "strict_recall",
        "covered_recall",
        "population_false_positive_rate",
        "covered_false_positive_rate",
        "precision",
        "recall_delta",
        "coverage_delta",
        "expert_call_count_by_name",
        "verdict_path_by_label_count",
    }
    if not required.issubset(harness.required_metrics):
        raise ValueError("OWASP harness omits required ternary/headline metrics")


def validate_vulngym_harness(
    harness: RetrievalEvaluationHarness = VULNGYM_RETRIEVAL_HARNESS,
) -> None:
    if harness.dataset_role != DatasetRole.ORACLE_DIAGNOSTIC or harness.claim_eligible:
        raise ValueError("VulnGym oracle retrieval must remain non-claim diagnostic data")
    if set(harness.retrieval_modes) != set(RetrievalMode):
        raise ValueError("VulnGym retrieval must report local, text, graph, and hybrid")
    if harness.budget.augmentation_context_tokens <= 0:
        raise ValueError("VulnGym retrieval requires a positive shared augmentation budget")
    if not (
        harness.experiment_name.strip()
        and harness.limitation.strip()
        and harness.candidate_protocol.strip()
    ):
        raise ValueError("VulnGym experiment name, limitation, and candidate protocol are required")
    if harness.critical_hit_policy != "full-critical-line-retained":
        raise ValueError("VulnGym hits must retain the complete critical line")


def validate_full_system_harness(
    harness: EndToEndHarness = FULL_SYSTEM_HARNESS,
) -> None:
    if set(harness.runtime_modes) != set(AgentRuntimeMode):
        raise ValueError("full system must declare scripted and live runtime modes")
    if harness.claim_runtime_mode != AgentRuntimeMode.LIVE:
        raise ValueError("only live model runs may become claim eligible")
    if (
        harness.model.temperature != 0.0
        or not harness.model.base_url_env.strip()
        or not harness.model.model_env.strip()
        or not harness.model.api_key_env.strip()
    ):
        raise ValueError("live model configuration must be deterministic and environment-backed")
    if not (
        harness.react_loop.require_model_action
        and harness.react_loop.require_tool_observation
        and harness.react_loop.final_schema == "AgentExpertVote"
    ):
        raise ValueError("material expert results must contain a genuine ReAct trace")

    experts = {expert.expert: expert for expert in harness.experts}
    if set(experts) != {"scan", "taint", "authz"} or len(harness.experts) != 3:
        raise ValueError("full system must define scan, taint, and authz experts exactly once")
    for name, expert in experts.items():
        if not expert.mandate.strip() or not expert.tools or not expert.require_react_trace:
            raise ValueError(f"expert {name} lacks a mandate, tools, or ReAct requirement")
        if len(expert.tools) != len(set(expert.tools)):
            raise ValueError(f"expert {name} contains duplicate tools")

    if not harness.development_repositories or len(
        harness.development_repositories
    ) != len(set(harness.development_repositories)):
        raise ValueError("development repositories must be explicit and unique")
    if not harness.held_out_positive_dataset.strip() or not harness.paired_negative_sources:
        raise ValueError("full system requires held-out positive and paired negative data")

    systems = {spec.system: spec for spec in harness.systems}
    if set(systems) != set(AgentSystemVersion) or len(harness.systems) != len(
        AgentSystemVersion
    ):
        raise ValueError("full system must define E1 through E5 exactly once")
    e1 = harness.system_spec(AgentSystemVersion.E1_LOCAL_SINGLE)
    e2 = harness.system_spec(AgentSystemVersion.E2_TEXT_SINGLE)
    e3 = harness.system_spec(AgentSystemVersion.E3_GRAPH_SINGLE)
    e4 = harness.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)
    e5 = harness.system_spec(AgentSystemVersion.E5_GRAPH_FAST)
    if len({spec.budget.base_context_tokens for spec in harness.systems}) != 1:
        raise ValueError("E1-E5 must share an identical candidate-local base budget")
    if (
        e1.retrieval != RetrievalMode.LOCAL
        or e1.budget.augmentation_context_tokens != 0
        or e1.budget.top_k != 0
    ):
        raise ValueError("E1 must use candidate-local context only")
    if e2.retrieval != RetrievalMode.TEXT or e3.retrieval != RetrievalMode.GRAPH:
        raise ValueError("E2 and E3 must isolate text versus graph Code-RAG")
    if not (
        e2.budget.top_k == e3.budget.top_k
        and e2.budget.base_context_tokens == e3.budget.base_context_tokens
        and e2.budget.augmentation_context_tokens
        == e3.budget.augmentation_context_tokens
    ):
        raise ValueError("E2 and E3 must share top_k, base, and augmentation budgets")
    if any(spec.retrieval != RetrievalMode.GRAPH for spec in (e3, e4, e5)):
        raise ValueError("E3-E5 must share graph retrieval")
    if not (e3.budget == e4.budget == e5.budget):
        raise ValueError("E3-E5 must share the complete graph retrieval budget")
    if any(
        spec.planner_enabled
        or spec.expert_order != ("scan",)
        or spec.full_review_policy != "single"
        or spec.early_quorum_after is not None
        for spec in (e1, e2, e3)
    ):
        raise ValueError("E1-E3 must isolate one scan ReAct expert without a planner")
    if any(
        not spec.planner_enabled
        or spec.expert_order != ("scan", "taint", "authz")
        or spec.full_review_policy != "majority"
        for spec in (e4, e5)
    ):
        raise ValueError("E4 and E5 must share planner, experts, and full-review policy")
    if e4.early_quorum_after is not None or e5.early_quorum_after != 2:
        raise ValueError("only E5 may exit after two expert votes")
    if (
        e4.quorum != e5.quorum
        or e4.fast_confidence != e5.fast_confidence
        or e5.early_quorum_after < e5.quorum
    ):
        raise ValueError("E4/E5 quorum definitions are inconsistent")

    if (
        harness.validation.command_policy != "typed-allowlist"
        or harness.validation.network_policy != "disabled-or-loopback"
        or harness.validation.subject_mode != "read-only"
        or not harness.validation.validators
    ):
        raise ValueError("validation tools must retain the declared safety boundary")
    executable_tools = {
        tool for expert in harness.experts for tool in expert.tools
    }
    orphaned_validators = sorted(
        set(harness.validation.validators) - executable_tools
    )
    if orphaned_validators:
        raise ValueError(
            "validation tools must be owned by an executable expert: "
            f"{orphaned_validators}"
        )
    required_metrics = {
        "advisory_recall",
        "entry_recall",
        "precision",
        "population_false_positive_rate",
        "coverage",
        "abstain_rate",
        "paired_graph_text_outcomes",
        "validation_status_counts",
        "expert_model_tool_calls",
        "fast_slow_path_counts",
        "clustered_uncertainty",
    }
    if not required_metrics.issubset(harness.required_metrics):
        raise ValueError("full-system Harness omits required attribution metrics")


def validate_project_harness() -> None:
    validate_owasp_harness()
    validate_vulngym_harness()
    validate_full_system_harness()
    commands = [policy.command for policy in COMMAND_POLICIES]
    if len(commands) != len(set(commands)):
        raise ValueError("project harness contains duplicate command policies")
    valid_harness_ids = {
        OWASP_HARNESS.harness_id,
        VULNGYM_RETRIEVAL_HARNESS.harness_id,
        FULL_SYSTEM_HARNESS.harness_id,
    }
    for policy in COMMAND_POLICIES:
        if policy.harness_id is not None and policy.harness_id not in valid_harness_ids:
            raise ValueError(f"command {policy.command} references an unknown harness")
        if policy.kind == "experiment" and policy.harness_id is None:
            raise ValueError(f"experiment command {policy.command} lacks a harness")


def describe_project_harness() -> dict[str, object]:
    validate_project_harness()
    return {
        "status": "PASS",
        "owasp": OWASP_HARNESS.model_dump(mode="json"),
        "vulngym_retrieval": VULNGYM_RETRIEVAL_HARNESS.model_dump(mode="json"),
        "full_system": FULL_SYSTEM_HARNESS.model_dump(mode="json"),
        "commands": [policy.model_dump(mode="json") for policy in COMMAND_POLICIES],
    }
