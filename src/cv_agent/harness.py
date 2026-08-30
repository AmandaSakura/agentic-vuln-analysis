from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Literal

from pydantic import Field

from .types import FrozenModel, SystemVersion


ExpertName = Literal["scan", "taint", "authz"]


class DatasetRole(StrEnum):
    DEVELOPMENT = "development"
    FINAL_TEST = "final-test"
    ORACLE_DIAGNOSTIC = "oracle-diagnostic"


class RetrievalMode(StrEnum):
    LOCAL = "local"
    TEXT = "text"
    GRAPH = "graph"
    HYBRID = "hybrid"


class RetrievalBudget(FrozenModel):
    top_k: int = Field(ge=0, le=50)
    base_context_tokens: int = Field(ge=32, le=100_000)
    augmentation_context_tokens: int = Field(ge=0, le=100_000)
    graph_hops: int = Field(ge=0, le=8)

    @property
    def total_context_tokens(self) -> int:
        return self.base_context_tokens + self.augmentation_context_tokens


class SystemHarness(FrozenModel):
    system: SystemVersion
    retrieval: RetrievalMode
    budget: RetrievalBudget
    expert_order: tuple[ExpertName, ...]
    full_review_policy: Literal["single", "majority"]
    quorum: int = Field(default=2, ge=2, le=3)
    fast_score: float = Field(default=0.80, ge=0.0, le=1.0)
    early_quorum_after: int | None = Field(default=None, ge=2, le=3)


class ExperimentHarness(FrozenModel):
    harness_id: str
    dataset_name: str
    dataset_role: DatasetRole
    claim_eligible: bool
    candidate_protocol: str
    primary_scope: tuple[str, ...]
    primary_scope_rationale: str
    systems: tuple[SystemHarness, ...]
    required_metrics: tuple[str, ...]

    def system_spec(self, system: SystemVersion) -> SystemHarness:
        matches = [spec for spec in self.systems if spec.system == system]
        if len(matches) != 1:
            raise ValueError(f"{self.harness_id}: expected one spec for {system}, found {len(matches)}")
        return matches[0]


class RetrievalEvaluationHarness(FrozenModel):
    harness_id: str
    dataset_name: str
    dataset_role: DatasetRole
    claim_eligible: bool
    candidate_protocol: str
    retrieval_modes: tuple[RetrievalMode, ...]
    budget: RetrievalBudget
    critical_hit_policy: Literal["full-critical-line-retained"]


class CommandPolicy(FrozenModel):
    command: str
    kind: Literal["experiment", "diagnostic", "data-preparation", "harness"]
    claim_eligible: bool
    harness_id: str | None = None


COMPARABLE_BASE_TOKENS = 512
COMPARABLE_AUGMENTATION_TOKENS = 1488
COMPARABLE_TOP_K = 6


def _system(
    system: SystemVersion,
    retrieval: RetrievalMode,
    *,
    top_k: int,
    augmentation_tokens: int,
    graph_hops: int,
    experts: tuple[ExpertName, ...],
    policy: Literal["single", "majority"],
    early_quorum_after: int | None = None,
) -> SystemHarness:
    return SystemHarness(
        system=system,
        retrieval=retrieval,
        budget=RetrievalBudget(
            top_k=top_k,
            base_context_tokens=COMPARABLE_BASE_TOKENS,
            augmentation_context_tokens=augmentation_tokens,
            graph_hops=graph_hops,
        ),
        expert_order=experts,
        full_review_policy=policy,
        early_quorum_after=early_quorum_after,
    )


OWASP_HARNESS = ExperimentHarness(
    harness_id="owasp-development-v2",
    dataset_name="OWASP BenchmarkJava 1.2beta",
    dataset_role=DatasetRole.DEVELOPMENT,
    claim_eligible=False,
    candidate_protocol=(
        "One source-derived servlet doGet method per BenchmarkTest case; "
        "the identical local method is the base context for every system."
    ),
    primary_scope=("cmdi", "ldapi", "pathtraver", "sqli", "xpathi"),
    primary_scope_rationale=(
        "Predeclared API families covered by command, LDAP, path, SQL, and XPath sink rules."
    ),
    systems=(
        _system(
            SystemVersion.V1_LOCAL_SINGLE,
            RetrievalMode.LOCAL,
            top_k=0,
            augmentation_tokens=0,
            graph_hops=0,
            experts=("scan",),
            policy="single",
        ),
        _system(
            SystemVersion.V2_TEXT_SINGLE,
            RetrievalMode.TEXT,
            top_k=COMPARABLE_TOP_K,
            augmentation_tokens=COMPARABLE_AUGMENTATION_TOKENS,
            graph_hops=0,
            experts=("scan",),
            policy="single",
        ),
        _system(
            SystemVersion.V3_GRAPH_SINGLE,
            RetrievalMode.GRAPH,
            top_k=COMPARABLE_TOP_K,
            augmentation_tokens=COMPARABLE_AUGMENTATION_TOKENS,
            graph_hops=2,
            experts=("scan",),
            policy="single",
        ),
        _system(
            SystemVersion.V4_GRAPH_MULTI,
            RetrievalMode.GRAPH,
            top_k=COMPARABLE_TOP_K,
            augmentation_tokens=COMPARABLE_AUGMENTATION_TOKENS,
            graph_hops=2,
            experts=("scan", "taint", "authz"),
            policy="majority",
        ),
        _system(
            SystemVersion.V5_GRAPH_FAST_SLOW,
            RetrievalMode.GRAPH,
            top_k=COMPARABLE_TOP_K,
            augmentation_tokens=COMPARABLE_AUGMENTATION_TOKENS,
            graph_hops=2,
            experts=("scan", "taint", "authz"),
            policy="majority",
            early_quorum_after=2,
        ),
    ),
    required_metrics=(
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
    ),
)


VULNGYM_RETRIEVAL_HARNESS = RetrievalEvaluationHarness(
    harness_id="vulngym-oracle-retrieval-v2",
    dataset_name="VulnGym v0.1.4 verified Python subset",
    dataset_role=DatasetRole.ORACLE_DIAGNOSTIC,
    claim_eligible=False,
    candidate_protocol=(
        "A verified VulnGym entry point is an explicit oracle seed; the identical containing "
        "function is the base context for local, text, graph, and hybrid retrieval."
    ),
    retrieval_modes=(
        RetrievalMode.LOCAL,
        RetrievalMode.TEXT,
        RetrievalMode.GRAPH,
        RetrievalMode.HYBRID,
    ),
    budget=RetrievalBudget(
        top_k=8,
        base_context_tokens=512,
        augmentation_context_tokens=3488,
        graph_hops=4,
    ),
    critical_hit_policy="full-critical-line-retained",
)


COMMAND_POLICIES = (
    CommandPolicy(command="harness-check", kind="harness", claim_eligible=False),
    CommandPolicy(command="synthetic", kind="diagnostic", claim_eligible=False),
    CommandPolicy(command="profile", kind="data-preparation", claim_eligible=False),
    CommandPolicy(
        command="owasp-baseline",
        kind="diagnostic",
        claim_eligible=False,
        harness_id=OWASP_HARNESS.harness_id,
    ),
    CommandPolicy(command="owasp-ast-profile", kind="diagnostic", claim_eligible=False),
    CommandPolicy(
        command="owasp-rag",
        kind="experiment",
        claim_eligible=False,
        harness_id=OWASP_HARNESS.harness_id,
    ),
    CommandPolicy(command="vulngym-subset", kind="diagnostic", claim_eligible=False),
    CommandPolicy(command="vulngym-fetch", kind="data-preparation", claim_eligible=False),
    CommandPolicy(
        command="vulngym-retrieval",
        kind="diagnostic",
        claim_eligible=False,
        harness_id=VULNGYM_RETRIEVAL_HARNESS.harness_id,
    ),
)


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
    if v4.expert_order != ("scan", "taint", "authz"):
        raise ValueError("the conditional workflow supports scan, taint, authz in that order")
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
    if harness.critical_hit_policy != "full-critical-line-retained":
        raise ValueError("VulnGym hits must retain the complete critical line")


def validate_project_harness() -> None:
    validate_owasp_harness()
    validate_vulngym_harness()
    commands = [policy.command for policy in COMMAND_POLICIES]
    if len(commands) != len(set(commands)):
        raise ValueError("project harness contains duplicate command policies")
    valid_harness_ids = {
        OWASP_HARNESS.harness_id,
        VULNGYM_RETRIEVAL_HARNESS.harness_id,
    }
    for policy in COMMAND_POLICIES:
        if policy.harness_id is not None and policy.harness_id not in valid_harness_ids:
            raise ValueError(f"command {policy.command} references an unknown harness")
        if policy.kind == "experiment" and policy.harness_id is None:
            raise ValueError(f"experiment command {policy.command} lacks a harness")


def command_policy(command: str) -> CommandPolicy:
    matches = [policy for policy in COMMAND_POLICIES if policy.command == command]
    if len(matches) != 1:
        raise ValueError(f"command is not registered in the project harness: {command}")
    return matches[0]


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"result field {name} must be an object")
    return value


def _require_keys(container: Mapping[str, object], required: set[str], name: str) -> None:
    missing = sorted(required - set(container))
    if missing:
        raise ValueError(f"result field {name} is missing required keys: {missing}")


def _validate_run_identity(payload: Mapping[str, object]) -> None:
    identity = _mapping(payload.get("run_identity"), "run_identity")
    _require_keys(identity, {"code", "datasets", "uv_lock_tracked_by_code_revision"}, "run_identity")
    if identity["uv_lock_tracked_by_code_revision"] is not True:
        raise ValueError("run_identity must bind uv.lock through the code revision")
    code = _mapping(identity["code"], "run_identity.code")
    _require_keys(code, {"revision", "dirty"}, "run_identity.code")
    if not str(code["revision"]).strip() or not isinstance(code["dirty"], bool):
        raise ValueError("run_identity.code must contain a revision and boolean dirty state")
    datasets = _mapping(identity["datasets"], "run_identity.datasets")
    if not datasets:
        raise ValueError("run_identity must contain at least one dataset revision")
    for name, value in datasets.items():
        dataset = _mapping(value, f"run_identity.datasets.{name}")
        _require_keys(dataset, {"revision", "dirty"}, f"run_identity.datasets.{name}")
        if not str(dataset["revision"]).strip() or not isinstance(dataset["dirty"], bool):
            raise ValueError(f"dataset identity {name} is invalid")
    assessment = _mapping(payload.get("claim_assessment"), "claim_assessment")
    _require_keys(assessment, {"eligible", "reasons"}, "claim_assessment")
    if not isinstance(assessment["eligible"], bool) or not isinstance(
        assessment["reasons"], list
    ):
        raise ValueError("claim_assessment must contain a boolean and reason list")


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


def validate_vulngym_result_payload(payload: Mapping[str, object]) -> None:
    if payload.get("harness_id") != VULNGYM_RETRIEVAL_HARNESS.harness_id:
        raise ValueError("VulnGym result carries the wrong harness id")
    if payload.get("claim_eligible") is not False:
        raise ValueError("VulnGym oracle result cannot be claim eligible")
    if payload.get("dataset_role") != VULNGYM_RETRIEVAL_HARNESS.dataset_role.value:
        raise ValueError("VulnGym result carries the wrong dataset role")
    if payload.get("candidate_protocol") != VULNGYM_RETRIEVAL_HARNESS.candidate_protocol:
        raise ValueError("VulnGym result carries the wrong candidate protocol")
    _require_keys(
        payload,
        {
            "run_identity",
            "claim_assessment",
            "candidate_protocol",
            "retrieval_contract",
            "overall",
            "cross_file",
            "same_file",
            "resolved_entry_count",
            "resolved_critical_count",
        },
        "root",
    )
    overall = _mapping(payload["overall"], "overall")
    if set(overall) != {mode.value for mode in VULNGYM_RETRIEVAL_HARNESS.retrieval_modes}:
        raise ValueError("VulnGym result must contain every registered retrieval mode")
    expected_contract = {
        **VULNGYM_RETRIEVAL_HARNESS.budget.model_dump(mode="json"),
        "total_context_tokens": VULNGYM_RETRIEVAL_HARNESS.budget.total_context_tokens,
        "modes": [mode.value for mode in VULNGYM_RETRIEVAL_HARNESS.retrieval_modes],
        "critical_hit_policy": VULNGYM_RETRIEVAL_HARNESS.critical_hit_policy,
    }
    if payload["retrieval_contract"] != expected_contract:
        raise ValueError("VulnGym result retrieval contract differs from the project harness")
    _validate_run_identity(payload)
    assessment = _mapping(payload["claim_assessment"], "claim_assessment")
    if assessment["eligible"] is not False:
        raise ValueError("VulnGym oracle results cannot pass claim assessment")


def describe_project_harness() -> dict[str, object]:
    validate_project_harness()
    return {
        "status": "PASS",
        "owasp": OWASP_HARNESS.model_dump(mode="json"),
        "vulngym_retrieval": VULNGYM_RETRIEVAL_HARNESS.model_dump(mode="json"),
        "commands": [policy.model_dump(mode="json") for policy in COMMAND_POLICIES],
    }


# Fail at import time if the single source of truth becomes internally inconsistent.
validate_project_harness()
