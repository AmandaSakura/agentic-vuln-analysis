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


class AgentRuntimeMode(StrEnum):
    SCRIPTED = "scripted"
    LIVE = "live"


class AgentSystemVersion(StrEnum):
    E1_LOCAL_SINGLE = "E1"
    E2_TEXT_SINGLE = "E2"
    E3_GRAPH_SINGLE = "E3"
    E4_GRAPH_MULTI = "E4"
    E5_GRAPH_FAST = "E5"


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
    experiment_name: str
    limitation: str
    candidate_protocol: str
    retrieval_modes: tuple[RetrievalMode, ...]
    budget: RetrievalBudget
    hybrid_aggregation: Literal["per-branch-union-under-shared-token-budget"]
    critical_hit_policy: Literal["full-critical-line-retained"]


class CommandPolicy(FrozenModel):
    command: str
    kind: Literal["experiment", "diagnostic", "data-preparation", "harness"]
    claim_eligible: bool
    harness_id: str | None = None


class ModelRuntimeHarness(FrozenModel):
    protocol: Literal["openai-compatible-chat"]
    base_url_env: str
    model_env: str
    api_key_env: str
    temperature: float = Field(ge=0.0, le=2.0)
    request_timeout_seconds: int = Field(ge=1, le=600)


class ReActLoopHarness(FrozenModel):
    max_steps: int = Field(ge=1, le=32)
    max_tool_observation_tokens: int = Field(ge=128, le=100_000)
    require_model_action: bool
    require_tool_observation: bool
    final_schema: str


class ExpertAgentHarness(FrozenModel):
    expert: ExpertName
    mandate: str
    tools: tuple[str, ...]
    require_react_trace: bool


class ValidationRuntimeHarness(FrozenModel):
    validators: tuple[str, ...]
    command_policy: Literal["typed-allowlist"]
    network_policy: Literal["disabled-or-loopback"]
    subject_mode: Literal["read-only"]
    timeout_seconds: int = Field(ge=1, le=600)
    max_output_bytes: int = Field(ge=1_024, le=10_000_000)


class AgentSystemHarness(FrozenModel):
    system: AgentSystemVersion
    retrieval: RetrievalMode
    budget: RetrievalBudget
    planner_enabled: bool
    expert_order: tuple[ExpertName, ...]
    full_review_policy: Literal["single", "majority"]
    quorum: int = Field(default=2, ge=2, le=3)
    fast_confidence: float = Field(default=0.80, ge=0.0, le=1.0)
    early_quorum_after: int | None = Field(default=None, ge=2, le=3)


class EndToEndHarness(FrozenModel):
    harness_id: str
    runtime_modes: tuple[AgentRuntimeMode, ...]
    claim_runtime_mode: AgentRuntimeMode
    model: ModelRuntimeHarness
    react_loop: ReActLoopHarness
    planner_max_subtasks: int = Field(ge=1, le=32)
    experts: tuple[ExpertAgentHarness, ...]
    validation: ValidationRuntimeHarness
    tier1_languages: tuple[str, ...]
    fallback_suffixes: tuple[str, ...]
    development_repositories: tuple[str, ...]
    held_out_positive_dataset: str
    paired_negative_sources: tuple[str, ...]
    systems: tuple[AgentSystemHarness, ...]
    required_metrics: tuple[str, ...]

    def system_spec(self, system: AgentSystemVersion) -> AgentSystemHarness:
        matches = [spec for spec in self.systems if spec.system == system]
        if len(matches) != 1:
            raise ValueError(
                f"{self.harness_id}: expected one agent-system spec for {system}, "
                f"found {len(matches)}"
            )
        return matches[0]


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
        "One source-derived servlet doGet method per BenchmarkTest case, retrieved against "
        "one repository-wide method corpus containing every BenchmarkJava main-source file, "
        "including shared helpers; the identical local method is the base context for every system."
    ),
    primary_scope=("cmdi", "ldapi", "pathtraver", "sqli", "xpathi"),
    primary_scope_rationale=(
        "Predeclared API families targeted by the current command, LDAP, path, SQL, and XPath "
        "sink patterns; pattern coverage within those families is intentionally incomplete."
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
    harness_id="vulngym-oracle-retrieval-v3",
    dataset_name="VulnGym v0.1.4 verified Python subset",
    dataset_role=DatasetRole.ORACLE_DIAGNOSTIC,
    claim_eligible=False,
    experiment_name="oracle-seeded critical-context retrieval coverage",
    limitation=(
        "VulnGym entry_point is used only as the retrieval seed; this is not end-to-end "
        "vulnerability recall."
    ),
    candidate_protocol=(
        "A verified VulnGym entry point is an explicit oracle seed; the identical containing "
        "function is the base context for local, text, graph, and hybrid retrieval. Hybrid "
        "retrieval unions text, entry-graph, and lexical-seed graph branches under the same "
        "total token budget; top_k is a per-branch cap for hybrid."
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
    hybrid_aggregation="per-branch-union-under-shared-token-budget",
    critical_hit_policy="full-critical-line-retained",
)


AGENT_BASE_TOKENS = 4_096
AGENT_AUGMENTATION_TOKENS = 12_288
AGENT_TOP_K = 12
AGENT_GRAPH_HOPS = 4


def _agent_system(
    system: AgentSystemVersion,
    retrieval: RetrievalMode,
    *,
    planner_enabled: bool,
    experts: tuple[ExpertName, ...],
    policy: Literal["single", "majority"],
    early_quorum_after: int | None = None,
) -> AgentSystemHarness:
    augmented = retrieval != RetrievalMode.LOCAL
    return AgentSystemHarness(
        system=system,
        retrieval=retrieval,
        budget=RetrievalBudget(
            top_k=AGENT_TOP_K if augmented else 0,
            base_context_tokens=AGENT_BASE_TOKENS,
            augmentation_context_tokens=(
                AGENT_AUGMENTATION_TOKENS if augmented else 0
            ),
            graph_hops=(
                AGENT_GRAPH_HOPS
                if retrieval in {RetrievalMode.GRAPH, RetrievalMode.HYBRID}
                else 0
            ),
        ),
        planner_enabled=planner_enabled,
        expert_order=experts,
        full_review_policy=policy,
        early_quorum_after=early_quorum_after,
    )


FULL_SYSTEM_HARNESS = EndToEndHarness(
    harness_id="agentic-vulnerability-system-v1",
    runtime_modes=(AgentRuntimeMode.SCRIPTED, AgentRuntimeMode.LIVE),
    claim_runtime_mode=AgentRuntimeMode.LIVE,
    model=ModelRuntimeHarness(
        protocol="openai-compatible-chat",
        base_url_env="CV_AGENT_MODEL_BASE_URL",
        model_env="CV_AGENT_MODEL_NAME",
        api_key_env="CV_AGENT_MODEL_API_KEY",
        temperature=0.0,
        request_timeout_seconds=180,
    ),
    react_loop=ReActLoopHarness(
        max_steps=8,
        max_tool_observation_tokens=8_192,
        require_model_action=True,
        require_tool_observation=True,
        final_schema="AgentExpertVote",
    ),
    planner_max_subtasks=8,
    experts=(
        ExpertAgentHarness(
            expert="scan",
            mandate=(
                "Locate externally reachable security-sensitive operations and produce "
                "candidate vulnerability categories without deciding safety from absence."
            ),
            tools=(
                "search_symbols",
                "read_span",
                "find_references",
                "get_callers",
                "get_callees",
                "run_static_check",
                "run_fixture_test",
            ),
            require_react_trace=True,
        ),
        ExpertAgentHarness(
            expert="taint",
            mandate=(
                "Establish or refute a source-to-sink path with transformations, "
                "sanitizers, and missing graph edges stated explicitly."
            ),
            tools=(
                "read_span",
                "get_callers",
                "get_callees",
                "find_sources",
                "find_sinks",
                "trace_dataflow",
                "find_sanitizers",
                "compare_vulnerable_and_fixed",
            ),
            require_react_trace=True,
        ),
        ExpertAgentHarness(
            expert="authz",
            mandate=(
                "Model principal, action, resource or tenant scope, and enforcement "
                "guards; abstain when the candidate is outside authorization semantics."
            ),
            tools=(
                "read_span",
                "get_routes",
                "get_callers",
                "get_callees",
                "get_guards",
                "inspect_principal",
                "inspect_resource_scope",
                "compare_route_and_service_guard",
                "run_loopback_http_case",
            ),
            require_react_trace=True,
        ),
    ),
    validation=ValidationRuntimeHarness(
        validators=(
            "run_static_check",
            "run_fixture_test",
            "run_loopback_http_case",
            "compare_vulnerable_and_fixed",
        ),
        command_policy="typed-allowlist",
        network_policy="disabled-or-loopback",
        subject_mode="read-only",
        timeout_seconds=120,
        max_output_bytes=1_000_000,
    ),
    tier1_languages=("python", "typescript", "javascript", "go"),
    fallback_suffixes=(
        ".swift",
        ".vue",
        ".yaml",
        ".yml",
        ".ini",
        ".jsx",
        ".sh",
        ".svelte",
    ),
    development_repositories=(
        "https://github.com/google/adk-python",
        "https://github.com/PrefectHQ/fastmcp",
        "https://github.com/jlowin/fastmcp",
    ),
    held_out_positive_dataset="VulnGym v0.1.4 verified entries excluding development repositories",
    paired_negative_sources=(
        "OSV same-repository verified fixed Git descendants",
        "OWASP Benchmark positive/negative executable cases",
        "PrimeVul paired C/C++ optional external discrimination set",
    ),
    systems=(
        _agent_system(
            AgentSystemVersion.E1_LOCAL_SINGLE,
            RetrievalMode.LOCAL,
            planner_enabled=False,
            experts=("scan",),
            policy="single",
        ),
        _agent_system(
            AgentSystemVersion.E2_TEXT_SINGLE,
            RetrievalMode.TEXT,
            planner_enabled=False,
            experts=("scan",),
            policy="single",
        ),
        _agent_system(
            AgentSystemVersion.E3_GRAPH_SINGLE,
            RetrievalMode.GRAPH,
            planner_enabled=False,
            experts=("scan",),
            policy="single",
        ),
        _agent_system(
            AgentSystemVersion.E4_GRAPH_MULTI,
            RetrievalMode.GRAPH,
            planner_enabled=True,
            experts=("scan", "taint", "authz"),
            policy="majority",
        ),
        _agent_system(
            AgentSystemVersion.E5_GRAPH_FAST,
            RetrievalMode.GRAPH,
            planner_enabled=True,
            experts=("scan", "taint", "authz"),
            policy="majority",
            early_quorum_after=2,
        ),
    ),
    required_metrics=(
        "advisory_recall",
        "entry_recall",
        "precision",
        "population_false_positive_rate",
        "covered_false_positive_rate",
        "coverage",
        "abstain_rate",
        "paired_graph_text_outcomes",
        "validation_status_counts",
        "expert_model_tool_calls",
        "fast_slow_path_counts",
        "clustered_uncertainty",
    ),
)


COMMAND_POLICIES = (
    CommandPolicy(command="harness-check", kind="harness", claim_eligible=False),
    CommandPolicy(command="synthetic", kind="diagnostic", claim_eligible=False),
    CommandPolicy(
        command="agentic-smoke",
        kind="diagnostic",
        claim_eligible=False,
        harness_id=FULL_SYSTEM_HARNESS.harness_id,
    ),
    CommandPolicy(
        command="agentic-eval",
        kind="diagnostic",
        claim_eligible=False,
        harness_id=FULL_SYSTEM_HARNESS.harness_id,
    ),
    CommandPolicy(
        command="agentic-live-owasp",
        kind="diagnostic",
        claim_eligible=False,
        harness_id=FULL_SYSTEM_HARNESS.harness_id,
    ),
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


def command_policy(command: str) -> CommandPolicy:
    matches = [policy for policy in COMMAND_POLICIES if policy.command == command]
    if len(matches) != 1:
        raise ValueError(f"command is not registered in the project harness: {command}")
    return matches[0]


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"result field {name} must be an object")
    return value


def _list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"result field {name} must be an array")
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


def _vulngym_summary(
    records: list[Mapping[str, object]],
    modes: tuple[str, ...],
) -> dict[str, object]:
    return {
        mode: {
            "hit_count": sum(
                bool(_mapping(record["hits"], "entries.hits")[mode])
                for record in records
            ),
            "hit_rate": (
                sum(
                    bool(_mapping(record["hits"], "entries.hits")[mode])
                    for record in records
                )
                / len(records)
                if records
                else None
            ),
        }
        for mode in modes
    }


def _validate_vulngym_summary(
    value: object,
    records: list[Mapping[str, object]],
    modes: tuple[str, ...],
    name: str,
) -> None:
    summary = _mapping(value, name)
    expected = _vulngym_summary(records, modes)
    if summary != expected:
        raise ValueError(f"VulnGym summary {name} is inconsistent with entry hits")


def validate_vulngym_result_payload(
    payload: Mapping[str, object],
    *,
    expected_entries: Mapping[str, Mapping[str, object]],
    expected_subject_revisions: Mapping[str, str],
) -> None:
    modes = tuple(
        mode.value for mode in VULNGYM_RETRIEVAL_HARNESS.retrieval_modes
    )
    if not expected_entries:
        raise ValueError("VulnGym validation requires selected entry identities")
    if not expected_subject_revisions:
        raise ValueError("VulnGym validation requires selected subject revisions")
    for entry_id, expected in expected_entries.items():
        subject_key = expected.get("subject_key")
        repository_url = expected.get("repository_url")
        if (
            not entry_id
            or not isinstance(subject_key, str)
            or not subject_key.strip()
            or not isinstance(repository_url, str)
            or not repository_url.strip()
        ):
            raise ValueError("selected VulnGym entry mapping lacks repository identity")
        if not isinstance(expected.get("cross_file"), bool):
            raise ValueError("selected VulnGym entry mapping has invalid cross-file state")
    expected_entry_ids = set(expected_entries)
    expected_cross_file_entry_ids = {
        entry_id
        for entry_id, expected in expected_entries.items()
        if bool(expected.get("cross_file"))
    }
    expected_entry_subjects = {
        str(expected.get("subject_key")) for expected in expected_entries.values()
    }
    if expected_entry_subjects != set(expected_subject_revisions):
        raise ValueError("selected VulnGym entries and subjects are inconsistent")
    if payload.get("harness_id") != VULNGYM_RETRIEVAL_HARNESS.harness_id:
        raise ValueError("VulnGym result carries the wrong harness id")
    if payload.get("dataset") != VULNGYM_RETRIEVAL_HARNESS.dataset_name:
        raise ValueError("VulnGym result carries the wrong dataset name")
    if payload.get("claim_eligible") is not False:
        raise ValueError("VulnGym oracle result cannot be claim eligible")
    if payload.get("dataset_role") != VULNGYM_RETRIEVAL_HARNESS.dataset_role.value:
        raise ValueError("VulnGym result carries the wrong dataset role")
    if payload.get("experiment") != VULNGYM_RETRIEVAL_HARNESS.experiment_name:
        raise ValueError("VulnGym result carries the wrong experiment name")
    if payload.get("limitation") != VULNGYM_RETRIEVAL_HARNESS.limitation:
        raise ValueError("VulnGym result must retain its oracle limitation")
    if payload.get("candidate_protocol") != VULNGYM_RETRIEVAL_HARNESS.candidate_protocol:
        raise ValueError("VulnGym result carries the wrong candidate protocol")
    _require_keys(
        payload,
        {
            "dataset",
            "experiment",
            "limitation",
            "run_identity",
            "claim_assessment",
            "candidate_protocol",
            "retrieval_contract",
            "entry_count",
            "cross_file_entry_count",
            "entries",
            "overall",
            "cross_file",
            "same_file",
            "resolved_entry_count",
            "resolved_critical_count",
            "context_tokenizer",
            "context_token_count",
            "max_context_token_count_per_entry",
            "context_evidence_count",
            "max_context_evidence_count_per_entry",
            "repository_profiles",
            "by_repository",
            "graph_vs_local_hit_gain_percentage_points",
            "graph_vs_text_hit_gain_percentage_points",
            "hybrid_vs_text_hit_gain_percentage_points",
            "missed_entry_ids",
        },
        "root",
    )
    expected_contract = {
        **VULNGYM_RETRIEVAL_HARNESS.budget.model_dump(mode="json"),
        "total_context_tokens": VULNGYM_RETRIEVAL_HARNESS.budget.total_context_tokens,
        "modes": list(modes),
        "hybrid_aggregation": VULNGYM_RETRIEVAL_HARNESS.hybrid_aggregation,
        "critical_hit_policy": VULNGYM_RETRIEVAL_HARNESS.critical_hit_policy,
    }
    if payload["retrieval_contract"] != expected_contract:
        raise ValueError("VulnGym result retrieval contract differs from the project harness")
    if payload["context_tokenizer"] != "deterministic word-or-punctuation units":
        raise ValueError("VulnGym result carries the wrong context tokenizer")

    entries_raw = _list(payload["entries"], "entries")
    records: list[Mapping[str, object]] = []
    entry_ids: list[str] = []
    for index, raw_record in enumerate(entries_raw):
        record = _mapping(raw_record, f"entries[{index}]")
        _require_keys(
            record,
            {
                "entry_id",
                "repository_url",
                "subject_key",
                "cross_file",
                "entry_resolved",
                "critical_resolved",
                "hits",
                "evidence_counts",
            },
            f"entries[{index}]",
        )
        entry_id = str(record["entry_id"])
        if not entry_id:
            raise ValueError("VulnGym entry identity cannot be empty")
        expected = expected_entries.get(entry_id)
        if expected is None:
            raise ValueError(f"unexpected VulnGym entry identity: {entry_id}")
        if not str(record["repository_url"]) or not str(record["subject_key"]):
            raise ValueError(f"VulnGym entry {entry_id} lacks repository identity")
        if (
            str(record["subject_key"]) != str(expected.get("subject_key"))
            or str(record["repository_url"])
            != str(expected.get("repository_url"))
        ):
            raise ValueError(
                f"VulnGym entry {entry_id} differs from its selected repository mapping"
            )
        if not isinstance(record["cross_file"], bool):
            raise ValueError(f"VulnGym entry {entry_id} has invalid cross-file state")
        if record["cross_file"] is not bool(expected.get("cross_file")):
            raise ValueError(f"VulnGym entry {entry_id} has the wrong cross-file stratum")
        if not isinstance(record["entry_resolved"], bool) or not isinstance(
            record["critical_resolved"],
            bool,
        ):
            raise ValueError(f"VulnGym entry {entry_id} has invalid resolution state")
        hits = _mapping(record["hits"], f"entries[{index}].hits")
        if set(hits) != set(modes) or any(
            not isinstance(hits[mode], bool) for mode in modes
        ):
            raise ValueError(f"VulnGym entry {entry_id} has an invalid hit vector")
        if (not record["entry_resolved"] or not record["critical_resolved"]) and any(
            bool(hits[mode]) for mode in modes
        ):
            raise ValueError(f"unresolved VulnGym entry {entry_id} cannot be a retrieval hit")
        evidence_counts = _mapping(
            record["evidence_counts"],
            f"entries[{index}].evidence_counts",
        )
        if set(evidence_counts) != set(modes):
            raise ValueError(f"VulnGym entry {entry_id} has an invalid evidence-count vector")
        for mode in modes:
            value = evidence_counts[mode]
            if type(value) is not int or int(value) < 0:
                raise ValueError(f"VulnGym entry {entry_id} has invalid evidence count for {mode}")
        records.append(record)
        entry_ids.append(entry_id)

    if len(entry_ids) != len(set(entry_ids)) or set(entry_ids) != expected_entry_ids:
        raise ValueError("VulnGym result entries differ from the selected entry identities")
    if type(payload["entry_count"]) is not int or payload["entry_count"] != len(
        expected_entry_ids
    ):
        raise ValueError("VulnGym entry count differs from the selected denominator")
    if (
        type(payload["cross_file_entry_count"]) is not int
        or payload["cross_file_entry_count"] != len(expected_cross_file_entry_ids)
    ):
        raise ValueError("VulnGym cross-file count differs from the selected stratum")
    if type(payload["resolved_entry_count"]) is not int or payload[
        "resolved_entry_count"
    ] != sum(bool(record["entry_resolved"]) for record in records):
        raise ValueError("VulnGym resolved-entry count is inconsistent")
    if type(payload["resolved_critical_count"]) is not int or payload[
        "resolved_critical_count"
    ] != sum(bool(record["critical_resolved"]) for record in records):
        raise ValueError("VulnGym resolved-critical count is inconsistent")

    cross_records = [record for record in records if bool(record["cross_file"])]
    same_records = [record for record in records if not bool(record["cross_file"])]
    _validate_vulngym_summary(payload["overall"], records, modes, "overall")
    _validate_vulngym_summary(
        payload["cross_file"],
        cross_records,
        modes,
        "cross_file",
    )
    _validate_vulngym_summary(
        payload["same_file"],
        same_records,
        modes,
        "same_file",
    )
    records_by_repository: dict[str, list[Mapping[str, object]]] = {}
    for record in records:
        records_by_repository.setdefault(str(record["repository_url"]), []).append(
            record
        )
    by_repository = _mapping(payload["by_repository"], "by_repository")
    if set(by_repository) != set(records_by_repository):
        raise ValueError("VulnGym repository summaries differ from selected repositories")
    for repository_url, repository_records in records_by_repository.items():
        _validate_vulngym_summary(
            by_repository[repository_url],
            repository_records,
            modes,
            f"by_repository.{repository_url}",
        )

    missed = _mapping(payload["missed_entry_ids"], "missed_entry_ids")
    if set(missed) != set(modes):
        raise ValueError("VulnGym missed-entry lists must cover every retrieval mode")
    for mode in modes:
        expected_missed = sorted(
            str(record["entry_id"])
            for record in records
            if not bool(_mapping(record["hits"], "entries.hits")[mode])
        )
        if missed[mode] != expected_missed:
            raise ValueError(f"VulnGym missed-entry list is inconsistent for {mode}")

    overall = _mapping(payload["overall"], "overall")
    rates = {
        mode: _mapping(overall[mode], f"overall.{mode}")["hit_rate"]
        for mode in modes
    }
    expected_gains = {
        "graph_vs_local_hit_gain_percentage_points": 100.0
        * (float(rates["graph"]) - float(rates["local"])),
        "graph_vs_text_hit_gain_percentage_points": 100.0
        * (float(rates["graph"]) - float(rates["text"])),
        "hybrid_vs_text_hit_gain_percentage_points": 100.0
        * (float(rates["hybrid"]) - float(rates["text"])),
    }
    for field, expected in expected_gains.items():
        if payload[field] != expected:
            raise ValueError(f"VulnGym gain field is inconsistent: {field}")

    context_totals = _mapping(payload["context_token_count"], "context_token_count")
    context_maxima = _mapping(
        payload["max_context_token_count_per_entry"],
        "max_context_token_count_per_entry",
    )
    evidence_totals = _mapping(payload["context_evidence_count"], "context_evidence_count")
    evidence_maxima = _mapping(
        payload["max_context_evidence_count_per_entry"],
        "max_context_evidence_count_per_entry",
    )
    if set(context_totals) != set(modes) or set(context_maxima) != set(modes):
        raise ValueError("VulnGym context diagnostics must cover every retrieval mode")
    if set(evidence_totals) != set(modes) or set(evidence_maxima) != set(modes):
        raise ValueError("VulnGym evidence-count diagnostics must cover every retrieval mode")
    for mode in modes:
        total = context_totals[mode]
        maximum = context_maxima[mode]
        if type(total) is not int or type(maximum) is not int or total < 0 or maximum < 0:
            raise ValueError(f"VulnGym context diagnostics are invalid for {mode}")
        limit = (
            VULNGYM_RETRIEVAL_HARNESS.budget.base_context_tokens
            if mode == RetrievalMode.LOCAL.value
            else VULNGYM_RETRIEVAL_HARNESS.budget.total_context_tokens
        )
        if maximum > limit or total > len(records) * limit or total < maximum:
            raise ValueError(f"VulnGym context budget was exceeded for {mode}")
        evidence_total = evidence_totals[mode]
        evidence_maximum = evidence_maxima[mode]
        expected_counts = [
            int(_mapping(record["evidence_counts"], "entries.evidence_counts")[mode])
            for record in records
        ]
        if (
            type(evidence_total) is not int
            or type(evidence_maximum) is not int
            or evidence_total != sum(expected_counts)
            or evidence_maximum != max(expected_counts, default=0)
        ):
            raise ValueError(f"VulnGym evidence-count diagnostics are inconsistent for {mode}")

    profiles_raw = _list(payload["repository_profiles"], "repository_profiles")
    profiles: dict[str, Mapping[str, object]] = {}
    for index, raw_profile in enumerate(profiles_raw):
        profile = _mapping(raw_profile, f"repository_profiles[{index}]")
        _require_keys(
            profile,
            {
                "subject_key",
                "repository_url",
                "commit",
                "dirty",
                "source_file_count",
                "function_document_count",
                "parse_error_count",
            },
            f"repository_profiles[{index}]",
        )
        subject_key = str(profile["subject_key"])
        if subject_key in profiles:
            raise ValueError(f"duplicate VulnGym subject profile: {subject_key}")
        if not isinstance(profile["dirty"], bool):
            raise ValueError(f"VulnGym subject profile {subject_key} has invalid dirty state")
        for field in (
            "source_file_count",
            "function_document_count",
            "parse_error_count",
        ):
            if type(profile[field]) is not int or int(profile[field]) < 0:
                raise ValueError(f"VulnGym subject profile {subject_key} has invalid {field}")
        if (
            int(profile["source_file_count"]) < 1
            or int(profile["function_document_count"]) < 1
            or int(profile["parse_error_count"]) > int(profile["source_file_count"])
        ):
            raise ValueError(f"VulnGym subject profile {subject_key} has impossible counts")
        profiles[subject_key] = profile
    if set(profiles) != set(expected_subject_revisions):
        raise ValueError("VulnGym subject profiles differ from selected subjects")
    if {str(record["subject_key"]) for record in records} != set(
        expected_subject_revisions
    ):
        raise ValueError("VulnGym entries do not cover every selected subject")
    for subject_key, revision in expected_subject_revisions.items():
        profile = profiles[subject_key]
        if profile["commit"] != revision:
            raise ValueError(f"VulnGym subject profile has wrong revision: {subject_key}")
        subject_records = [
            record
            for record in records
            if str(record["subject_key"]) == subject_key
        ]
        repository_urls = {
            str(record["repository_url"]) for record in subject_records
        }
        if repository_urls != {str(profile["repository_url"])}:
            raise ValueError(
                f"VulnGym subject profile has inconsistent repository URL: {subject_key}"
            )

    _validate_run_identity(payload)
    identity = _mapping(payload["run_identity"], "run_identity")
    datasets = _mapping(identity["datasets"], "run_identity.datasets")
    if set(datasets) != {"VulnGym", *expected_subject_revisions}:
        raise ValueError("VulnGym run identity has the wrong dataset/subject set")
    for subject_key, revision in expected_subject_revisions.items():
        dataset_identity = _mapping(
            datasets[subject_key],
            f"run_identity.datasets.{subject_key}",
        )
        if dataset_identity["revision"] != revision:
            raise ValueError(f"VulnGym run identity has wrong revision: {subject_key}")
        if profiles[subject_key]["dirty"] is not dataset_identity["dirty"]:
            raise ValueError(f"VulnGym subject dirty state is inconsistent: {subject_key}")
    assessment = _mapping(payload["claim_assessment"], "claim_assessment")
    if assessment["eligible"] is not False:
        raise ValueError("VulnGym oracle results cannot pass claim assessment")


def describe_project_harness() -> dict[str, object]:
    validate_project_harness()
    return {
        "status": "PASS",
        "owasp": OWASP_HARNESS.model_dump(mode="json"),
        "vulngym_retrieval": VULNGYM_RETRIEVAL_HARNESS.model_dump(mode="json"),
        "full_system": FULL_SYSTEM_HARNESS.model_dump(mode="json"),
        "commands": [policy.model_dump(mode="json") for policy in COMMAND_POLICIES],
    }


# Fail at import time if the single source of truth becomes internally inconsistent.
validate_project_harness()
