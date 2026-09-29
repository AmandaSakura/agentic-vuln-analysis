"""Declared experiment defaults, retrieval budgets, and command policies."""

from __future__ import annotations

from typing import Literal

from cv_agent.domain.types import SystemVersion
from cv_agent.harness.models import AgentRuntimeMode, AgentSystemHarness, AgentSystemVersion, CommandPolicy, DatasetRole, EndToEndHarness, ExperimentHarness, ExpertAgentHarness, ExpertName, ModelRuntimeHarness, OwaspExpertName, ReActLoopHarness, RetrievalBudget, RetrievalEvaluationHarness, RetrievalMode, SystemHarness, ValidationRuntimeHarness


COMPARABLE_BASE_TOKENS = 512
COMPARABLE_AUGMENTATION_TOKENS = 1488
COMPARABLE_TOP_K = 10


def _system(
    system: SystemVersion,
    retrieval: RetrievalMode,
    *,
    top_k: int,
    augmentation_tokens: int,
    graph_hops: int,
    experts: tuple[OwaspExpertName, ...],
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
    harness_id="owasp-development-v3",
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
            graph_hops=4,
            experts=("scan",),
            policy="single",
        ),
        _system(
            SystemVersion.V4_GRAPH_MULTI,
            RetrievalMode.GRAPH,
            top_k=COMPARABLE_TOP_K,
            augmentation_tokens=COMPARABLE_AUGMENTATION_TOKENS,
            graph_hops=4,
            experts=("scan", "taint", "verify"),
            policy="majority",
        ),
        _system(
            SystemVersion.V5_GRAPH_FAST_SLOW,
            RetrievalMode.GRAPH,
            top_k=COMPARABLE_TOP_K,
            augmentation_tokens=COMPARABLE_AUGMENTATION_TOKENS,
            graph_hops=4,
            experts=("scan", "taint", "verify"),
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
        "conservative_false_positive_rate",
        "covered_false_positive_rate",
        "covered_fpr_reduction",
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
        max_tokens_env="CV_AGENT_MODEL_MAX_TOKENS",
        thinking_mode_env="CV_AGENT_MODEL_THINKING",
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
                "candidate vulnerability categories without deciding safety from absence. "
                "Validate candidates with a concrete Python eval probe or a registered fixture "
                "when applicable; sink presence alone is not confirmation. Distinguish an "
                "evidence-backed prediction (UNRESOLVED validation status) from successful "
                "typed validation. An exact-scope run_fixture_test CONFIRMED or REFUTED "
                "observation is typed validation for the declared candidate property; keep "
                "that label and validation_status in later same-expert tasks unless another "
                "exact-scope typed validator contradicts it. Static checks remain UNRESOLVED. "
                "For filesystem permission candidates, prefer validate_permission_mode over "
                "static chmod matching. "
                "For command injection candidates, inspect_command_construction status "
                "SANITIZED is affirmative counter-evidence for SAFE/UNRESOLVED and "
                "UNSANITIZED supports VULNERABLE/UNRESOLVED; do not require a typed "
                "REFUTED status from that static command inspector. "
                "These command facts must establish the declared candidate property "
                "under its source, location and input assumptions; a local helper "
                "status is not a caller proof. Other declared properties also require "
                "matching supporting proof. A source-bound run_bounded_execution_witness "
                "CONFIRMED observation is positive candidate command evidence; its literal "
                "or incomplete UNRESOLVED observation never proves SAFE. Supply only its "
                "reported missing call data in the preparation state's field destinations; "
                "preserve declared dataset scenarios, and supply classified hypotheses only for "
                "scenario-empty candidates. Runtime settings are system-owned. "
                "Inspect your own evidence rather than "
                "adopting another vote. "
                "When making a SAFE prediction based on an authorization or ownership check, "
                "first collect guard evidence with get_guards."
            ),
            tools=(
                "search_symbols",
                "read_span",
                "find_references",
                "get_callers",
                "get_callees",
                "get_guards",
                "run_static_check",
                "inspect_command_construction",
                "validate_permission_mode",
                "probe_python_eval",
                "run_fixture_test",
                "run_bounded_execution_witness",
            ),
            require_react_trace=True,
        ),
        ExpertAgentHarness(
            expert="taint",
            mandate=(
                "Assess a source-to-sink path with transformations, "
                "sanitizers, and missing graph edges stated explicitly. For command "
                "injection candidates, inspect_command_construction status SANITIZED "
                "is affirmative counter-evidence for a SAFE/UNRESOLVED vote, while "
                "UNSANITIZED supports a VULNERABLE/UNRESOLVED vote. "
                "Your label is an evidence-backed prediction, not a requirement for a "
                "concrete exploit witness. A validator returning UNRESOLVED does not by "
                "itself require ABSTAIN. Evaluate static MAY_REACH traces together with "
                "the actual caller, selected branch, helper interpolation and sanitizers. "
                "A material vote requires supporting proof bound to the candidate's "
                "declared property, source snapshot, location and input assumptions. "
                "Do not bridge an unresolved upstream transformation with source-reading "
                "inference or repeated expert votes. MAY_REACH, sink presence and local "
                "helper return values alone do not establish a complete dangerous path. "
                "An independent complete dangerous path may remain usable despite an "
                "unrelated unresolved path; SAFE requires coverage of all relevant paths. "
                "Conflicting proofs for the same scope require ABSTAIN. For dynamic "
                "evaluation, cite a matching candidate-bound proof; static flow alone "
                "does not support either material label. For command-execution tasks, "
                "a dependency's candidate-bound run_fixture_test CONFIRMED or REFUTED "
                "observation, or run_bounded_execution_witness CONFIRMED observation, "
                "is concrete command evidence for your dataflow judgment; "
                "your trace_dataflow MAY_REACH/UNRESOLVED result supplies path context "
                "and does not erase that matching fixture proof. Abstain when the required "
                "proof is missing. A complete static command proof can still support "
                "a prediction with UNRESOLVED validation status."
            ),
            tools=(
                "read_span",
                "get_callers",
                "get_callees",
                "find_sources",
                "find_sinks",
                "trace_dataflow",
                "inspect_command_construction",
                "find_sanitizers",
                "compare_vulnerable_and_fixed",
            ),
            require_react_trace=True,
        ),
        ExpertAgentHarness(
            expert="authz",
            mandate=(
                "Model principal, action, resource or tenant scope, and enforcement "
                "guards. Treat filesystem permission bits as resource access-control "
                "semantics when validate_permission_mode applies; abstain when the "
                "candidate is outside authorization semantics. A literal chmod mode "
                "proof covers only chmod-mode-others-write, not a directory race or "
                "a broader authorization boundary. Require proof of the declared "
                "candidate property before submitting a material vote. An exact-scope "
                "run_fixture_test observation for authorization-boundary, temporary-directory-race, "
                "or permission resource-access candidates is concrete access-control evidence; "
                "a narrower UNRESOLVED guard or chmod helper check does not erase that matching "
                "fixture proof."
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
                "validate_permission_mode",
                "run_loopback_http_case",
            ),
            require_react_trace=True,
        ),
    ),
    validation=ValidationRuntimeHarness(
        validators=(
            "run_static_check",
            "probe_python_eval",
            "run_fixture_test",
            "run_bounded_execution_witness",
            "run_loopback_http_case",
            "compare_vulnerable_and_fixed",
            "trace_dataflow",
            "inspect_command_construction",
            "validate_permission_mode",
            "compare_route_and_service_guard",
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
        "https://github.com/langchain-ai/langchain",
        "https://github.com/nltk/nltk",
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
    CommandPolicy(command="readiness", kind="harness", claim_eligible=False),
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


def command_policy(command: str) -> CommandPolicy:
    matches = [policy for policy in COMMAND_POLICIES if policy.command == command]
    if len(matches) != 1:
        raise ValueError(f"command is not registered in the project harness: {command}")
    return matches[0]
