"""Typed, immutable experiment and runtime contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from ..types import FrozenModel, SystemVersion


ExpertName = Literal["scan", "taint", "authz"]
OwaspExpertName = Literal["scan", "taint", "verify"]


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
    graph_direction: Literal["forward", "reverse", "both"] = "forward"
    graph_ranking: Literal["lexical", "distance"] = "lexical"

    @property
    def total_context_tokens(self) -> int:
        return self.base_context_tokens + self.augmentation_context_tokens


class SystemHarness(FrozenModel):
    system: SystemVersion
    retrieval: RetrievalMode
    budget: RetrievalBudget
    expert_order: tuple[OwaspExpertName, ...]
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
    max_tokens_env: str | None = None
    thinking_mode_env: str | None = None
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
