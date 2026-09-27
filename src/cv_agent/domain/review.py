"""Expert conclusions, validation plans and complete review results."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from cv_agent.harness import AgentRuntimeMode, ExpertName
from cv_agent.domain.types import FrozenModel, VerdictLabel
from cv_agent.domain.chat import ModelUsage
from cv_agent.domain.evidence import ReActStep, ToolObservation, ValidationStatus


class AgentExpertConclusion(FrozenModel):
    expert: ExpertName
    label: VerdictLabel
    confidence: float = Field(ge=0.0, le=1.0)
    validation_status: ValidationStatus
    evidence_ids: tuple[str, ...] = ()
    supporting_observation_ids: tuple[str, ...] = ()
    counter_observation_ids: tuple[str, ...] = ()
    unresolved_observation_ids: tuple[str, ...] = ()
    rationale: Annotated[str, Field(max_length=360)]

class AgentExpertVote(AgentExpertConclusion):
    runtime_mode: AgentRuntimeMode
    trace: tuple[ReActStep, ...]
    model_ids: tuple[str, ...]
    model_calls: int = Field(ge=1)
    tool_calls: int = Field(ge=1)
    tool_observation_token_count: int = Field(ge=0)
    usage: ModelUsage

class ValidationSubtask(FrozenModel):
    task_id: Annotated[str, Field(max_length=64)]
    objective: Annotated[str, Field(max_length=280)]
    expert: ExpertName
    allowed_validator: Annotated[str, Field(max_length=80)]
    # A fixture that replaces mandatory checks must name the qualified case.
    # Unbound fixture tasks remain available for diagnostic observations.
    fixture_case_id: str | None = None
    dependencies: tuple[str, ...] = ()
    success_condition: Annotated[str, Field(max_length=220)]

    @model_validator(mode="after")
    def validate_fixture_binding(self) -> ValidationSubtask:
        if self.fixture_case_id is not None:
            if not self.fixture_case_id.strip():
                raise ValueError("fixture_case_id must be nonempty")
            if self.allowed_validator != "run_fixture_test":
                raise ValueError("fixture_case_id requires run_fixture_test")
        return self

class ValidationPlan(FrozenModel):
    candidate_id: str
    vulnerability_hypotheses: tuple[Annotated[str, Field(max_length=180)], ...]
    subtasks: tuple[ValidationSubtask, ...]
    rationale: Annotated[str, Field(max_length=600)]

    @model_validator(mode="after")
    def validate_task_graph(self) -> ValidationPlan:
        if not self.subtasks:
            raise ValueError("validation plan must contain at least one executable subtask")
        task_ids = [task.task_id for task in self.subtasks]
        if len(task_ids) != len(set(task_ids)):
            raise ValueError("validation plan contains duplicate task ids")
        known: set[str] = set()
        for task in self.subtasks:
            if not (
                task.task_id.strip()
                and task.objective.strip()
                and task.allowed_validator.strip()
                and task.success_condition.strip()
            ):
                raise ValueError(
                    "validation task identity, objective, validator, and success condition "
                    "are required"
                )
            missing = set(task.dependencies) - known
            if missing:
                raise ValueError(
                    f"validation task {task.task_id} has forward or unknown dependencies: "
                    f"{sorted(missing)}"
                )
            known.add(task.task_id)
        return self

class PlannerResult(FrozenModel):
    runtime_mode: AgentRuntimeMode
    plan: ValidationPlan
    trace: tuple[ReActStep, ...]
    model_ids: tuple[str, ...]
    model_calls: int = Field(ge=1)
    # A scoped patch can reuse the routing source observation without another read.
    tool_calls: int = Field(ge=0)
    tool_observation_token_count: int = Field(ge=0)
    usage: ModelUsage

class ValidationTaskExecution(FrozenModel):
    task_id: str | None
    vote: AgentExpertVote
    # None denotes a legacy record without completion evidence; never infer
    # success from a terminal vote or from its prose rationale.
    validator_completed: bool | None = None


class BlockedValidationTask(FrozenModel):
    task_id: str
    expert: ExpertName
    dependencies: tuple[str, ...]


class TaskOrigin(FrozenModel):
    task_id: str
    origin: Literal['policy', 'jev', 'llm']
    decision_id: str | None = None


class RoutingDecision(FrozenModel):
    decision_id: str
    choice: str
    selected_probability: float = Field(ge=0, le=1)
    provider_confidence: float = Field(ge=0, le=1)
    threshold: float = Field(ge=0, le=1)
    accepted: bool
    applied: bool = False
    applied_reason: str | None = None
    action: Literal['validator', 'expert_react', 'llm_planner']
    reason: str


class RoutingResult(FrozenModel):
    """Scheduling decisions are not expert ballots or vulnerability evidence."""
    runtime_mode: AgentRuntimeMode
    spec_version: int = 2
    mode: Literal['off', 'shadow', 'active']
    observation: ToolObservation | None = None
    decisions: dict[str, RoutingDecision] = Field(default_factory=dict)
    state_digest: str | None = None
    latency_sec: float = Field(default=0, ge=0)
    answers: dict[str, dict] = Field(default_factory=dict)
    model_id: str | None = None
    model_calls: int = Field(ge=0, le=2)
    tool_calls: int = Field(ge=0, le=1)
    usage: ModelUsage = Field(default_factory=lambda: ModelUsage(input_tokens=0, output_tokens=0, total_tokens=0))
    tool_observation_token_count: int = Field(default=0, ge=0)
    plan: ValidationPlan | None = None
    proposed_plan: ValidationPlan | None = None
    escalation_reason: str | None = None
    locked_tasks: tuple[ValidationSubtask, ...] = ()
    task_origins: tuple[TaskOrigin, ...] = ()
    fallback_scope: str | None = None
    rejection_reasons: dict[str, str] = Field(default_factory=dict)


class SourceAdmissionRecord(FrozenModel):
    path: str
    bound_call_source: str
    call_symbol: str
    graph_distance: int = Field(ge=1)
    document_sha256: str
    source_sha256: str | None = None
    serialized_token_cost: int = Field(default=0, ge=0)
    status: Literal["admitted", "skipped"]
    reason: str


class RetrievalAdmissionAudit(FrozenModel):
    subject_digest: str
    records: tuple[SourceAdmissionRecord, ...] = ()


class AgenticVerdict(FrozenModel):
    runtime_mode: AgentRuntimeMode
    label: VerdictLabel
    confidence: float = Field(ge=0.0, le=1.0)
    path: Literal["single", "fast", "slow"]
    rationale: str
    planner: PlannerResult | None = None
    votes: tuple[AgentExpertVote, ...]
    task_executions: tuple[ValidationTaskExecution, ...] = ()
    blocked_tasks: tuple[BlockedValidationTask, ...] = ()
    model_calls: int = Field(ge=1)
    tool_calls: int = Field(ge=1)
    usage: ModelUsage
    retrieval_context_token_count: int = Field(ge=0)
    tool_observation_token_count: int = Field(ge=0)
    context_token_count: int = Field(ge=0)
    context_accounting: Literal["utf8-byte-upper-bound"] = "utf8-byte-upper-bound"
    retrieval_admission: RetrievalAdmissionAudit | None = None

    @model_validator(mode="after")
    def context_components_match_total(self) -> AgenticVerdict:
        expected = (
            self.retrieval_context_token_count + self.tool_observation_token_count
        )
        if self.context_token_count != expected:
            raise ValueError("agentic context total does not match its measured components")
        return self


class RoutedAgenticVerdict(AgenticVerdict):
    """The Jev experiment adds routing without changing historical E1–E5 JSON."""
    routing: RoutingResult


class ApplicableAgenticVerdict(AgenticVerdict):
    """An opted-in expert policy records roles excluded from its ballot."""

    expert_policy: Literal["applicable_v1"] = "applicable_v1"
    skipped_experts: dict[ExpertName, str] = Field(default_factory=dict)


class RoutedApplicableAgenticVerdict(RoutedAgenticVerdict):
    expert_policy: Literal["applicable_v1"] = "applicable_v1"
    skipped_experts: dict[ExpertName, str] = Field(default_factory=dict)
