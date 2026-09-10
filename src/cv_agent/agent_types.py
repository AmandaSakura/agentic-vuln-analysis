from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, model_validator

from .harness import AgentRuntimeMode, ExpertName
from .types import FrozenModel, VerdictLabel


class ValidationStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    UNRESOLVED = "UNRESOLVED"


class ModelToolCall(FrozenModel):
    call_id: str
    name: str
    arguments: dict[str, Any]


class ChatMessage(FrozenModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str | None = None
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: tuple[ModelToolCall, ...] = ()


class ModelUsage(FrozenModel):
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)


class ModelReply(FrozenModel):
    model_id: str
    content: str | None = None
    tool_calls: tuple[ModelToolCall, ...] = ()
    usage: ModelUsage = Field(default_factory=ModelUsage)

    @model_validator(mode="after")
    def has_content_or_tool(self) -> ModelReply:
        if not self.content and not self.tool_calls:
            raise ValueError("model reply must contain text or a tool call")
        return self


class ToolObservation(FrozenModel):
    tool: str
    status: Literal["ok", "error", "blocked"]
    content: str
    evidence_ids: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)
    citation_id: str | None = None
    validation_status: ValidationStatus | None = None


class ReActStep(FrozenModel):
    step: int = Field(ge=1)
    model_id: str
    tool_call: ModelToolCall
    observation: ToolObservation


class AgentExpertConclusion(FrozenModel):
    expert: ExpertName
    label: VerdictLabel
    confidence: float = Field(ge=0.0, le=1.0)
    validation_status: ValidationStatus
    evidence_ids: tuple[str, ...] = ()
    rationale: str


class AgentExpertVote(AgentExpertConclusion):
    runtime_mode: AgentRuntimeMode
    trace: tuple[ReActStep, ...]
    model_ids: tuple[str, ...]
    model_calls: int = Field(ge=1)
    tool_calls: int = Field(ge=1)
    tool_observation_token_count: int = Field(ge=0)
    usage: ModelUsage


class ValidationSubtask(FrozenModel):
    task_id: str
    objective: str
    expert: ExpertName
    allowed_validator: str
    dependencies: tuple[str, ...] = ()
    success_condition: str


class ValidationPlan(FrozenModel):
    candidate_id: str
    vulnerability_hypotheses: tuple[str, ...]
    subtasks: tuple[ValidationSubtask, ...]
    rationale: str

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
    tool_calls: int = Field(ge=1)
    tool_observation_token_count: int = Field(ge=0)
    usage: ModelUsage


class ValidationTaskExecution(FrozenModel):
    task_id: str | None
    vote: AgentExpertVote


class AgenticVerdict(FrozenModel):
    runtime_mode: AgentRuntimeMode
    label: VerdictLabel
    confidence: float = Field(ge=0.0, le=1.0)
    path: Literal["single", "fast", "slow"]
    rationale: str
    planner: PlannerResult | None = None
    votes: tuple[AgentExpertVote, ...]
    task_executions: tuple[ValidationTaskExecution, ...] = ()
    model_calls: int = Field(ge=1)
    tool_calls: int = Field(ge=1)
    usage: ModelUsage
    retrieval_context_token_count: int = Field(ge=0)
    tool_observation_token_count: int = Field(ge=0)
    context_token_count: int = Field(ge=0)
    context_accounting: Literal["utf8-byte-upper-bound"] = "utf8-byte-upper-bound"

    @model_validator(mode="after")
    def context_components_match_total(self) -> AgenticVerdict:
        expected = (
            self.retrieval_context_token_count + self.tool_observation_token_count
        )
        if self.context_token_count != expected:
            raise ValueError("agentic context total does not match its measured components")
        return self
