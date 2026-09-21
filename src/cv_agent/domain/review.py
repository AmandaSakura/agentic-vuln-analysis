"""Expert conclusions, validation plans and complete review results."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from cv_agent.harness import AgentRuntimeMode, ExpertName
from cv_agent.domain.types import FrozenModel, VerdictLabel
from cv_agent.domain.chat import ModelUsage
from cv_agent.domain.evidence import ReActStep, ValidationStatus


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
    dependencies: tuple[str, ...] = ()
    success_condition: Annotated[str, Field(max_length=220)]

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
