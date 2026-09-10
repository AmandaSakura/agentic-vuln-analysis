from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

from pydantic import BaseModel, ValidationError

from .agent_tools import ToolExecutionScope, ToolRegistry
from .agent_types import (
    AgentExpertConclusion,
    AgentExpertVote,
    ChatMessage,
    ModelUsage,
    PlannerResult,
    ReActStep,
    ValidationPlan,
    ValidationStatus,
)
from .harness import ExpertName, ReActLoopHarness
from .model_runtime import ChatModel, trusted_runtime_mode


OutputT = TypeVar("OutputT", bound=BaseModel)


@dataclass(frozen=True)
class ReActRun(Generic[OutputT]):
    output: OutputT
    trace: tuple[ReActStep, ...]
    model_ids: tuple[str, ...]
    model_calls: int
    tool_calls: int
    tool_observation_token_count: int
    usage: ModelUsage


def validate_conclusion(
    output: AgentExpertConclusion, trace: list[ReActStep],
    initial_evidence_ids: frozenset[str], required_validators: tuple[str, ...] = (),
    current_trace: list[ReActStep] | None = None,
) -> None:
    observations = [
        step.observation for step in trace
        if step.observation.status == "ok"
        and not step.observation.metadata.get("model_payload_suppressed")
    ]
    known = set(initial_evidence_ids)
    for observation in observations:
        known.update(observation.evidence_ids)
        if observation.citation_id:
            known.add(observation.citation_id)
    if set(output.evidence_ids) - known:
        raise ValueError("Unknown evidence reference. Cite retrieved evidence or a returned tool citation_id.")
    if output.label != "ABSTAIN" and not output.evidence_ids:
        raise ValueError("A material prediction must cite observed evidence.")
    executed = Counter(
        step.observation.tool for step in (current_trace if current_trace is not None else trace)
        if step.observation.status == "ok"
        and not step.observation.metadata.get("observation_truncated")
    )
    if Counter(required_validators) - executed:
        raise ValueError("Assigned validation tools must complete before finalizing the expert tasks.")
    if output.validation_status == ValidationStatus.UNRESOLVED:
        return
    expected = {
        ValidationStatus.CONFIRMED: "VULNERABLE", ValidationStatus.REFUTED: "SAFE",
    }[output.validation_status]
    if output.label != expected:
        raise ValueError("Validation status contradicts the prediction label.")
    referenced = [
        item for item in observations
        if not item.metadata.get("observation_truncated")
        and set(output.evidence_ids) & {*item.evidence_ids, item.citation_id}
        and item.validation_status not in {None, ValidationStatus.UNRESOLVED}
    ]
    if not referenced or any(item.validation_status != output.validation_status for item in referenced):
        raise ValueError(
            "CONFIRMED/REFUTED requires matching cited validator output; "
            "reading code alone only supports validation_status=UNRESOLVED."
        )


def _sum_optional(left: int | None, right: int | None) -> int | None:
    if left is None or right is None:
        return None
    return left + right


def _merge_usage(left: ModelUsage, right: ModelUsage) -> ModelUsage:
    return ModelUsage(
        input_tokens=_sum_optional(left.input_tokens, right.input_tokens),
        output_tokens=_sum_optional(left.output_tokens, right.output_tokens),
        total_tokens=_sum_optional(left.total_tokens, right.total_tokens),
    )


class ReActEngine:
    def __init__(
        self,
        *,
        model: ChatModel,
        tools: ToolRegistry,
        scope: ToolExecutionScope,
        harness: ReActLoopHarness,
        prior_trace: tuple[ReActStep, ...] = (),
        citation_prefix: str = "tool",
        citation_offset: int = 0,
    ) -> None:
        self.model = model
        self.runtime_mode = trusted_runtime_mode(model)
        self.tools = tools
        self.scope = scope
        self.harness = harness
        self.prior_trace = prior_trace
        self.citation_prefix = citation_prefix
        self.citation_offset = citation_offset

    def run(
        self,
        *,
        system_prompt: str,
        task_prompt: str,
        allowed_tools: tuple[str, ...],
        output_model: type[OutputT],
        required_validators: tuple[str, ...] = (),
        output_validator: Callable[[OutputT], None] | None = None,
    ) -> ReActRun[OutputT]:
        schema = json.dumps(
            output_model.model_json_schema(),
            sort_keys=True,
            separators=(",", ":"),
        )
        messages = [
            ChatMessage(role="system", content=system_prompt),
            ChatMessage(
                role="user",
                content=(
                    f"{task_prompt}\n\nUse the registered tools before reaching a material "
                    "conclusion. When finished, return exactly one JSON object matching "
                    f"this schema: {schema}"
                ),
            ),
        ]
        definitions = self.tools.definitions(allowed_tools)
        trace: list[ReActStep] = []
        model_ids: list[str] = []
        usage: ModelUsage | None = None
        model_calls = 0
        successful_observations = 0
        starting_observed_tokens = self.scope.observed_tokens

        for _ in range(self.harness.max_steps):
            reply = self.model.complete(messages, definitions)
            model_calls += 1
            model_ids.append(reply.model_id)
            usage = reply.usage if usage is None else _merge_usage(usage, reply.usage)
            if reply.tool_calls:
                messages.append(
                    ChatMessage(
                        role="assistant",
                        content=reply.content,
                        tool_calls=reply.tool_calls,
                    )
                )
                for call in reply.tool_calls:
                    observation = self.tools.invoke(
                        call,
                        allowed=allowed_tools,
                        scope=self.scope,
                        citation_id=f"{self.citation_prefix}:{self.citation_offset + len(trace) + 1}",
                    )
                    if observation.status == "ok":
                        successful_observations += 1
                    trace.append(
                        ReActStep(
                            step=self.citation_offset + len(trace) + 1,
                            model_id=reply.model_id,
                            tool_call=call,
                            observation=observation,
                        )
                    )
                    messages.append(
                        ChatMessage(
                            role="tool",
                            name=call.name,
                            tool_call_id=call.call_id,
                            content=self.tools.prompt_payload(observation),
                        )
                    )
                continue

            if self.harness.require_tool_observation and successful_observations == 0:
                messages.extend(
                    (
                        ChatMessage(role="assistant", content=reply.content),
                        ChatMessage(
                            role="user",
                            content=(
                                "A material conclusion requires at least one successful typed "
                                "tool observation. Call an allowed tool before finalizing."
                            ),
                        ),
                    )
                )
                continue
            try:
                raw_output = json.loads(reply.content or "")
                output = output_model.model_validate(raw_output)
                if isinstance(output, AgentExpertConclusion):
                    validate_conclusion(
                        output, [*self.prior_trace, *trace], self.scope.initial_evidence_ids,
                        required_validators, current_trace=trace,
                    )
                if output_validator is not None:
                    output_validator(output)
            except (ValueError, ValidationError) as error:
                messages.extend(
                    (
                        ChatMessage(role="assistant", content=reply.content),
                        ChatMessage(
                            role="user",
                            content=(
                                "The final object failed schema or evidence validation. Return corrected "
                                f"JSON only. Validation error: {error}"
                            ),
                        ),
                    )
                )
                continue
            return ReActRun(
                output=output,
                trace=tuple(trace),
                model_ids=tuple(dict.fromkeys(model_ids)),
                model_calls=model_calls,
                tool_calls=len(trace),
                tool_observation_token_count=self.scope.observed_tokens - starting_observed_tokens,
                usage=usage or ModelUsage(),
            )
        raise RuntimeError(
            f"ReAct loop exhausted its {self.harness.max_steps} model-step budget"
        )


def run_expert(
    engine: ReActEngine,
    *,
    expert: ExpertName,
    system_prompt: str,
    task_prompt: str,
    allowed_tools: tuple[str, ...],
    required_validators: tuple[str, ...] = (),
) -> AgentExpertVote:
    run = engine.run(
        system_prompt=system_prompt,
        task_prompt=task_prompt,
        allowed_tools=allowed_tools,
        output_model=AgentExpertConclusion,
        required_validators=required_validators,
    )
    if run.output.expert != expert:
        raise ValueError(
            f"expert output identity drifted: expected {expert}, got {run.output.expert}"
        )
    return AgentExpertVote(
        **run.output.model_dump(),
        runtime_mode=engine.runtime_mode,
        trace=run.trace,
        model_ids=run.model_ids,
        model_calls=run.model_calls,
        tool_calls=run.tool_calls,
        tool_observation_token_count=run.tool_observation_token_count,
        usage=run.usage,
    )


def run_planner(
    engine: ReActEngine,
    *,
    system_prompt: str,
    task_prompt: str,
    allowed_tools: tuple[str, ...],
    max_subtasks: int,
    output_validator: Callable[[ValidationPlan], None] | None = None,
) -> PlannerResult:
    run = engine.run(
        system_prompt=system_prompt,
        task_prompt=task_prompt,
        allowed_tools=allowed_tools,
        output_model=ValidationPlan,
        output_validator=output_validator,
    )
    if len(run.output.subtasks) > max_subtasks:
        raise ValueError(
            f"planner emitted {len(run.output.subtasks)} subtasks; maximum is {max_subtasks}"
        )
    return PlannerResult(
        runtime_mode=engine.runtime_mode,
        plan=run.output,
        trace=run.trace,
        model_ids=run.model_ids,
        model_calls=run.model_calls,
        tool_calls=run.tool_calls,
        tool_observation_token_count=run.tool_observation_token_count,
        usage=run.usage,
    )
