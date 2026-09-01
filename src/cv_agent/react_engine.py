from __future__ import annotations

import json
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
    ) -> None:
        self.model = model
        self.runtime_mode = trusted_runtime_mode(model)
        self.tools = tools
        self.scope = scope
        self.harness = harness

    def run(
        self,
        *,
        system_prompt: str,
        task_prompt: str,
        allowed_tools: tuple[str, ...],
        output_model: type[OutputT],
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
                    )
                    if observation.status == "ok":
                        successful_observations += 1
                    trace.append(
                        ReActStep(
                            step=len(trace) + 1,
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
            except (json.JSONDecodeError, ValidationError) as error:
                messages.extend(
                    (
                        ChatMessage(role="assistant", content=reply.content),
                        ChatMessage(
                            role="user",
                            content=(
                                "The final object failed schema validation. Return corrected "
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
                tool_observation_token_count=self.scope.observed_tokens,
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
) -> AgentExpertVote:
    run = engine.run(
        system_prompt=system_prompt,
        task_prompt=task_prompt,
        allowed_tools=allowed_tools,
        output_model=AgentExpertConclusion,
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
) -> PlannerResult:
    run = engine.run(
        system_prompt=system_prompt,
        task_prompt=task_prompt,
        allowed_tools=allowed_tools,
        output_model=ValidationPlan,
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
