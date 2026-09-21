from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

from pydantic import BaseModel, ValidationError

from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.agents.evidence_policy import validate_conclusion
from cv_agent.domain.review import AgentExpertConclusion, AgentExpertVote, PlannerResult, ValidationPlan
from cv_agent.domain.chat import ChatMessage, ModelUsage
from cv_agent.domain.evidence import ReActStep
from cv_agent.harness import ExpertName, ReActLoopHarness
from cv_agent.runtime.model import ChatModel, trusted_runtime_mode


OutputT = TypeVar("OutputT", bound=BaseModel)


def parse_final_json(content: str | None):
    """Accept bare JSON or one complete JSON code block, never extract from prose."""
    text = (content or "").strip()
    lines = text.splitlines()
    if len(lines) >= 3 and lines[0] in {"```json", "```"} and lines[-1] == "```":
        text = "\n".join(lines[1:-1])
    return json.loads(text)


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
                    "conclusion. When finished, return exactly one JSON object with no "
                    f"Markdown code fence, matching this schema: {schema}"
                ),
            ),
        ]
        messages.append(ChatMessage(role="user", content=(
            f"Remaining tool-observation budget for this subtask: {self.scope.remaining_tokens}. "
            f"Required validators: {', '.join(required_validators) or 'none'}. "
            "Run required validators before optional reads. Reuse already visible observations; "
            "read only missing line ranges instead of entire spans. Later subtasks share the expert budget."
        )))
        if output_model is AgentExpertConclusion:
            messages[0] = ChatMessage(
                role="system",
                content=(system_prompt + "\nEvidence contract: label is your prediction; "
                         "validation_status is the result of a cited typed validator, not your "
                         "confidence or interpretation of source code. Use CONFIRMED or REFUTED "
                         "only when a cited tool observation explicitly returns that same "
                         "validation_status. If an exact-scope validator returns CONFIRMED, "
                         "use label VULNERABLE with validation_status CONFIRMED; if it returns "
                         "REFUTED, use label SAFE with validation_status REFUTED unless another "
                         "exact-scope validator contradicts it. A successful tool call, zero static findings, or "
                         "reading code does not establish validation. Otherwise use UNRESOLVED. "
                         "An evidence-backed prediction may have UNRESOLVED validation; if the "
                         "visible evidence cannot establish a prediction, use label ABSTAIN. "
                         "SAFE/UNRESOLVED requires cited affirmative counter-evidence, such as "
                         "observed guards or sanitizers; these remain hypotheses, not refutations. "
                         "Source reads, search hits, zero findings, inconclusive probes, and a "
                         "repair in another revision cannot alone support SAFE. A typed refutation "
                         "must match this candidate and source snapshot and must not be truncated. "
                         "A material prediction cannot contradict concrete validator evidence "
                         "for the same candidate and scope, even if you cite another observation. "
                         "Tool path arguments must exactly match retrieved_code paths or paths "
                         "returned by previous tools; file:line markers are not tool paths. "
                         "Use supporting_observation_ids for observations that support your "
                         "prediction, counter_observation_ids for observations that cut against it, "
                         "and unresolved_observation_ids for observations that leave the issue open. "
                         "For SAFE, observed sanitizers or guards supporting safety belong in "
                         "supporting_observation_ids; counter_observation_ids means evidence "
                         "against SAFE, not evidence against the vulnerability hypothesis. "
                         "For CONFIRMED/REFUTED, include the supporting validator citation_id "
                         "in evidence_ids as well as supporting_observation_ids. "
                         "Do not repeatedly request a path outside admitted scope. Complete "
                         "assigned validators before finalizing; do not invent evidence. Keep "
                         "the final rationale terse and cite evidence_ids instead of copying "
                         "code or tool output. Rationale must be at most 360 characters "
                         "(not words or tokens); aim for one sentence under 180 characters. "
                         "Put citations in the ID arrays rather than repeating them in rationale."),
            )
        definitions = self.tools.definitions(allowed_tools)
        trace: list[ReActStep] = []
        model_ids: list[str] = []
        usage: ModelUsage | None = None
        model_calls = 0
        successful_observations = 0
        starting_observed_tokens = self.scope.observed_tokens

        for step_index in range(self.harness.max_steps):
            final_step = step_index == self.harness.max_steps - 1
            finalization_step = final_step or (
                self.harness.max_steps >= 3
                and step_index >= self.harness.max_steps - 2
            )
            if finalization_step:
                prefix = (
                    "This is the final model step in the fixed execution budget. "
                    if final_step
                    else "The tool-call budget is now closed for finalization. "
                )
                messages.append(ChatMessage(
                    role="user",
                    content=(prefix
                             + "No more tool calls are available. Return the final JSON schema "
                             "using only observed evidence. Do not fabricate validator results "
                             "or claim an unexecuted assigned task completed."
                             + (" If evidence is insufficient, return ABSTAIN with "
                                "validation_status UNRESOLVED."
                                if output_model is AgentExpertConclusion else "")),
                ))
            reply = self.model.complete(messages, () if finalization_step else definitions)
            model_calls += 1
            model_ids.append(reply.model_id)
            usage = reply.usage if usage is None else _merge_usage(usage, reply.usage)
            if reply.tool_calls:
                if finalization_step:
                    raise RuntimeError("Model requested tools during the finalization-only step")
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
                raw_output = parse_final_json(reply.content)
                output = output_model.model_validate(raw_output)
                if isinstance(output, AgentExpertConclusion):
                    validate_conclusion(
                        output, [*self.prior_trace, *trace], self.scope.initial_evidence_ids,
                        required_validators, current_trace=trace,
                        subject=self.scope.subject,
                    )
                if output_validator is not None:
                    output_validator(output)
            except (ValueError, ValidationError) as error:
                feedback = str(error)
                if isinstance(error, ValidationError) and output_model is AgentExpertConclusion:
                    for detail in error.errors():
                        if detail['loc'] == ('rationale',) and detail['type'] == 'string_too_long':
                            feedback = (
                                f"rationale has {len(detail['input'])} characters; "
                                "it must be at most 360 characters, not words or tokens. "
                                "Rewrite it as one sentence under 180 characters. "
                                "Keep the substantive judgment and evidence references; "
                                "do not change the label just to shorten the explanation. "
                                "All other schema and evidence checks still apply. "
                            ) + feedback
                            break
                messages.append(ChatMessage(role="assistant", content=reply.content))
                messages.append(
                    ChatMessage(
                        role="user",
                        content=(
                            "The previous final object failed schema or evidence validation. "
                            "Return corrected JSON only, or call an allowed tool if more "
                            "evidence is required and tool calls are still available. "
                            f"Validation error: {feedback}"
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
    def validate_identity(output: AgentExpertConclusion) -> None:
        if output.expert != expert:
            raise ValueError(
                f"expert output identity drifted: expected {expert}, got {output.expert}"
            )

    run = engine.run(
        system_prompt=(system_prompt + f"\nYour assigned expert identity is {expert}. "
                       f"The final JSON expert field must be {expert!r}."),
        task_prompt=task_prompt,
        allowed_tools=allowed_tools,
        output_model=AgentExpertConclusion,
        required_validators=required_validators,
        output_validator=validate_identity,
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
