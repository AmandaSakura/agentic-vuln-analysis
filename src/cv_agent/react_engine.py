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
    ToolObservation,
    ValidationPlan,
    ValidationStatus,
    ValidationSubject,
)
from .harness import ExpertName, ReActLoopHarness
from .model_runtime import ChatModel, trusted_runtime_mode


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


def validate_conclusion(
    output: AgentExpertConclusion, trace: list[ReActStep],
    initial_evidence_ids: frozenset[str], required_validators: tuple[str, ...] = (),
    current_trace: list[ReActStep] | None = None,
    subject: ValidationSubject | None = None,
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
    referenced_ids = {
        *output.evidence_ids,
        *output.supporting_observation_ids,
        *output.counter_observation_ids,
        *output.unresolved_observation_ids,
    }
    if referenced_ids - known:
        available = sorted(item.citation_id for item in observations if item.citation_id)
        raise ValueError(
            f"Unknown evidence reference: {', '.join(sorted(referenced_ids - known))}. "
            f"Available tool citations: {', '.join(available) or 'none'}. "
            "Use only a listed successful tool citation or retrieved evidence ID. "
            "Blocked/error calls are not evidence. Remove an unsupported reference "
            "from every citation array; do not invent a replacement."
        )
    if output.label != "ABSTAIN" and not output.evidence_ids:
        raise ValueError("A material prediction must cite observed evidence.")
    executed = Counter(
        step.observation.tool for step in (current_trace if current_trace is not None else trace)
        if step.observation.status == "ok"
        and not step.observation.metadata.get("observation_truncated")
    )
    if Counter(required_validators) - executed:
        raise ValueError("Assigned validation tools must complete before finalizing the expert tasks.")
    concrete_labels = {
        'VULNERABLE' if item.validation_status == ValidationStatus.CONFIRMED else 'SAFE'
        for item in observations
        if subject is not None and item.subject == subject
        and not item.metadata.get('observation_truncated')
        and item.validation_status in {ValidationStatus.CONFIRMED, ValidationStatus.REFUTED}
    }
    if output.label != 'ABSTAIN' and concrete_labels - {output.label}:
        raise ValueError('Prediction contradicts concrete validator evidence for this candidate and scope; resolve the conflict or abstain.')
    if output.label == "VULNERABLE" and _contradicts_observed_command_evidence(
        output, observations
    ):
        raise ValueError(
            "Prediction contradicts observed command-construction counter-evidence; "
            "cite supporting command construction evidence, resolve the conflict, or abstain."
        )
    if output.label == "VULNERABLE" and _relies_on_unestablished_taint_without_command_support(
        output, observations
    ):
        raise ValueError(
            "A NOT_ESTABLISHED taint trace and sink listings do not support a "
            "VULNERABLE prediction; inspect command construction evidence or abstain."
        )
    if output.label != "ABSTAIN" and _relies_on_static_permission_without_validator(
        output, observations
    ):
        raise ValueError(
            "Static chmod mode matching does not support a material permission prediction; "
            "cite validate_permission_mode evidence or abstain."
        )
    if output.label != "ABSTAIN" and _relies_on_static_command_without_inspection(
        output, observations
    ):
        raise ValueError(
            "Static command-execution sink matching does not support a material "
            "prediction; cite inspect_command_construction evidence or abstain."
        )
    if (
        output.label == "SAFE"
        and output.validation_status == ValidationStatus.UNRESOLVED
        and _safe_prediction_lacks_affirmative_evidence(output, observations, subject)
    ):
        raise ValueError(
            "SAFE/UNRESOLVED requires affirmative counter-evidence; empty searches, "
            "missing graph neighbors, static no-finding results, or source reads alone "
            "must be reported as ABSTAIN/UNRESOLVED. "
            "Evidence supporting SAFE belongs in supporting_observation_ids, not "
            "counter_observation_ids or unresolved_observation_ids. Counter means "
            "against your predicted label, not against the vulnerability hypothesis."
        )
    if output.validation_status == ValidationStatus.UNRESOLVED:
        return
    expected = {
        ValidationStatus.CONFIRMED: "VULNERABLE", ValidationStatus.REFUTED: "SAFE",
    }[output.validation_status]
    if output.label != expected:
        raise ValueError("Validation status contradicts the prediction label.")
    missing_bibliography = [
        item.citation_id for item in _supporting_observations(output, observations)
        if item.citation_id and subject is not None and item.subject == subject
        and not item.metadata.get("observation_truncated")
        and item.validation_status == output.validation_status
        and not set(output.evidence_ids) & {*item.evidence_ids, item.citation_id}
    ]
    referenced = [
        item for item in _supporting_observations(output, observations)
        if not item.metadata.get("observation_truncated")
        and set(output.evidence_ids) & {*item.evidence_ids, item.citation_id}
        and item.validation_status not in {None, ValidationStatus.UNRESOLVED}
    ]
    if not referenced or any(item.validation_status != output.validation_status for item in referenced):
        if not referenced and missing_bibliography:
            raise ValueError(
                "CONFIRMED/REFUTED requires matching cited validator output in evidence_ids. "
                "These matching validator citations appear in supporting_observation_ids "
                "but are missing from evidence_ids: " + ", ".join(missing_bibliography)
                + ". Include the supporting validator citation in evidence_ids too; "
                "a local source reference alone is not a validator citation."
            )
        raise ValueError(
            "CONFIRMED/REFUTED requires matching cited validator output; "
            "reading code alone only supports validation_status=UNRESOLVED."
        )
    if subject is None or any(item.subject != subject for item in referenced):
        raise ValueError("Confirmed/refuted evidence subject must match this candidate and source snapshot")


def _json_object(content: str) -> dict | None:
    try:
        value = json.loads(content)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _supporting_observations(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
) -> list[ToolObservation]:
    # evidence_ids is a general bibliography; explicit counter/undecided roles
    # must not silently become support for the proposed label.
    supporting = {*output.evidence_ids, *output.supporting_observation_ids}
    other_roles = {*output.counter_observation_ids, *output.unresolved_observation_ids}
    return [item for item in observations
            if supporting & {*item.evidence_ids, item.citation_id}
            and not other_roles & {*item.evidence_ids, item.citation_id}]


def _has_affirmative_safe_evidence(
    observation: ToolObservation, subject: ValidationSubject | None,
) -> bool:
    if observation.metadata.get("observation_truncated"):
        return False
    if observation.subject is not None and observation.subject != subject:
        return False
    if observation.validation_status == ValidationStatus.REFUTED:
        return subject is not None and observation.subject == subject
    if observation.validation_status == ValidationStatus.CONFIRMED:
        return False
    content = _json_object(observation.content)
    if content is None:
        return False
    # These signals support a safety hypothesis, never typed refutation. Search
    # hits, potential sinks, inconclusive probes and another revision's repair
    # provide no affirmative counter-evidence for the current snapshot.
    if observation.tool == "get_guards":
        return bool(content.get("guards"))
    if observation.tool == "find_sanitizers":
        return bool(content.get("findings"))
    if observation.tool == "compare_route_and_service_guard":
        return content.get("recognized_guard_precedes_actions") is True
    if observation.tool == "inspect_command_construction":
        return content.get("command_construction_status") == "SANITIZED"
    return False


def _safe_prediction_lacks_affirmative_evidence(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
    subject: ValidationSubject | None,
) -> bool:
    referenced = _supporting_observations(output, observations)
    return not any(_has_affirmative_safe_evidence(item, subject) for item in referenced)


def _command_status(observation: ToolObservation) -> str | None:
    if observation.metadata.get("observation_truncated"):
        return None
    if observation.tool != "inspect_command_construction":
        return None
    content = _json_object(observation.content)
    if content is None:
        return None
    status = content.get("command_construction_status")
    return status if isinstance(status, str) else None


def _contradicts_observed_command_evidence(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
) -> bool:
    referenced = _supporting_observations(output, observations)
    if any(_command_status(observation) == "UNSANITIZED" for observation in referenced):
        return False
    return any(_command_status(observation) == "SANITIZED" for observation in referenced)


def _relies_on_unestablished_taint_without_command_support(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
) -> bool:
    referenced = _supporting_observations(output, observations)
    if any(_command_status(observation) == "UNSANITIZED" for observation in referenced):
        return False
    for observation in referenced:
        if observation.tool != "trace_dataflow":
            continue
        content = _json_object(observation.content)
        if content is not None and content.get("flow_status") == "NOT_ESTABLISHED":
            return True
    return False


def _relies_on_static_permission_without_validator(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
) -> bool:
    referenced = _supporting_observations(output, observations)
    cites_permission_static = False
    cites_permission_validator = False
    for observation in referenced:
        content = _json_object(observation.content)
        if content is None:
            continue
        if observation.tool == "run_static_check" and "permission_mode_check" in content:
            cites_permission_static = True
        if (
            observation.tool == "validate_permission_mode"
            and observation.validation_status in {
                ValidationStatus.CONFIRMED,
                ValidationStatus.REFUTED,
            }
        ):
            cites_permission_validator = True
    return cites_permission_static and not cites_permission_validator


def _relies_on_static_command_without_inspection(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
) -> bool:
    referenced = _supporting_observations(output, observations)
    cites_static_command = False
    cites_command_inspection = False
    observed_get_cmd = False
    for observation in referenced:
        if "get_cmd" in observation.content:
            observed_get_cmd = True
        content = _json_object(observation.content)
        if content is None:
            continue
        if observation.tool == "run_static_check":
            findings = content.get("findings")
            if isinstance(findings, list) and any(
                isinstance(item, dict)
                and item.get("category") == "command-execution"
                for item in findings
            ):
                cites_static_command = True
        if observation.tool == "inspect_command_construction" and _command_status(
            observation
        ) in {"SANITIZED", "UNSANITIZED"}:
            cites_command_inspection = True
    return cites_static_command and observed_get_cmd and not cites_command_inspection


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
