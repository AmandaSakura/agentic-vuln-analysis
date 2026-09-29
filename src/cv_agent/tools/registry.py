"""Tool registration, allowlists and shared observation budgets."""
from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import ValidationError

from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import (
    FixtureCapability,
    ToolObservation,
    ValidationStatus,
    ValidationSubject,
)
from cv_agent.retrieval import prompt_token_upper_bound as context_text_token_count, fit_text_to_serialized_context
from cv_agent.domain.types import FrozenModel


EXHAUSTED_OBSERVATION = (
    "no observation can be delivered: this task's tool-observation budget is spent. "
    "Finalize from the observations already visible; further calls cannot return content."
)


def _exhausted_content(content_type: str) -> str:
    """Answer an undeliverable call; JSON tools keep a parseable payload."""
    if content_type != "json":
        return EXHAUSTED_OBSERVATION
    return json.dumps(
        {
            "observation_truncated": True,
            "reason": "token_budget",
            "diagnostic": EXHAUSTED_OBSERVATION,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


@dataclass
class ToolExecutionScope:
    admitted_paths: frozenset[str]
    max_observation_tokens: int
    observed_tokens: int = 0
    initial_evidence_ids: frozenset[str] = frozenset()
    candidate_path: str | None = None
    subject: ValidationSubject | None = None
    # When a planned fixture substitutes mandatory checks, only its
    # qualified registered case may execute in that task.
    fixture_case_id: str | None = None
    # One scope is one expert task over one frozen index. Remember successful
    # producer execution separately from observation delivery; clipping cannot
    # authorize repeating it. Only the original citation is stored, never proof.
    answered_calls: dict[tuple[str, str], str | None] = field(default_factory=dict)
    budget_exhausted: bool = False

    def __post_init__(self) -> None:
        if self.max_observation_tokens < 1:
            raise ValueError("tool-observation token budget must be positive")
        if self.observed_tokens < 0 or self.observed_tokens > self.max_observation_tokens:
            raise ValueError("observed tool tokens must fit inside the scope budget")
        if self.subject is not None and self.candidate_path is not None and self.subject.entry_path != self.candidate_path:
            raise ValueError("validation subject entry must match the candidate path")

    @property
    def remaining_tokens(self) -> int:
        return self.max_observation_tokens - self.observed_tokens

@dataclass(frozen=True)
class AgentTool:
    name: str
    description: str
    input_model: type[FrozenModel]
    handler: Callable[[FrozenModel, ToolExecutionScope], ToolObservation]
    content_type: Literal["text", "json"] = "text"
    available: bool = True
    validation_statuses: tuple[ValidationStatus, ...] = ()
    fixture_capabilities: tuple[FixtureCapability, ...] = ()
    candidate_witness_supports: Callable[[ValidationSubject], bool] | None = None
    response_token_limit: Callable[[ToolExecutionScope], int | None] | None = None

    def definition(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.input_model.model_json_schema(),
            },
        }

class ToolRegistry:
    def __init__(
        self,
        tools: Iterable[AgentTool],
        *,
        max_output_bytes: int,
    ) -> None:
        registered = list(tools)
        self._tools = {tool.name: tool for tool in registered}
        if len(self._tools) != len(registered):
            raise ValueError("tool registry contains duplicate names")
        if (
            any(tool.content_type == "json" for tool in registered)
            and max_output_bytes < self._json_marker_byte_floor()
        ):
            raise ValueError(
                "json tool output budget cannot fit the required truncation marker"
            )
        self.max_output_bytes = max_output_bytes

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    @property
    def available_names(self) -> tuple[str, ...]:
        return tuple(sorted(name for name, tool in self._tools.items() if tool.available))

    @property
    def fixture_capabilities(self) -> tuple[FixtureCapability, ...]:
        caps: list[FixtureCapability] = []
        for tool in self._tools.values():
            caps.extend(tool.fixture_capabilities)
        return tuple(caps)

    def candidate_fixture_capabilities(
        self, subject: ValidationSubject | None
    ) -> tuple[FixtureCapability, ...]:
        if subject is None:
            return ()
        return tuple(
            cap
            for cap in self.fixture_capabilities
            if cap.subject == subject
            and cap.coverage == "candidate"
            and cap.method != "source_pattern"
            and (cap.property_id is None or cap.property_id == subject.property_id)
        )

    def candidate_witness_available(self, subject: ValidationSubject | None) -> bool:
        """Query system-owned source qualification; no model manifest is accepted."""
        tool = self._tools.get("run_bounded_execution_witness")
        return bool(subject is not None and tool is not None and tool.available
                    and tool.candidate_witness_supports is not None
                    and tool.candidate_witness_supports(subject))

    def definitions(self, allowed: Iterable[str]) -> tuple[dict[str, Any], ...]:
        allowed_names = tuple(allowed)
        missing = sorted(set(allowed_names) - set(self._tools))
        if missing:
            raise ValueError(f"allowed tools are not registered: {missing}")
        return tuple(self._tools[name].definition() for name in allowed_names)

    @staticmethod
    def _minimal_json_truncation(reason: str) -> str:
        return json.dumps(
            {
                "observation_truncated": True,
                "reason": reason,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def _json_marker_byte_floor(cls) -> int:
        return max(
            len(cls._minimal_json_truncation(reason).encode("utf-8"))
            for reason in ("byte_budget", "invalid_json", "token_budget")
        )

    @classmethod
    def _json_truncation(
        cls,
        reason: str,
        original_size: int,
        *,
        byte_budget: int | None = None,
    ) -> str:
        full = json.dumps(
            {
                "observation_truncated": True,
                "original_size": original_size,
                "reason": reason,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        if byte_budget is None or len(full.encode("utf-8")) <= byte_budget:
            return full
        minimal = cls._minimal_json_truncation(reason)
        if len(minimal.encode("utf-8")) <= byte_budget:
            return minimal
        raise ValueError("json truncation marker does not fit output byte budget")

    def _bounded(
        self,
        observation: ToolObservation,
        *,
        content_type: Literal["text", "json"],
    ) -> ToolObservation:
        encoded = observation.content.encode("utf-8")
        if len(encoded) <= self.max_output_bytes:
            return observation
        if content_type == "json" and observation.status == "ok":
            marker = self._json_truncation(
                "byte_budget",
                len(encoded),
                byte_budget=self.max_output_bytes,
            )
            return observation.model_copy(
                update={"content": marker, "status": "error"}
            )
        suffix = "\n[tool output truncated by Harness]"
        available = max(0, self.max_output_bytes - len(suffix.encode("utf-8")))
        content = encoded[:available].decode("utf-8", errors="ignore") + suffix
        return observation.model_copy(update={"content": content})

    def _finalize(
        self,
        observation: ToolObservation,
        scope: ToolExecutionScope,
        *,
        content_type: Literal["text", "json"] = "text",
        citation_id: str | None = None,
        response_token_limit: int | None = None,
    ) -> ToolObservation:
        if response_token_limit is None:
            registered = self._tools.get(observation.tool)
            if registered is not None and registered.response_token_limit is not None:
                response_token_limit = registered.response_token_limit(scope)
        if response_token_limit is not None and response_token_limit < 1:
            raise ValueError("tool response token limit must be positive")
        available_tokens = min(scope.remaining_tokens, response_token_limit) if response_token_limit is not None else scope.remaining_tokens
        observation = observation.model_copy(update={"citation_id": citation_id})
        effective_content_type = (
            content_type if observation.status == "ok" else "text"
        )
        bounded = self._bounded(
            observation,
            content_type=effective_content_type,
        )
        structural_truncation = (
            bounded.content != observation.content
            or bounded.status != observation.status
        )
        if structural_truncation or bounded.status != "ok":
            bounded = bounded.model_copy(update={"validation_status": None, "fixture_proof": None})
        if effective_content_type == "json":
            try:
                json.loads(bounded.content)
            except (json.JSONDecodeError, TypeError):
                bounded = bounded.model_copy(
                    update={
                        "content": self._json_truncation(
                            "invalid_json",
                            len(bounded.content.encode("utf-8")),
                            byte_budget=self.max_output_bytes,
                        ),
                        "status": "error",
                    }
                )
                structural_truncation = True
            payload = self._render_prompt_payload(
                bounded,
                content=bounded.content,
            )
            if context_text_token_count(payload) <= available_tokens:
                fitted = (
                    bounded.content,
                    payload,
                    context_text_token_count(payload),
                )
            else:
                marker = self._json_truncation(
                    "token_budget",
                    context_text_token_count(payload),
                    byte_budget=self.max_output_bytes,
                )
                truncated = bounded.model_copy(
                    update={"content": marker, "status": "error", "validation_status": None, "fixture_proof": None}
                )
                marker_payload = self._render_prompt_payload(
                    truncated,
                    content=marker,
                )
                marker_tokens = context_text_token_count(marker_payload)
                bounded = truncated
                structural_truncation = True
                fitted = (
                    (marker, marker_payload, marker_tokens)
                    if marker_tokens <= available_tokens
                    else None
                )
        else:
            fitted = fit_text_to_serialized_context(
                bounded.content,
                token_budget=available_tokens,
                render=lambda content: self._render_prompt_payload(
                    bounded,
                    content=content,
                ),
                count_tokens=context_text_token_count,
            )
        if fitted is None:
            # An empty tool message reads as "the tool returned nothing" and provokes
            # blind retries until the step budget ends. The diagnostic that explains the
            # limit must therefore survive the limit it reports: it is delivered and not
            # charged, because charging it is what suppressed it.
            scope.budget_exhausted = True
            return bounded.model_copy(
                update={
                    "status": (
                        "error" if effective_content_type == "json"
                        else "blocked" if bounded.status == "ok" else bounded.status
                    ),
                    "content": _exhausted_content(effective_content_type),
                    "metadata": {
                        **bounded.metadata,
                        "observation_token_count": 0,
                        "observation_truncated": True,
                        "model_payload_suppressed": False,
                    **({"response_token_limit": response_token_limit} if response_token_limit is not None else {}),
                        "budget_exhausted": True,
                    },
                }
            )
        content, _, token_count = fitted
        if bounded.status == "ok" and bounded.content and not content:
            scope.budget_exhausted = True
            return bounded.model_copy(
                update={
                    "status": "blocked",
                    "content": "",
                    "metadata": {
                        **bounded.metadata,
                        "observation_token_count": 0,
                        "observation_truncated": True,
                        "model_payload_suppressed": True,
                        "budget_exhausted": True,
                    },
                }
            )
        truncated = structural_truncation or content != bounded.content
        if truncated:
            bounded = bounded.model_copy(update={"validation_status": None, "fixture_proof": None})
        token_count = context_text_token_count(self._render_prompt_payload(bounded, content=content))
        scope.observed_tokens += token_count
        return bounded.model_copy(
            update={
                "content": content,
                "validation_status": None if truncated else bounded.validation_status,
                "fixture_proof": None if truncated else bounded.fixture_proof,
                "metadata": {
                    **bounded.metadata,
                    "observation_token_count": token_count,
                    "observation_truncated": truncated,
                    "model_payload_suppressed": False,
                    **({"response_token_limit": response_token_limit} if response_token_limit is not None else {}),
                },
            }
        )

    @staticmethod
    def _render_prompt_payload(
        observation: ToolObservation,
        *,
        content: str,
    ) -> str:
        return json.dumps(
            {
                "content": content,
                "status": observation.status,
                "tool": observation.tool,
                **({"citation_id": observation.citation_id} if observation.citation_id else {}),
                **(
                    {"validation_status": observation.validation_status.value}
                    if observation.validation_status is not None else {}
                ),
                **(
                    {"fixture_proof": observation.fixture_proof.model_dump(mode="json")}
                    if observation.fixture_proof is not None else {}
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def prompt_payload(self, observation: ToolObservation) -> str:
        if observation.metadata.get("model_payload_suppressed") is True:
            return ""
        return self._render_prompt_payload(
            observation,
            content=observation.content,
        )

    def refuse(
        self,
        call: ModelToolCall,
        scope: ToolExecutionScope,
        *,
        content: str,
        citation_id: str | None = None,
    ) -> ToolObservation:
        """Record a refusal so it is budgeted and rendered like any other observation."""
        return self._finalize(
            ToolObservation(tool=call.name, status="blocked", content=content),
            scope,
            citation_id=citation_id,
        )

    def invoke(
        self,
        call: ModelToolCall,
        *,
        allowed: Iterable[str],
        scope: ToolExecutionScope,
        citation_id: str | None = None,
    ) -> ToolObservation:
        allowed_names = set(allowed)
        if scope.remaining_tokens == 0:
            scope.budget_exhausted = True
            refusal = self.refuse(
                call, scope, content="observation budget exhausted", citation_id=citation_id
            )
            return refusal.model_copy(
                update={"metadata": {**refusal.metadata, "budget_exhausted": True}}
            )
        if call.name not in allowed_names:
            return self.refuse(
                call, scope, content="tool is outside this agent's Harness allowlist",
                citation_id=citation_id,
            )
        tool = self._tools.get(call.name)
        if tool is None:
            return self.refuse(
                call, scope, content="tool is not registered", citation_id=citation_id
            )
        if not tool.available:
            return self.refuse(
                call, scope, content="tool is unavailable for this run", citation_id=citation_id
            )
        try:
            arguments = tool.input_model.model_validate(call.arguments)
        except ValidationError as error:
            return self._finalize(
                ToolObservation(
                    tool=call.name,
                    status="error",
                    content=f"invalid tool arguments: {error}",
                ),
                scope,
                citation_id=citation_id,
            )
        if (
            call.name == "run_fixture_test"
            and scope.fixture_case_id is not None
            and arguments.model_dump(mode="json").get("case_id") != scope.fixture_case_id
        ):
            return self.refuse(
                call, scope,
                content="fixture case is outside this task's qualified case binding",
                citation_id=citation_id,
            )
        requested = (
            call.name,
            json.dumps(arguments.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
        )
        if requested in scope.answered_calls:
            previous = scope.answered_calls[requested]
            reference = f" as {previous}" if previous is not None else ""
            return self.refuse(
                call, scope, citation_id=citation_id,
                content=(
                    f"identical call already executed{reference} in this task; the Harness "
                    "does not repeat it. Reuse that observation or change the arguments. A "
                    "result that does not settle the question is this tool's limit for this "
                    "input, not a missing call."
                ),
            )
        try:
            observation = tool.handler(arguments, scope)
        except Exception as error:  # The typed boundary turns tool failures into observations.
            return self._finalize(
                ToolObservation(
                    tool=call.name,
                    status="error",
                    content=f"tool execution failed: {type(error).__name__}: {error}",
                ),
                scope,
                citation_id=citation_id,
            )
        if observation.tool != call.name:
            raise ValueError(
                f"tool handler returned observation for {observation.tool}, expected {call.name}"
            )
        if observation.status == "ok" or observation.metadata.get("producer_completed") is True:
            scope.answered_calls[requested] = citation_id
        return self._finalize(
            observation,
            scope,
            content_type=tool.content_type,
            citation_id=citation_id,
        )
