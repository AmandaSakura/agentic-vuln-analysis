from __future__ import annotations

import json
import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Literal, cast

from pydantic import Field, ValidationError

from .agent_types import ModelToolCall, ToolObservation, ValidationSubject, ValidationStatus
from .retrieval import (
    RepositoryIndex,
    prompt_token_upper_bound as context_text_token_count,
    fit_text_to_serialized_context,
)
from .types import FrozenModel, Candidate


class SearchSymbolsInput(FrozenModel):
    query: str
    top_k: int = Field(default=8, ge=1, le=50)


class ReadSpanInput(FrozenModel):
    path: str


class GraphNeighborsInput(FrozenModel):
    path: str


@dataclass
class ToolExecutionScope:
    admitted_paths: frozenset[str]
    max_observation_tokens: int
    observed_tokens: int = 0
    initial_evidence_ids: frozenset[str] = frozenset()
    candidate_path: str | None = None
    subject: ValidationSubject | None = None

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


def repository_source_digest(index: RepositoryIndex) -> str:
    return hashlib.sha256(json.dumps(
        [index.documents[path].model_dump(mode="json") for path in sorted(index.documents)],
        sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()


def candidate_subject(index: RepositoryIndex, candidate: Candidate) -> ValidationSubject:
    """One identity constructor shared by the pipeline and registered fixtures."""
    return ValidationSubject(candidate_id=candidate.candidate_id, repository_id=candidate.repository_id,
                             entry_path=candidate.path, source_digest=repository_source_digest(index),
                             entry_line=candidate.line,
                             input_parameters=candidate.input_parameters,
                             entry_boolean_arguments=candidate.entry_boolean_arguments,
                             analysis_scope=candidate.analysis_scope)


@dataclass(frozen=True)
class AgentTool:
    name: str
    description: str
    input_model: type[FrozenModel]
    handler: Callable[[FrozenModel, ToolExecutionScope], ToolObservation]
    content_type: Literal["text", "json"] = "text"
    available: bool = True
    validation_statuses: tuple[ValidationStatus, ...] = ()

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
    ) -> ToolObservation:
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
            bounded = bounded.model_copy(update={"validation_status": None})
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
            if context_text_token_count(payload) <= scope.remaining_tokens:
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
                    update={"content": marker, "status": "error", "validation_status": None}
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
                    if marker_tokens <= scope.remaining_tokens
                    else None
                )
        else:
            fitted = fit_text_to_serialized_context(
                bounded.content,
                token_budget=scope.remaining_tokens,
                render=lambda content: self._render_prompt_payload(
                    bounded,
                    content=content,
                ),
                count_tokens=context_text_token_count,
            )
        if fitted is None:
            if effective_content_type == "json":
                return bounded.model_copy(
                    update={
                        "status": "error",
                        "metadata": {
                            **bounded.metadata,
                            "observation_token_count": 0,
                            "observation_truncated": True,
                            "model_payload_suppressed": True,
                        },
                    }
                )
            return bounded.model_copy(
                update={
                    "status": "blocked" if bounded.status == "ok" else bounded.status,
                    "content": "",
                    "metadata": {
                        **bounded.metadata,
                        "observation_token_count": 0,
                        "observation_truncated": bool(bounded.content),
                        "model_payload_suppressed": True,
                    },
                }
            )
        content, _, token_count = fitted
        if bounded.status == "ok" and bounded.content and not content:
            return bounded.model_copy(
                update={
                    "status": "blocked",
                    "content": "",
                    "metadata": {
                        **bounded.metadata,
                        "observation_token_count": 0,
                        "observation_truncated": True,
                        "model_payload_suppressed": True,
                    },
                }
            )
        truncated = structural_truncation or content != bounded.content
        if truncated:
            bounded = bounded.model_copy(update={"validation_status": None})
        token_count = context_text_token_count(self._render_prompt_payload(bounded, content=content))
        scope.observed_tokens += token_count
        return bounded.model_copy(
            update={
                "content": content,
                "validation_status": None if truncated else bounded.validation_status,
                "metadata": {
                    **bounded.metadata,
                    "observation_token_count": token_count,
                    "observation_truncated": truncated,
                    "model_payload_suppressed": False,
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
            return self._finalize(
                ToolObservation(tool=call.name, status="blocked", content="observation budget exhausted"),
                scope, citation_id=citation_id,
            )
        if call.name not in allowed_names:
            return self._finalize(
                ToolObservation(
                    tool=call.name,
                    status="blocked",
                    content="tool is outside this agent's Harness allowlist",
                ),
                scope,
                citation_id=citation_id,
            )
        tool = self._tools.get(call.name)
        if tool is None:
            return self._finalize(
                ToolObservation(
                    tool=call.name,
                    status="blocked",
                    content="tool is not registered",
                ),
                scope,
                citation_id=citation_id,
            )
        if not tool.available:
            return self._finalize(
                ToolObservation(
                    tool=call.name,
                    status="blocked",
                    content="tool is unavailable for this run",
                ),
                scope,
                citation_id=citation_id,
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
        return self._finalize(
            observation,
            scope,
            content_type=tool.content_type,
            citation_id=citation_id,
        )


def repository_tools(index: RepositoryIndex) -> tuple[AgentTool, ...]:
    def search(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        value = cast(SearchSymbolsInput, arguments)
        evidence = index.text_search(
            value.query,
            top_k=min(value.top_k, len(scope.admitted_paths)),
            allowed_paths=scope.admitted_paths,
        )
        return ToolObservation(
            tool="search_symbols",
            status="ok",
            content="\n\n".join(
                f"[{item.path}] score={item.score:.4f}\n{item.text}"
                for item in evidence
            )
            or "no matching symbols",
            evidence_ids=tuple(item.evidence_id for item in evidence),
            metadata={"result_count": len(evidence)},
        )

    def read(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        value = cast(ReadSpanInput, arguments)
        if value.path not in scope.admitted_paths:
            return ToolObservation(
                tool="read_span",
                status="blocked",
                content=f"code span is outside the retrieved execution scope: {value.path}",
            )
        document = index.document(value.path)
        if document is None:
            return ToolObservation(
                tool="read_span",
                status="error",
                content=f"code span not found: {value.path}",
            )
        return ToolObservation(
            tool="read_span",
            status="ok",
            content=document.text,
            evidence_ids=(f"span:{document.path}",),
            metadata={
                "adapter_tier": document.adapter_tier,
                "language": document.language,
                "path": document.path,
                "defines": list(document.defines),
                "calls": list(document.calls),
                "imports": list(document.imports),
                "routes": list(document.routes),
                "guards": list(document.guards),
            },
        )

    def callees(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        value = cast(GraphNeighborsInput, arguments)
        if value.path not in scope.admitted_paths:
            return ToolObservation(
                tool="get_callees",
                status="blocked",
                content=f"graph seed is outside the retrieved execution scope: {value.path}",
            )
        paths = tuple(
            path
            for path in index.graph_neighbors(value.path, direction="forward")
            if path in scope.admitted_paths
        )
        return ToolObservation(
            tool="get_callees",
            status="ok",
            content="\n".join(paths) or "no resolved callees",
            evidence_ids=tuple(f"callee:{path}" for path in paths),
            metadata={"result_count": len(paths)},
        )

    def callers(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        value = cast(GraphNeighborsInput, arguments)
        if value.path not in scope.admitted_paths:
            return ToolObservation(
                tool="get_callers",
                status="blocked",
                content=f"graph seed is outside the retrieved execution scope: {value.path}",
            )
        paths = tuple(
            path
            for path in index.graph_neighbors(value.path, direction="reverse")
            if path in scope.admitted_paths
        )
        return ToolObservation(
            tool="get_callers",
            status="ok",
            content="\n".join(paths) or "no resolved callers",
            evidence_ids=tuple(f"caller:{path}" for path in paths),
            metadata={"result_count": len(paths)},
        )

    return (
        AgentTool(
            name="search_symbols",
            description="Search repository code spans using deterministic lexical ranking.",
            input_model=SearchSymbolsInput,
            handler=search,
        ),
        AgentTool(
            name="read_span",
            description="Read one exact indexed code span by path.",
            input_model=ReadSpanInput,
            handler=read,
        ),
        AgentTool(
            name="get_callees",
            description="List resolved one-hop forward callees for an indexed code span.",
            input_model=GraphNeighborsInput,
            handler=callees,
        ),
        AgentTool(
            name="get_callers",
            description="List resolved one-hop reverse callers for an indexed code span.",
            input_model=GraphNeighborsInput,
            handler=callers,
        ),
    )
