from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, cast

from pydantic import Field, ValidationError

from .agent_types import ModelToolCall, ToolObservation
from .retrieval import RepositoryIndex, fit_text_to_serialized_context
from .types import FrozenModel


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

    def __post_init__(self) -> None:
        if self.max_observation_tokens < 1:
            raise ValueError("tool-observation token budget must be positive")
        if self.observed_tokens < 0 or self.observed_tokens > self.max_observation_tokens:
            raise ValueError("observed tool tokens must fit inside the scope budget")

    @property
    def remaining_tokens(self) -> int:
        return self.max_observation_tokens - self.observed_tokens


@dataclass(frozen=True)
class AgentTool:
    name: str
    description: str
    input_model: type[FrozenModel]
    handler: Callable[[FrozenModel, ToolExecutionScope], ToolObservation]

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
        self.max_output_bytes = max_output_bytes

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def definitions(self, allowed: Iterable[str]) -> tuple[dict[str, Any], ...]:
        allowed_names = tuple(allowed)
        missing = sorted(set(allowed_names) - set(self._tools))
        if missing:
            raise ValueError(f"allowed tools are not registered: {missing}")
        return tuple(self._tools[name].definition() for name in allowed_names)

    def _bounded(self, observation: ToolObservation) -> ToolObservation:
        encoded = observation.content.encode("utf-8")
        if len(encoded) <= self.max_output_bytes:
            return observation
        suffix = "\n[tool output truncated by Harness]"
        available = max(0, self.max_output_bytes - len(suffix.encode("utf-8")))
        content = encoded[:available].decode("utf-8", errors="ignore") + suffix
        return observation.model_copy(update={"content": content})

    def _finalize(
        self,
        observation: ToolObservation,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        bounded = self._bounded(observation)
        fitted = fit_text_to_serialized_context(
            bounded.content,
            token_budget=scope.remaining_tokens,
            render=lambda content: self._render_prompt_payload(
                bounded,
                content=content,
            ),
        )
        if fitted is None:
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
        truncated = content != bounded.content
        scope.observed_tokens += token_count
        return bounded.model_copy(
            update={
                "content": content,
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
    ) -> ToolObservation:
        allowed_names = set(allowed)
        if call.name not in allowed_names:
            return self._finalize(
                ToolObservation(
                    tool=call.name,
                    status="blocked",
                    content="tool is outside this agent's Harness allowlist",
                ),
                scope,
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
            )
        if observation.tool != call.name:
            raise ValueError(
                f"tool handler returned observation for {observation.tool}, expected {call.name}"
            )
        return self._finalize(observation, scope)


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
                "path": document.path,
                "defines": list(document.defines),
                "calls": list(document.calls),
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
