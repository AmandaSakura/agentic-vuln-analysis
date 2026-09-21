"""Repository tools restricted to the admitted retrieval scope."""
from __future__ import annotations

from typing import cast

from pydantic import Field

from cv_agent.domain.evidence import ToolObservation
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import FrozenModel
from cv_agent.tools.registry import AgentTool, ToolExecutionScope


class SearchSymbolsInput(FrozenModel):
    query: str
    top_k: int = Field(default=8, ge=1, le=50)

class ReadSpanInput(FrozenModel):
    path: str

class GraphNeighborsInput(FrozenModel):
    path: str

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
