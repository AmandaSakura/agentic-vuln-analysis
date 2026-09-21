"""Shared admission checks and observation serialization."""

from __future__ import annotations

import json

from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.domain.evidence import ToolObservation
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import CodeDocument


def _json_content(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _admitted_document(
    index: RepositoryIndex,
    path: str,
    scope: ToolExecutionScope,
    tool: str,
) -> tuple[CodeDocument | None, ToolObservation | None]:
    if path not in scope.admitted_paths:
        return None, ToolObservation(
            tool=tool,
            status="blocked",
            content=f"path is outside the retrieved execution scope: {path}",
        )
    document = index.document(path)
    if document is None:
        return None, ToolObservation(
            tool=tool,
            status="error",
            content=f"indexed document not found: {path}",
        )
    return document, None


def _scope_documents(
    index: RepositoryIndex,
    scope: ToolExecutionScope,
) -> list[CodeDocument]:
    return [
        document
        for path in sorted(scope.admitted_paths)
        if (document := index.document(path)) is not None
    ]
