"""Scoped route, identity and authorization-guard inspection."""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Callable
from typing import Any, cast

from ..agent_tools import ToolExecutionScope
from ..agent_types import ToolObservation, ValidationStatus
from ..python_flow import function_node
from ..retrieval import RepositoryIndex
from ..types import CodeDocument, FrozenModel
from .dataflow import _symbol_matches_target
from .models import CompareGuardInput, PathInput
from .patterns import GUARD_PATTERN, PRINCIPAL_PATTERN, RESOURCE_PATTERN, SENSITIVE_ACTION_PATTERN
from .scope import _admitted_document, _json_content


def routes(
    index: RepositoryIndex,
    arguments: FrozenModel,
    scope: ToolExecutionScope,
) -> ToolObservation:
    value = cast(PathInput, arguments)
    document, error = _admitted_document(index, value.path, scope, "get_routes")
    if error is not None:
        return error
    item = cast(CodeDocument, document)
    inferred = sorted(
        {
            *item.routes,
            *(
                f"{match.group(1).upper()}:{match.group(2)}"
                for match in re.finditer(
                    r"\.(get|post|put|patch|delete)\(\s*['\"]([^'\"]*)['\"]",
                    item.text,
                    flags=re.IGNORECASE,
                )
            ),
        }
    )
    return ToolObservation(
        tool="get_routes",
        status="ok",
        content=_json_content({"path": value.path, "routes": inferred}),
        evidence_ids=(f"routes:{value.path}",),
    )


def guards(
    index: RepositoryIndex,
    arguments: FrozenModel,
    scope: ToolExecutionScope,
) -> ToolObservation:
    value = cast(PathInput, arguments)
    document, error = _admitted_document(index, value.path, scope, "get_guards")
    if error is not None:
        return error
    item = cast(CodeDocument, document)
    inferred = sorted(
        {
            *item.guards,
            *(match.group(0) for match in GUARD_PATTERN.finditer(item.text)),
        }
    )
    return ToolObservation(
        tool="get_guards",
        status="ok",
        content=_json_content({"guards": inferred, "path": value.path}),
        evidence_ids=(f"guards:{value.path}",),
    )


def semantic_matches(
    index: RepositoryIndex,
    tool_name: str,
    pattern: re.Pattern[str],
    key: str,
) -> Callable[[FrozenModel, ToolExecutionScope], ToolObservation]:
    def handle(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        value = cast(PathInput, arguments)
        document, error = _admitted_document(index, value.path, scope, tool_name)
        if error is not None:
            return error
        item = cast(CodeDocument, document)
        matches = sorted({match.group(0) for match in pattern.finditer(item.text)})
        return ToolObservation(
            tool=tool_name,
            status="ok",
            content=_json_content({key: matches, "path": value.path}),
            evidence_ids=(f"{tool_name}:{value.path}",),
        )

    return handle


def compare_guard(
    index: RepositoryIndex,
    arguments: FrozenModel,
    scope: ToolExecutionScope,
) -> ToolObservation:
    value = cast(CompareGuardInput, arguments)
    route, error = _admitted_document(
        index,
        value.route_path,
        scope,
        "compare_route_and_service_guard",
    )
    if error is not None:
        return error
    route_path = cast(CodeDocument, route).path
    queue: deque[tuple[str, tuple[str, ...]]] = deque(
        [(route_path, (route_path,))]
    )
    records_by_path: dict[str, dict[str, Any]] = {}
    sensitive_occurrences: list[tuple[tuple[str, ...], str, int]] = []
    while queue:
        path, graph_path = queue.popleft()
        distance = len(graph_path) - 1
        if distance > value.max_hops:
            continue
        document = index.document(path)
        if document is None:
            continue
        # Route decorators execute when defining the endpoint, not when a
        # request enters its body. Do not treat registration as a runtime sink.
        function = function_node(document)
        definition_lines = {
            line
            for decorator in (function.decorator_list if function is not None else ())
            for line in range(decorator.lineno, (decorator.end_lineno or decorator.lineno) + 1)
        }
        guard_lines = [
            line_number
            for line_number, line in enumerate(document.text.splitlines(), start=1)
            if GUARD_PATTERN.search(line)
        ]
        sensitive_lines = [
            line_number
            for line_number, line in enumerate(document.text.splitlines(), start=1)
            if line_number not in definition_lines and not re.match(
                r"^\s*(?:(?:async\s+)?def|function|func)\b",
                line,
            )
            and SENSITIVE_ACTION_PATTERN.search(line)
        ]
        records_by_path.setdefault(
            path,
            {
                "distance": distance,
                "guards": sorted(
                    {
                        *document.guards,
                        *(
                            match.group(0)
                            for match in GUARD_PATTERN.finditer(document.text)
                        ),
                    }
                ),
                "guard_lines": guard_lines,
                "path": path,
                "principals": sorted(
                    {
                        match.group(0)
                        for match in PRINCIPAL_PATTERN.finditer(document.text)
                    }
                ),
                "resources": sorted(
                    {
                        match.group(0)
                        for match in RESOURCE_PATTERN.finditer(document.text)
                    }
                ),
                "sensitive": bool(sensitive_lines),
                "sensitive_lines": sensitive_lines,
            },
        )
        sensitive_occurrences.extend(
            (graph_path, path, line) for line in sensitive_lines
        )
        for neighbor in index.graph_neighbors(path, direction="forward"):
            if neighbor in scope.admitted_paths and neighbor not in graph_path:
                queue.append((neighbor, (*graph_path, neighbor)))
    records = sorted(
        records_by_path.values(),
        key=lambda record: (record["distance"], record["path"]),
    )
    has_sensitive = any(record["sensitive"] for record in records)

    def edge_call_lines(caller_path: str, target_path: str) -> list[int]:
        caller = index.document(caller_path)
        target = index.document(target_path)
        if caller is None or target is None:
            return []
        final_names = {
            call.rsplit(".", 1)[-1]
            for call in caller.calls
            if _symbol_matches_target(call, target)
        }
        return [
            line_number
            for line_number, line in enumerate(caller.text.splitlines(), start=1)
            if any(
                re.search(rf"\b{re.escape(name)}\s*\(", line)
                for name in final_names
            )
        ]

    def occurrence_is_guarded(
        graph_path: tuple[str, ...],
        sensitive_path: str,
        sensitive_line: int,
    ) -> bool:
        for position, guard_path in enumerate(graph_path):
            record = records_by_path[guard_path]
            if guard_path == sensitive_path:
                if any(line < sensitive_line for line in record["guard_lines"]):
                    return True
                continue
            next_path = graph_path[position + 1]
            boundary = min(
                edge_call_lines(guard_path, next_path),
                default=None,
            )
            if boundary is not None and any(
                line < boundary for line in record["guard_lines"]
            ):
                return True
        return False

    guard_dominates = bool(
        sensitive_occurrences
        and all(
            occurrence_is_guarded(
                graph_path,
                sensitive_path,
                sensitive_line,
            )
            for graph_path, sensitive_path, sensitive_line in sensitive_occurrences
        )
    )
    if has_sensitive and not guard_dominates:
        status = ValidationStatus.UNRESOLVED
        interpretation = (
            "a sensitive-name pattern lacks a recognized preceding guard; "
            "authorization requirements and enforcement are not established"
        )
    elif has_sensitive and guard_dominates:
        status = ValidationStatus.UNRESOLVED
        interpretation = (
            "a guard precedes the sensitive action, but static presence alone does not "
            "prove principal and resource enforcement"
        )
    else:
        status = ValidationStatus.UNRESOLVED
        interpretation = "no sensitive authorization-relevant action was established"
    return ToolObservation(
        tool="compare_route_and_service_guard",
        status="ok",
        validation_status=status,
        content=_json_content(
            {
                "interpretation": interpretation,
                "recognized_guard_precedes_actions": guard_dominates,
                "records": records,
                "status": status,
            }
        ),
        evidence_ids=tuple(f"authz:{record['path']}" for record in records),
    )
