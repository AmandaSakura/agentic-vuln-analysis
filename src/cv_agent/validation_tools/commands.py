"""Admitted command-construction analysis adapter."""

from __future__ import annotations

from typing import Any, cast

from ..agent_tools import ToolExecutionScope
from ..agent_types import ToolObservation, ValidationStatus
from ..command_analysis import analyze_command, command_status, returned_command, shell_status
from ..retrieval import RepositoryIndex
from ..types import CodeDocument, FrozenModel
from .models import CommandConstructionInput
from .scope import _admitted_document, _json_content


def command_construction(
    index: RepositoryIndex,
    arguments: FrozenModel,
    scope: ToolExecutionScope,
) -> ToolObservation:
    value = cast(CommandConstructionInput, arguments)
    if scope.candidate_path is not None and value.source_path != scope.candidate_path:
        return ToolObservation(
            tool="inspect_command_construction",
            status="blocked",
            content="command construction inspection must start at the candidate entry",
        )
    source, error = _admitted_document(
        index,
        value.source_path,
        scope,
        "inspect_command_construction",
    )
    if error is not None:
        return error
    source_document = cast(CodeDocument, source)
    helper_paths = [
        path for path in index.graph_neighbors(value.source_path, direction="forward")
        if path in scope.admitted_paths
        and (document := index.document(path)) is not None
        and any(definition.rsplit(".", 1)[-1] == "get_cmd" for definition in document.defines)
    ]
    unresolved_edges: list[dict[str, str]] = []
    helper_facts: list[dict[str, Any]] = []
    for path in sorted(helper_paths):
        helper = index.document(path)
        if helper is None:
            continue
        analysis = analyze_command(helper)
        if analysis.issues:
            unresolved_edges.append({"from": value.source_path, "to": path})
        helper_facts.append(
            {
                "return_line": analysis.return_line,
                "path": path,
                "status": shell_status(returned_command(analysis)),
                "issues": analysis.issues,
                "scope": "helper return value only; caller transformations must still be checked",
            }
        )
    admitted_helpers = tuple(
        helper for path in helper_paths
        if (helper := index.document(path)) is not None
    ) if value.max_hops > 0 else ()
    entry_arguments = scope.subject.entry_boolean_arguments if scope.subject is not None else {}
    source_analysis = analyze_command(source_document, admitted_helpers, entry_boolean_arguments=entry_arguments)
    construction_status = command_status(source_analysis)
    if not admitted_helpers and "get_cmd" in source_document.text and source_analysis.issues:
        construction_status = "UNAVAILABLE"
    summary = {
        "SANITIZED": "supported caller paths pass a command with protected argument interpolation to a POSIX shell",
        "UNSANITIZED": "a supported caller path passes raw parameter interpolation to a POSIX shell",
        "UNAVAILABLE": "the candidate calls get_cmd but no admitted callee was available within the hop budget",
        "NOT_ESTABLISHED": "no supported shell execution was established on the inspected path",
        "AMBIGUOUS": "command binding, execution path or shell context is outside supported semantics",
    }[construction_status]
    return ToolObservation(
        tool="inspect_command_construction",
        status="ok",
        validation_status=ValidationStatus.UNRESOLVED,
        content=_json_content(
            {
                "command_construction_status": construction_status,
                "entry_boolean_arguments": entry_arguments,
                "helpers": helper_facts,
                "source_path": value.source_path,
                "status": ValidationStatus.UNRESOLVED,
                "summary": summary,
                "unresolved_edges": unresolved_edges,
                "sink_facts": source_analysis.sinks,
                "issues": source_analysis.issues,
                "unresolved_calls": source_analysis.unresolved_calls,
            }
        ),
        evidence_ids=(
            f"command_construction:{value.source_path}",
            *(f"command_helper:{path}" for path in sorted(helper_paths)),
        ),
    )
