"""Admitted command-construction analysis adapter."""

from __future__ import annotations

from typing import Any, cast

from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.identity import repository_source_digest, local_source_line
from cv_agent.domain.evidence import ToolObservation, ValidationStatus
from cv_agent.tools.analysis.commands import analyze_command, command_status, returned_command, shell_status
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import CodeDocument, FrozenModel
from cv_agent.tools.validation.models import CommandConstructionInput
from cv_agent.tools.validation.scope import _admitted_document, _json_content


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
    line_count = len(source_document.text.splitlines())
    subject_line = local_source_line(value.source_path, scope.subject.entry_line) if scope.subject else None
    if scope.subject is not None and (
        scope.subject.source_digest != repository_source_digest(index)
        or scope.subject.repository_id != source_document.repository_id
        or scope.subject.entry_path != value.source_path
        or subject_line is not None and not 1 <= subject_line <= line_count
    ):
        return ToolObservation(
            tool="inspect_command_construction", status="blocked",
            content="validation subject does not match the indexed candidate and source snapshot",
        )
    # Traverse admitted forward edges breadth-first: the hop budget limits
    # source availability, not evidence of execution. The interpreter still
    # resolves bindings and executes the supported caller paths.
    helpers_by_path: dict[str, CodeDocument] = {}
    helper_parents: dict[str, str] = {}
    visited = {value.source_path}
    frontier = [source_document]
    for _ in range(value.max_hops):
        next_frontier = []
        for caller in frontier:
            called_symbols = {call.rsplit(".", 1)[-1] for call in caller.calls}
            for path in sorted(index.graph_neighbors(caller.path, direction="forward")):
                if path in visited or path not in scope.admitted_paths:
                    continue
                helper = index.document(path)
                if helper is None:
                    continue
                if called_symbols and not any(
                    definition.rsplit(".", 1)[-1] in called_symbols
                    or definition.rsplit(".", 1)[-1] == "get_cmd"
                    for definition in helper.defines
                ):
                    continue
                visited.add(path)
                helpers_by_path[path] = helper
                helper_parents[path] = caller.path
                next_frontier.append(helper)
        frontier = next_frontier
        if not frontier:
            break
    helper_paths = sorted(helpers_by_path)
    admitted_helpers = tuple(
        helper for path in helper_paths
        if (helper := index.document(path)) is not None
    )
    entry_arguments = scope.subject.entry_boolean_arguments if scope.subject is not None else {}
    condition_assumptions = (
        scope.subject.entry_condition_assumptions if scope.subject is not None else {}
    )
    value_assumptions = (
        scope.subject.entry_value_assumptions if scope.subject is not None else {}
    )
    source_analysis = analyze_command(
        source_document, admitted_helpers, entry_boolean_arguments=entry_arguments,
        entry_condition_assumptions=condition_assumptions,
        entry_value_assumptions=value_assumptions,
        input_parameters=scope.subject.input_parameters if scope.subject is not None else None,
    )
    unresolved_edges: list[dict[str, str]] = []
    helper_facts: list[dict[str, Any]] = []
    diagnostic_paths = sorted(set(source_analysis.inspected_helpers))
    for path in diagnostic_paths:
        helper = index.document(path)
        if helper is None:
            continue
        analysis = analyze_command(helper)
        if analysis.issues:
            unresolved_edges.append({"from": helper_parents[path], "to": path})
        helper_facts.append(
            {
                "return_line": analysis.return_line,
                "path": path,
                "status": shell_status(returned_command(analysis)),
                "issues": analysis.issues,
                "scope": "helper return value only; caller transformations must still be checked",
            }
        )
    # Definition availability explains a possible next retrieval action;
    # it does not prove that a same-named definition is the runtime callee.
    analysis_gaps = []
    for call in source_analysis.unresolved_calls:
        matches = [document for document in index.documents.values()
                   if call["call"] in document.defines]
        if not matches:
            kind = "unmodeled_call"
        elif not any(document.path in scope.admitted_paths for document in matches):
            kind = "definition_not_admitted"
        elif not any(document.path in helpers_by_path for document in matches):
            kind = "available_definition_not_expanded"
        else:
            kind = "unresolved_binding"
        gap = {"kind": kind, **call}
        if gap not in analysis_gaps:
            analysis_gaps.append(gap)
    construction_status = command_status(source_analysis)
    # Missing callee identity is a direct signal; do not infer availability
    # from unrelated interpreter issues.
    if not admitted_helpers and (source_analysis.unresolved_calls or "get_cmd" in source_document.text):
        construction_status = "UNAVAILABLE"
    summary = {
        "SANITIZED": "supported caller paths pass a command with protected argument interpolation to a POSIX shell",
        "UNSANITIZED": "a supported caller path passes raw parameter interpolation to a POSIX shell",
        "UNAVAILABLE": "the candidate calls a command-construction helper but no admitted callee was available within the hop budget",
        "NOT_ESTABLISHED": "no supported shell execution was established on the inspected path",
        "AMBIGUOUS": "command binding, execution path or shell context is outside supported semantics",
    }[construction_status]
    return ToolObservation(
        tool="inspect_command_construction",
        subject=scope.subject if scope.subject is not None and scope.subject.property_id == "command-execution" else None,
        status="ok",
        validation_status=ValidationStatus.UNRESOLVED,
        content=_json_content(
            {
                "property_id": "command-execution",
                "command_construction_status": construction_status,
                "entry_boolean_arguments": entry_arguments,
                "entry_condition_assumptions": condition_assumptions,
                "entry_value_assumptions": value_assumptions,
                "input_parameters": scope.subject.input_parameters if scope.subject is not None else None,
                "helpers": helper_facts,
                "source_path": value.source_path,
                "source_line_count": line_count,
                "function_header_lines": source_analysis.function_header_lines,
                "status": ValidationStatus.UNRESOLVED,
                "summary": summary,
                "unresolved_edges": unresolved_edges,
                "sink_facts": source_analysis.sinks,
                "issues": source_analysis.issues,
                "analysis_gaps": analysis_gaps,
                "unresolved_calls": source_analysis.unresolved_calls,
            }
        ),
        evidence_ids=(
            f"command_construction:{value.source_path}",
            *(f"command_helper:{path}" for path in diagnostic_paths),
        ),
    )
