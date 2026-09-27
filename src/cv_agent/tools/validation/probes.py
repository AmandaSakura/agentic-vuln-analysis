"""Candidate-bound concrete Python eval probe adapter."""

from __future__ import annotations

from typing import cast

from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.identity import repository_source_digest, local_source_line
from cv_agent.domain.evidence import ToolObservation, ValidationStatus
from cv_agent.tools.analysis.python_probe import probe_python_eval
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import CodeDocument, FrozenModel
from cv_agent.tools.validation.models import SourceFlowInput
from cv_agent.tools.validation.scope import _admitted_document, _json_content


def concrete_eval_probe(index: RepositoryIndex, arguments: FrozenModel, scope: ToolExecutionScope) -> ToolObservation:
    value = cast(SourceFlowInput, arguments)
    if scope.subject is not None and scope.subject.source_digest != repository_source_digest(index):
        return ToolObservation(tool='probe_python_eval', status='blocked',
                               content='Probe index source does not match the candidate subject')
    if scope.candidate_path is not None and value.source_path != scope.candidate_path:
        return ToolObservation(
            tool="probe_python_eval", status="blocked",
            content=("The request-injection probe must start at the candidate entry "
                     f"{scope.candidate_path}; probing a retrieved helper directly "
                     "would bypass the candidate's argument bindings and guards."),
        )
    document, error = _admitted_document(index, value.source_path, scope, "probe_python_eval")
    if error is not None:
        return error
    if value.sink_path is not None and value.sink_path not in scope.admitted_paths:
        return ToolObservation(tool="probe_python_eval", status="blocked",
                               content="sink path is outside the retrieved execution scope")
    source = cast(CodeDocument, document)
    local_line = local_source_line(value.source_path, scope.subject.entry_line) if scope.subject else None
    if scope.subject is not None and (
        scope.subject.entry_path != value.source_path
        or scope.subject.repository_id != source.repository_id
        or local_line is not None and not 1 <= local_line <= len(source.text.splitlines())
    ):
        return ToolObservation(tool="probe_python_eval", status="blocked",
                               content="Probe subject does not match the indexed source span")
    result = probe_python_eval(index, scope.admitted_paths, value.source_path,
                               value.sink_path, value.max_hops,
                               entry_boolean_arguments=scope.subject.entry_boolean_arguments if scope.subject else {},
                               input_parameters=scope.subject.input_parameters if scope.subject else None)
    result["property_id"] = "dynamic-evaluation"
    result["source_path"] = value.source_path
    property_matches = scope.subject is not None and scope.subject.property_id == "dynamic-evaluation"
    scope_matches = (local_line is None or local_line in result["function_header_lines"]
                     or all(attempt.get("sink_path") == value.source_path
                            and attempt.get("sink_line") == local_line
                            for attempt in result["attempts"]))
    # The result still exposes a local witness when it cannot prove this subject.
    subject = scope.subject if property_matches and (result["status"] == "UNRESOLVED" or scope_matches) else None
    return ToolObservation(
        tool="probe_python_eval", status="ok",
        validation_status=ValidationStatus(result["status"]), content=_json_content(result),
        evidence_ids=(f"probe:{value.source_path}",),
        subject=subject,
    )
