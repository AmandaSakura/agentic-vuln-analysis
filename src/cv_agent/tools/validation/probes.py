"""Candidate-bound concrete Python eval probe adapter."""

from __future__ import annotations

from typing import cast

from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.identity import repository_source_digest
from cv_agent.domain.evidence import ToolObservation, ValidationStatus
from cv_agent.tools.analysis.python_probe import probe_python_eval
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import FrozenModel
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
    _, error = _admitted_document(index, value.source_path, scope, "probe_python_eval")
    if error is not None:
        return error
    if value.sink_path is not None and value.sink_path not in scope.admitted_paths:
        return ToolObservation(tool="probe_python_eval", status="blocked",
                               content="sink path is outside the retrieved execution scope")
    result = probe_python_eval(index, scope.admitted_paths, value.source_path,
                               value.sink_path, value.max_hops)
    return ToolObservation(
        tool="probe_python_eval", status="ok",
        validation_status=ValidationStatus(result["status"]), content=_json_content(result),
        evidence_ids=(f"probe:{value.source_path}",),
        subject=scope.subject,
    )
