"""Stable validation subjects bound to indexed repository source contents."""
from __future__ import annotations

import hashlib
import json

from cv_agent.domain.evidence import ValidationSubject
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import Candidate


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
