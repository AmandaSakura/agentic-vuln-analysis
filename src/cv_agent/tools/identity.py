"""Stable validation subjects bound to indexed repository source contents."""
from __future__ import annotations

import hashlib
import json
import re

from cv_agent.domain.evidence import ValidationSubject
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import Candidate


def local_source_line(path: str, line: int | None) -> int | None:
    if line is None:
        return None
    span = re.search(r"::.+@(\d+)(?:-\d+)?(?:#\d+-\d+)?$", path)
    return line - (int(span.group(1)) - 1 if span else 0)


def repository_source_digest(index: RepositoryIndex) -> str:
    return hashlib.sha256(json.dumps(
        [index.documents[path].model_dump(
            mode="json",
            # Preserve identities of adapters that have not added full-file
            # provenance; Java's nonempty file digest always participates.
            exclude={"source_sha256"} if index.documents[path].source_sha256 is None else set(),
        ) for path in sorted(index.documents)],
        sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()

def candidate_subject(index: RepositoryIndex, candidate: Candidate) -> ValidationSubject:
    """One identity constructor shared by the pipeline and registered fixtures."""
    return ValidationSubject(candidate_id=candidate.candidate_id, repository_id=candidate.repository_id,
                             entry_path=candidate.path, source_digest=repository_source_digest(index),
                             entry_line=candidate.line,
                             input_parameters=candidate.input_parameters,
                             entry_boolean_arguments=candidate.entry_boolean_arguments,
                             entry_condition_assumptions=candidate.entry_condition_assumptions,
                             entry_value_assumptions=candidate.entry_value_assumptions,
                             analysis_scope=candidate.analysis_scope, property_id=candidate.property_id)
