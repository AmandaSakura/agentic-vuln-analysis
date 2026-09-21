"""Expert protocol and evidence matching shared by deterministic specialists."""
from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol
import re

from cv_agent.domain.types import Candidate, Evidence, ExpertVote


class Expert(Protocol):
    name: str

    def evaluate(self, candidate: Candidate, evidence: Sequence[Evidence]) -> ExpertVote: ...


def _matching_evidence(evidence: Sequence[Evidence], patterns: Sequence[re.Pattern[str]]) -> list[Evidence]:
    return [item for item in evidence if any(pattern.search(item.text) for pattern in patterns)]


def _positions(text: str, patterns: Sequence[re.Pattern[str]]) -> list[int]:
    return sorted(match.start() for pattern in patterns for match in pattern.finditer(text))
