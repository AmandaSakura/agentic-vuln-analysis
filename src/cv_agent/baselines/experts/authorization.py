"""Same-function authorization guard ordering."""
from __future__ import annotations

from collections.abc import Sequence
import re

from cv_agent.domain.types import Candidate, Evidence, ExpertVote, ReasoningStep
from cv_agent.baselines.experts.common import _matching_evidence, _positions


class AuthorizationExpert:
    name = "authz"
    sensitive = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"\.delete\s*\(",
            r"(?<![\w.])transfer\s*\(",
            r"(?<![\w.])(?:update|set|grant)_role\s*\(",
        )
    )
    guards = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"require_permission\s*\(",
            r"(?<![\w.])authorize\s*\(",
            r"is_admin\s*\(",
            r"check_role\s*\(",
            r"has_permission\s*\(",
        )
    )

    def applies(self, evidence: Sequence[Evidence]) -> bool:
        return bool(_matching_evidence(evidence, (*self.sensitive, *self.guards)))

    def evaluate(self, candidate: Candidate, evidence: Sequence[Evidence]) -> ExpertVote:
        guarded_ids: list[str] = []
        unguarded_ids: list[str] = []
        partial_ids: list[str] = []
        for item in evidence:
            operations = _positions(item.text, self.sensitive)
            guards = _positions(item.text, self.guards)
            if operations or guards:
                partial_ids.append(item.evidence_id)
            for operation in operations:
                if any(guard < operation for guard in guards):
                    guarded_ids.append(item.evidence_id)
                else:
                    unguarded_ids.append(item.evidence_id)

        if unguarded_ids:
            return ExpertVote(
                expert="authz",
                label="VULNERABLE",
                confidence=0.82,
                evidence_ids=tuple(dict.fromkeys(unguarded_ids)),
                rationale="A sensitive operation has no preceding authorization guard in the same function.",
                trace=(ReasoningStep(action="order_guard_before_operation", observation="unguarded operation found"),),
            )
        if guarded_ids:
            return ExpertVote(
                expert="authz",
                label="SAFE",
                confidence=0.84,
                evidence_ids=tuple(dict.fromkeys(guarded_ids)),
                rationale="An authorization guard precedes the sensitive operation in the same function.",
                trace=(ReasoningStep(action="order_guard_before_operation", observation="ordered guard found"),),
            )
        return ExpertVote(
            expert="authz",
            label="ABSTAIN",
            confidence=0.35,
            evidence_ids=tuple(dict.fromkeys(partial_ids)),
            rationale="No same-function authorization claim can be established.",
        )
