from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Protocol

from .types import Candidate, Evidence, ExpertVote, ReasoningStep


class Expert(Protocol):
    name: str

    def evaluate(self, candidate: Candidate, evidence: Sequence[Evidence]) -> ExpertVote: ...


def _matching_evidence(evidence: Sequence[Evidence], patterns: Sequence[re.Pattern[str]]) -> list[Evidence]:
    return [item for item in evidence if any(pattern.search(item.text) for pattern in patterns)]


def _positions(text: str, patterns: Sequence[re.Pattern[str]]) -> list[int]:
    return sorted(match.start() for pattern in patterns for match in pattern.finditer(text))


class ScanExpert:
    name = "scan"
    sinks = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"(?<![\w.])(?:eval|exec)\s*\(",
            r"subprocess\.(?:run|popen|call)",
            r"Runtime\.getRuntime\(\)\.exec",
            r"\bProcessBuilder\s*\(",
            r"\.(?:execute|executeQuery|executeUpdate|prepareStatement|prepareCall)\s*\(",
            r"\.(?:search|compile|evaluate)\s*\(",
            r"\b(?:FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(",
            r"\.delete\s*\(",
            r"shell\s*=\s*True",
        )
    )

    def evaluate(self, candidate: Candidate, evidence: Sequence[Evidence]) -> ExpertVote:
        matches = _matching_evidence(evidence, self.sinks)
        if matches:
            ids = tuple(item.evidence_id for item in matches)
            return ExpertVote(
                expert="scan",
                label="VULNERABLE",
                confidence=min(0.95, 0.80 + 0.05 * len(matches)),
                evidence_ids=ids,
                rationale="A security-sensitive sink is present in retrieved code.",
                trace=(ReasoningStep(action="scan_sinks", observation=f"matched {len(matches)} evidence item(s)"),),
            )
        return ExpertVote(
            expert="scan",
            label="ABSTAIN",
            confidence=0.35,
            rationale="The configured scanner found no sink; limited rule coverage cannot prove safety.",
            trace=(ReasoningStep(action="scan_sinks", observation="no sink match; safety not established"),),
        )


class TaintExpert:
    name = "taint"
    sources = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (r"request\.", r"request\.args", r"getParameter\s*\(", r"user_input", r"\binput\s*\("))
    sinks = ScanExpert.sinks
    sanitizers = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"sanitize",
            r"escape",
            r"encodeFor(?:HTML|URL|JavaScript|SQL)",
            r"allowlist",
            r"validate",
        )
    )

    def evaluate(self, candidate: Candidate, evidence: Sequence[Evidence]) -> ExpertVote:
        vulnerable_ids: list[str] = []
        guarded_ids: list[str] = []
        partial_ids: list[str] = []
        for item in evidence:
            sources = _positions(item.text, self.sources)
            sinks = _positions(item.text, self.sinks)
            sanitizers = _positions(item.text, self.sanitizers)
            if sources or sinks or sanitizers:
                partial_ids.append(item.evidence_id)
            for sink in sinks:
                preceding_sources = [source for source in sources if source < sink]
                if not preceding_sources:
                    continue
                source = max(preceding_sources)
                if any(source < sanitizer < sink for sanitizer in sanitizers):
                    guarded_ids.append(item.evidence_id)
                else:
                    vulnerable_ids.append(item.evidence_id)

        if vulnerable_ids:
            return ExpertVote(
                expert="taint",
                label="VULNERABLE",
                confidence=0.84,
                evidence_ids=tuple(dict.fromkeys(vulnerable_ids)),
                rationale="A source precedes a sink in the same function without an intervening sanitizer.",
                trace=(
                    ReasoningStep(action="order_source_to_sink", observation=f"{len(set(vulnerable_ids))} unguarded function path(s)"),
                ),
            )
        if guarded_ids:
            return ExpertVote(
                expert="taint",
                label="SAFE",
                confidence=0.82,
                evidence_ids=tuple(dict.fromkeys(guarded_ids)),
                rationale="A sanitizer appears between the source and sink in the same function.",
                trace=(ReasoningStep(action="order_source_sanitizer_sink", observation="ordered sanitizer found"),),
            )
        return ExpertVote(
            expert="taint",
            label="ABSTAIN",
            confidence=0.35,
            evidence_ids=tuple(dict.fromkeys(partial_ids)),
            rationale="No ordered same-function source-to-sink path can be established.",
        )


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


EXPERTS: dict[str, Expert] = {
    "scan": ScanExpert(),
    "taint": TaintExpert(),
    "authz": AuthorizationExpert(),
}
