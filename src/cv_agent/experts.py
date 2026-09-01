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


ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:final\s+)?(?:[\w.$<>\[\],?]+\s+)+)?"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?::=|=(?!=))\s*"
    r"(?P<value>.+?)\s*;?\s*(?://.*)?$"
)
COLLECTION_PUT_RE = re.compile(
    r"\b(?P<name>[A-Za-z_$][\w$]*)\.put\s*\((?P<arguments>[^;]*)\)"
)
STRING_LITERAL_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
IDENTIFIER_RE = re.compile(r"\b[A-Za-z_$][\w$]*\b")
NON_VALUE_IDENTIFIERS = frozenset(
    {
        "String",
        "Object",
        "Integer",
        "Boolean",
        "Long",
        "Double",
        "Float",
        "new",
        "null",
        "true",
        "false",
    }
)
SINK_VALUE_NAME_RE = re.compile(
    r"(?:sql|query|filter|command|cmd|path|file|name|bar|param|value)",
    re.IGNORECASE,
)


def _contains_identifier(text: str, names: Sequence[str] | set[str]) -> bool:
    return any(re.search(rf"\b{re.escape(name)}\b", text) for name in names)


def _contains_clean_sink_value(text: str, clean: set[str]) -> bool:
    return any(
        SINK_VALUE_NAME_RE.search(name)
        and re.search(rf"\b{re.escape(name)}\b", text)
        for name in clean
    )


def _value_identifiers(value: str) -> set[str]:
    without_literals = STRING_LITERAL_RE.sub("", value)
    return {
        name
        for name in IDENTIFIER_RE.findall(without_literals)
        if name not in NON_VALUE_IDENTIFIERS and not name[:1].isupper()
    }


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
    sources = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"\b(?:request|req)\.(?:args|query|body|params|headers|cookies)\b",
            r"\brequest\.get(?:Header|Headers|Parameter|ParameterValues|Cookies?|QueryString)\s*\(",
            r"\.getTheParameter\s*\(",
            r"\buser_input\b",
            r"\binput\s*\(",
        )
    )
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

    def _value_is_tainted(
        self,
        value: str,
        tainted: set[str],
        tainted_containers: set[str],
    ) -> bool:
        return (
            any(pattern.search(value) for pattern in self.sources)
            or _contains_identifier(value, tainted)
            or _contains_identifier(value, tainted_containers)
        )

    def _value_is_clean(
        self,
        value: str,
        clean: set[str],
    ) -> bool:
        if any(pattern.search(value) for pattern in self.sources):
            return False
        identifiers = _value_identifiers(value)
        return not identifiers or identifiers.issubset(clean)

    def _legacy_source_before_sink(self, item: Evidence) -> bool:
        sources = _positions(item.text, self.sources)
        sinks = _positions(item.text, self.sinks)
        sanitizers = _positions(item.text, self.sanitizers)
        for sink in sinks:
            preceding_sources = [source for source in sources if source < sink]
            if not preceding_sources:
                continue
            source = max(preceding_sources)
            if any(source < sanitizer < sink for sanitizer in sanitizers):
                continue
            return True
        return False

    def evaluate(self, candidate: Candidate, evidence: Sequence[Evidence]) -> ExpertVote:
        vulnerable_ids: list[str] = []
        safe_ids: list[str] = []
        fallback_vulnerable_ids: list[str] = []
        partial_ids: list[str] = []
        for item in evidence:
            tainted: set[str] = set()
            clean: set[str] = set()
            tainted_containers: set[str] = set()
            source_seen = False
            sink_seen = False
            sanitizer_seen = False

            for raw_line in item.text.splitlines():
                line = raw_line.split("//", 1)[0]
                source_hits = any(pattern.search(line) for pattern in self.sources)
                sanitizer_hits = any(pattern.search(line) for pattern in self.sanitizers)
                assignment = ASSIGNMENT_RE.match(line)
                if source_hits:
                    source_seen = True
                if sanitizer_hits:
                    sanitizer_seen = True

                for put in COLLECTION_PUT_RE.finditer(line):
                    if self._value_is_tainted(
                        put.group("arguments"),
                        tainted,
                        tainted_containers,
                    ):
                        tainted_containers.add(put.group("name"))

                if assignment:
                    name = assignment.group("name")
                    value = assignment.group("value")
                    if sanitizer_hits:
                        tainted.discard(name)
                        clean.add(name)
                    elif self._value_is_tainted(value, tainted, tainted_containers):
                        tainted.add(name)
                        clean.discard(name)
                    elif self._value_is_clean(value, clean):
                        tainted.discard(name)
                        clean.add(name)
                    else:
                        tainted.discard(name)
                        clean.discard(name)

                line_is_tainted = (
                    source_hits
                    or _contains_identifier(line, tainted)
                    or _contains_identifier(line, tainted_containers)
                )
                line_has_clean_value = _contains_clean_sink_value(line, clean)
                if any(pattern.search(line) for pattern in self.sinks):
                    sink_seen = True
                    if line_is_tainted and not sanitizer_hits:
                        vulnerable_ids.append(item.evidence_id)
                    elif sanitizer_seen or line_has_clean_value:
                        safe_ids.append(item.evidence_id)

            if source_seen or sink_seen or sanitizer_seen:
                partial_ids.append(item.evidence_id)
            if self._legacy_source_before_sink(item):
                fallback_vulnerable_ids.append(item.evidence_id)

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
        if safe_ids:
            return ExpertVote(
                expert="taint",
                label="SAFE",
                confidence=0.82,
                evidence_ids=tuple(dict.fromkeys(safe_ids)),
                rationale=(
                    "A sink is present, but the local taint flow is cut by sanitization "
                    "or by assignment from non-source data."
                ),
                trace=(
                    ReasoningStep(
                        action="track_local_taint_to_sink",
                        observation="sink reached without a tracked tainted value",
                    ),
                ),
            )
        if fallback_vulnerable_ids:
            return ExpertVote(
                expert="taint",
                label="VULNERABLE",
                confidence=0.78,
                evidence_ids=tuple(dict.fromkeys(fallback_vulnerable_ids)),
                rationale=(
                    "A source precedes a sink in the same function; local value tracking "
                    "did not produce a stronger refutation."
                ),
                trace=(
                    ReasoningStep(
                        action="fallback_source_before_sink",
                        observation=(
                            f"{len(set(fallback_vulnerable_ids))} same-function "
                            "source-before-sink candidate(s)"
                        ),
                    ),
                ),
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
