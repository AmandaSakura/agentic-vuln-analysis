"""Security-sensitive sink scanning."""
from __future__ import annotations

from collections.abc import Sequence
import re

from cv_agent.domain.types import Candidate, Evidence, ExpertVote, ReasoningStep
from cv_agent.baselines.experts.common import _matching_evidence


class ScanExpert:
    name = "scan"
    sinks = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"(?<![\w.])(?:eval|exec)\s*\(",
            r"subprocess\.(?:run|popen|call)",
            r"Runtime\.getRuntime\(\)\.exec",
            r"\bProcessBuilder\s*\(",
            r"\.command\s*\(",
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
