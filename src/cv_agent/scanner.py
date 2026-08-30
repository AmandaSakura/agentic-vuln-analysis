from __future__ import annotations

import re
from collections.abc import Iterable

from .types import Candidate, CodeDocument


class StaticScanner:
    """Small deterministic V0 candidate generator used before agent reasoning."""

    rules = {
        "command-execution": re.compile(r"subprocess\.|Runtime\.getRuntime\(\)\.exec|shell\s*=\s*True", re.IGNORECASE),
        "dynamic-evaluation": re.compile(r"(?<![\w.])(?:eval|exec)\s*\(", re.IGNORECASE),
        "database-operation": re.compile(r"\.(?:executeQuery|delete)\s*\(", re.IGNORECASE),
    }

    def scan(self, repository_id: str, documents: Iterable[CodeDocument]) -> list[Candidate]:
        candidates: list[Candidate] = []
        for document in documents:
            for line_number, line in enumerate(document.text.splitlines(), start=1):
                for rule_name, pattern in self.rules.items():
                    if pattern.search(line):
                        candidate_id = f"{repository_id}:{document.path}:{line_number}:{rule_name}"
                        candidates.append(
                            Candidate(
                                candidate_id=candidate_id,
                                case_id=candidate_id,
                                repository_id=repository_id,
                                path=document.path,
                                line=line_number,
                                query=f"{rule_name} {line.strip()}",
                                metadata={"rule": rule_name},
                            )
                        )
        return candidates
