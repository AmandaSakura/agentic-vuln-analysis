from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from .types import ExpertVote, Verdict


class SingleExpertPolicy:
    def decide(self, votes: Sequence[ExpertVote]) -> Verdict:
        if not votes:
            return Verdict(label="ABSTAIN", confidence=0.0, path="single", votes=(), rationale="No expert vote was produced.")
        vote = votes[0]
        return Verdict(label=vote.label, confidence=vote.confidence, path="single", votes=tuple(votes), rationale=vote.rationale)


class QuorumPolicy:
    """Quorum-inspired majority adjudication; this is not distributed consensus."""

    def __init__(
        self,
        *,
        fast_enabled: bool = True,
        quorum: int = 2,
        fast_confidence: float = 0.80,
    ) -> None:
        self.fast_enabled = fast_enabled
        self.quorum = quorum
        self.fast_confidence = fast_confidence

    def try_fast(self, votes: Sequence[ExpertVote]) -> Verdict | None:
        material = [vote for vote in votes if vote.label != "ABSTAIN"]
        confident = [vote for vote in material if vote.confidence >= self.fast_confidence]
        labels = Counter(vote.label for vote in confident)
        if not labels:
            return None
        label, count = labels.most_common(1)[0]
        if count < self.quorum:
            return None
        selected = [vote for vote in confident if vote.label == label]
        return Verdict(
            label=label,
            confidence=sum(vote.confidence for vote in selected) / len(selected),
            path="fast",
            votes=tuple(votes),
            rationale=f"{count} high-confidence experts formed an early quorum.",
        )

    def decide(self, votes: Sequence[ExpertVote]) -> Verdict:
        if self.fast_enabled:
            fast = self.try_fast(votes)
            if fast is not None:
                return fast

        material = [vote for vote in votes if vote.label != "ABSTAIN"]
        if len(material) < self.quorum:
            return Verdict(
                label="ABSTAIN",
                confidence=max((vote.confidence for vote in material), default=0.0),
                path="slow",
                votes=tuple(votes),
                rationale="Fewer than two material expert votes were available.",
            )
        labels = Counter(vote.label for vote in material)
        ranked = labels.most_common()
        if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
            return Verdict(
                label="ABSTAIN",
                confidence=max(vote.confidence for vote in material),
                path="slow",
                votes=tuple(votes),
                rationale="Material expert votes were tied.",
            )
        label, count = ranked[0]
        if count < self.quorum:
            return Verdict(
                label="ABSTAIN",
                confidence=max(vote.confidence for vote in material),
                path="slow",
                votes=tuple(votes),
                rationale="No label reached the required expert quorum.",
            )
        selected = [vote for vote in material if vote.label == label]
        return Verdict(
            label=label,
            confidence=sum(vote.confidence for vote in selected) / len(selected),
            path="slow",
            votes=tuple(votes),
            rationale=f"{count} experts formed a majority quorum after full review.",
        )
