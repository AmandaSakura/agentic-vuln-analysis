from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .types import VerdictLabel


@dataclass(frozen=True)
class ConfusionMatrix:
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int

    @property
    def recall(self) -> float | None:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else None

    @property
    def false_positive_rate(self) -> float | None:
        denominator = self.false_positive + self.true_negative
        return self.false_positive / denominator if denominator else None

    @property
    def precision(self) -> float | None:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else None


@dataclass(frozen=True)
class TernaryEvaluation:
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    abstain_positive: int
    abstain_negative: int

    @property
    def total(self) -> int:
        return (
            self.true_positive
            + self.false_positive
            + self.true_negative
            + self.false_negative
            + self.abstain_positive
            + self.abstain_negative
        )

    @property
    def coverage(self) -> float | None:
        classified = (
            self.true_positive
            + self.false_positive
            + self.true_negative
            + self.false_negative
        )
        return classified / self.total if self.total else None

    @property
    def abstain_rate(self) -> float | None:
        abstained = self.abstain_positive + self.abstain_negative
        return abstained / self.total if self.total else None

    @property
    def strict_recall(self) -> float | None:
        denominator = self.true_positive + self.false_negative + self.abstain_positive
        return self.true_positive / denominator if denominator else None

    @property
    def covered_recall(self) -> float | None:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else None

    @property
    def population_false_positive_rate(self) -> float | None:
        denominator = self.false_positive + self.true_negative + self.abstain_negative
        return self.false_positive / denominator if denominator else None

    @property
    def covered_false_positive_rate(self) -> float | None:
        denominator = self.false_positive + self.true_negative
        return self.false_positive / denominator if denominator else None

    @property
    def precision(self) -> float | None:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else None


def _check_prediction_keys(labels: Mapping[str, bool], predictions: Mapping[str, object]) -> None:
    if set(labels) != set(predictions):
        missing = sorted(set(labels) - set(predictions))
        extra = sorted(set(predictions) - set(labels))
        raise ValueError(f"prediction keys differ: missing={missing}, extra={extra}")


def evaluate_binary(labels: Mapping[str, bool], predictions: Mapping[str, bool]) -> ConfusionMatrix:
    _check_prediction_keys(labels, predictions)
    tp = fp = tn = fn = 0
    for case_id, actual in labels.items():
        predicted = predictions[case_id]
        if actual and predicted:
            tp += 1
        elif actual:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    return ConfusionMatrix(tp, fp, tn, fn)


def evaluate_ternary(
    labels: Mapping[str, bool],
    predictions: Mapping[str, VerdictLabel],
) -> TernaryEvaluation:
    _check_prediction_keys(labels, predictions)
    tp = fp = tn = fn = abstain_positive = abstain_negative = 0
    for case_id, actual in labels.items():
        predicted = predictions[case_id]
        if predicted == "ABSTAIN":
            if actual:
                abstain_positive += 1
            else:
                abstain_negative += 1
        elif predicted == "VULNERABLE":
            if actual:
                tp += 1
            else:
                fp += 1
        elif predicted == "SAFE":
            if actual:
                fn += 1
            else:
                tn += 1
        else:
            raise ValueError(f"invalid ternary prediction for {case_id}: {predicted!r}")
    return TernaryEvaluation(
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
        abstain_positive=abstain_positive,
        abstain_negative=abstain_negative,
    )
