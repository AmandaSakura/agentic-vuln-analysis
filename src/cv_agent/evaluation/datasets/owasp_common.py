"""Shared OWASP source selection and metric serialization."""
from cv_agent.evaluation.classification import TernaryEvaluation


def _entry_document(documents, class_name: str):
    expected = f"{class_name}.doGet"
    return next((document for document in documents if expected in document.defines), None)


def _matrix_dict(matrix: TernaryEvaluation) -> dict[str, int | float | None]:
    return {
        "tp": matrix.true_positive,
        "fp": matrix.false_positive,
        "tn": matrix.true_negative,
        "fn": matrix.false_negative,
        "abstain_positive": matrix.abstain_positive,
        "abstain_negative": matrix.abstain_negative,
        "coverage": matrix.coverage,
        "abstain_rate": matrix.abstain_rate,
        "strict_recall": matrix.strict_recall,
        "covered_recall": matrix.covered_recall,
        "precision": matrix.precision,
        "population_false_positive_rate": matrix.population_false_positive_rate,
        "conservative_false_positive_rate": matrix.conservative_false_positive_rate,
        "covered_false_positive_rate": matrix.covered_false_positive_rate,
    }
