from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path

from .datasets import load_owasp_expected_results
from .metrics import ConfusionMatrix, evaluate_binary
from .scanner import StaticScanner
from .types import CodeDocument, OwaspLabel


def strip_java_comments(text: str) -> str:
    """Remove Java comments while preserving strings and source line numbers."""

    output: list[str] = []
    index = 0
    state = "code"
    while index < len(text):
        current = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""

        if state == "code":
            if current == '"':
                output.append(current)
                state = "string"
            elif current == "'":
                output.append(current)
                state = "character"
            elif current == "/" and following == "/":
                output.extend((" ", " "))
                index += 1
                state = "line_comment"
            elif current == "/" and following == "*":
                output.extend((" ", " "))
                index += 1
                state = "block_comment"
            else:
                output.append(current)
        elif state == "line_comment":
            if current == "\n":
                output.append(current)
                state = "code"
            else:
                output.append(" ")
        elif state == "block_comment":
            if current == "*" and following == "/":
                output.extend((" ", " "))
                index += 1
                state = "code"
            elif current == "\n":
                output.append(current)
            else:
                output.append(" ")
        else:
            output.append(current)
            if current == "\\" and following:
                output.append(following)
                index += 1
            elif state == "string" and current == '"':
                state = "code"
            elif state == "character" and current == "'":
                state = "code"
        index += 1
    return "".join(output)


def detect_owasp_sources(source_root: Path) -> tuple[dict[str, bool], dict[str, int]]:
    """Produce case predictions from Java source only, without evaluator labels."""

    source_files = sorted(source_root.glob("BenchmarkTest*.java"))
    if not source_files:
        raise ValueError(f"no OWASP Benchmark Java cases found under {source_root}")

    scanner = StaticScanner()
    predictions: dict[str, bool] = {}
    rule_hits: Counter[str] = Counter()
    for source_file in source_files:
        case_id = source_file.stem
        if case_id in predictions:
            raise ValueError(f"duplicate OWASP Java case: {case_id}")
        document = CodeDocument(
            repository_id="OWASP-BenchmarkJava-1.2beta",
            path=source_file.name,
            text=strip_java_comments(source_file.read_text(encoding="utf-8")),
        )
        findings = scanner.scan(document.repository_id, [document])
        predictions[case_id] = bool(findings)
        rule_hits.update(str(finding.metadata["rule"]) for finding in findings)
    return predictions, dict(sorted(rule_hits.items()))


def _matrix_dict(matrix: ConfusionMatrix) -> dict[str, int | float | None]:
    return {
        "tp": matrix.true_positive,
        "fp": matrix.false_positive,
        "tn": matrix.true_negative,
        "fn": matrix.false_negative,
        "recall": matrix.recall,
        "precision": matrix.precision,
        "false_positive_rate": matrix.false_positive_rate,
    }


def evaluate_owasp_predictions(
    labels: Mapping[str, OwaspLabel], predictions: Mapping[str, bool]
) -> dict[str, object]:
    truth = {case_id: label.vulnerable for case_id, label in labels.items()}
    overall = evaluate_binary(truth, predictions)

    category_ids: dict[str, list[str]] = defaultdict(list)
    for case_id, label in labels.items():
        category_ids[label.category].append(case_id)
    categories: dict[str, dict[str, int | float | None]] = {}
    for category, case_ids in sorted(category_ids.items()):
        category_truth = {case_id: truth[case_id] for case_id in case_ids}
        category_predictions = {case_id: predictions[case_id] for case_id in case_ids}
        categories[category] = _matrix_dict(evaluate_binary(category_truth, category_predictions))

    return {"overall": _matrix_dict(overall), "categories": categories}


def run_owasp_static_baseline(raw_root: Path) -> dict[str, object]:
    benchmark_root = raw_root / "BenchmarkJava"
    source_root = benchmark_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    predictions, rule_hits = detect_owasp_sources(source_root)

    # Ground truth enters only after every detector prediction has been produced.
    labels = load_owasp_expected_results(benchmark_root / "expectedresults-1.2beta.csv")
    metrics = evaluate_owasp_predictions(labels, predictions)
    return {
        "dataset": "OWASP BenchmarkJava 1.2beta",
        "system": "static-sink-baseline",
        "case_count": len(predictions),
        "predicted_vulnerable_count": sum(predictions.values()),
        "rule_hit_count": rule_hits,
        **metrics,
    }
