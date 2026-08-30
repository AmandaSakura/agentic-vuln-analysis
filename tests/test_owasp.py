from pathlib import Path

import pytest

from cv_agent.owasp import detect_owasp_sources, evaluate_owasp_predictions, strip_java_comments
from cv_agent.types import OwaspLabel


def test_strip_java_comments_preserves_strings_and_line_numbers():
    source = (
        '// Runtime.getRuntime().exec("comment")\n'
        'String url = "https://example.test/a//b"; /* .executeQuery( */\n'
        'Runtime.getRuntime().exec(cmd);\n'
    )
    stripped = strip_java_comments(source)
    assert stripped.count("\n") == source.count("\n")
    assert "comment" not in stripped
    assert '"https://example.test/a//b"' in stripped
    assert "Runtime.getRuntime().exec(cmd)" in stripped


def test_detector_reads_source_without_needing_labels(tmp_path: Path):
    (tmp_path / "BenchmarkTest00001.java").write_text(
        "class BenchmarkTest00001 { void run(String cmd) { Runtime.getRuntime().exec(cmd); } }",
        encoding="utf-8",
    )
    (tmp_path / "BenchmarkTest00002.java").write_text(
        "class BenchmarkTest00002 { void run() { /* Runtime.getRuntime().exec(x); */ } }",
        encoding="utf-8",
    )

    predictions, rule_hits = detect_owasp_sources(tmp_path)

    assert predictions == {"BenchmarkTest00001": True, "BenchmarkTest00002": False}
    assert rule_hits == {"command-execution": 1}


def test_owasp_evaluation_reports_per_category_metrics():
    labels = {
        "one": OwaspLabel(case_id="one", category="cmdi", vulnerable=True, cwe=78),
        "two": OwaspLabel(case_id="two", category="cmdi", vulnerable=False, cwe=78),
        "three": OwaspLabel(case_id="three", category="sqli", vulnerable=True, cwe=89),
    }
    result = evaluate_owasp_predictions(labels, {"one": True, "two": True, "three": False})
    assert result["overall"] == {
        "tp": 1,
        "fp": 1,
        "tn": 0,
        "fn": 1,
        "recall": 0.5,
        "precision": 0.5,
        "false_positive_rate": 1.0,
    }
    assert result["categories"]["cmdi"]["recall"] == 1.0
    assert result["categories"]["sqli"]["false_positive_rate"] is None


def test_detector_rejects_empty_source_tree(tmp_path: Path):
    with pytest.raises(ValueError, match="no OWASP Benchmark Java cases"):
        detect_owasp_sources(tmp_path)
