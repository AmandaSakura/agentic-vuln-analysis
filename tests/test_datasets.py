from __future__ import annotations

import json

from cv_agent.datasets import load_owasp_expected_results, load_vulngym_entries


def test_vulngym_detector_view_excludes_ground_truth(tmp_path):
    row = {
        "entry_id": "entry-00001",
        "report_id": "GHSA-AAAA-BBBB-CCCC",
        "repo_url": "https://example.invalid/repo",
        "commit": "a" * 40,
        "verify": 1,
        "entry_point": {"path": "api.py", "line": 10},
        "critical_operation": {"path": "db.py", "line": 50},
        "trace": [{"path": "api.py"}, {"path": "db.py"}],
    }
    path = tmp_path / "entries.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    cases, labels = load_vulngym_entries(path)
    detector_payload = cases[0].model_dump()
    assert set(detector_payload) == {"case_id", "repository_url", "commit"}
    assert labels["entry-00001"].critical_operation == row["critical_operation"]


def test_owasp_comment_header_is_preserved(tmp_path):
    path = tmp_path / "expectedresults.csv"
    path.write_text(
        "# generated benchmark truth table\n"
        "# test name, category, real vulnerability, CWE, Benchmark version: 1.2, generated date\n"
        "BenchmarkTest00001, sqli, TRUE, 89\n"
        "BenchmarkTest00002, sqli, FALSE, 89\n",
        encoding="utf-8",
    )
    labels = load_owasp_expected_results(path)
    assert labels["BenchmarkTest00001"].vulnerable is True
    assert labels["BenchmarkTest00002"].vulnerable is False
