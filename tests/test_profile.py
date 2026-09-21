from __future__ import annotations

import json

from cv_agent.evaluation.datasets.profile import profile_public_data


def test_profile_reports_aggregates_only(tmp_path):
    vulngym = tmp_path / "VulnGym" / "data"
    benchmark = tmp_path / "BenchmarkJava"
    java_root = benchmark / "src" / "main" / "java"
    vulngym.mkdir(parents=True)
    java_root.mkdir(parents=True)
    rows = [
        {
            "entry_id": "entry-1",
            "report_id": "GHSA-1",
            "repo_url": "https://example.invalid/repo",
            "commit": "a" * 40,
            "verify": 1,
            "entry_point": {"secret": 1},
            "critical_operation": {"secret": 2},
            "trace": [{"secret": 3}],
        },
        {
            "entry_id": "entry-2",
            "report_id": "GHSA-1",
            "repo_url": "https://example.invalid/repo",
            "commit": "a" * 40,
            "verify": 0,
            "entry_point": {"secret": 4},
            "critical_operation": {"secret": 5},
            "trace": [{"secret": 6}],
        },
    ]
    (vulngym / "entries.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    (benchmark / "expectedresults-1.2beta.csv").write_text(
        "# test name, category, real vulnerability, CWE, Benchmark version: 1.2, generated date\n"
        "BenchmarkTest00001, sqli, TRUE, 89\n"
        "BenchmarkTest00002, sqli, FALSE, 89\n",
        encoding="utf-8",
    )
    (java_root / "BenchmarkTest00001.java").write_text("class BenchmarkTest00001 {}\n", encoding="utf-8")
    result = profile_public_data(tmp_path)
    serialized = json.dumps(result)
    assert result["vulngym"]["verified_entry_count"] == 1
    assert result["owasp"]["vulnerable_count"] == 1
    assert "secret" not in serialized
