from __future__ import annotations

from pathlib import Path

from cv_agent.evaluation.datasets.loaders import load_owasp_expected_results, load_vulngym_entries


def profile_public_data(raw_root: Path) -> dict:
    vulngym_root = raw_root / "VulnGym"
    benchmark_root = raw_root / "BenchmarkJava"
    entries_path = vulngym_root / "data" / "entries.jsonl"
    expected_results_path = benchmark_root / "expectedresults-1.2beta.csv"
    if not entries_path.is_file():
        raise FileNotFoundError(entries_path)
    if not expected_results_path.is_file():
        raise FileNotFoundError(expected_results_path)

    detector_cases, vulngym_labels = load_vulngym_entries(entries_path)
    owasp_labels = load_owasp_expected_results(expected_results_path)
    java_files = list((benchmark_root / "src").rglob("BenchmarkTest*.java"))

    return {
        "vulngym": {
            "entry_count": len(detector_cases),
            "verified_entry_count": sum(label.verify for label in vulngym_labels.values()),
            "report_count": len({label.report_id for label in vulngym_labels.values()}),
            "repository_count": len({case.repository_url for case in detector_cases}),
            "commit_count": len({case.commit for case in detector_cases}),
            "detector_fields": sorted(detector_cases[0].model_dump()) if detector_cases else [],
        },
        "owasp": {
            "case_count": len(owasp_labels),
            "vulnerable_count": sum(label.vulnerable for label in owasp_labels.values()),
            "benign_count": sum(not label.vulnerable for label in owasp_labels.values()),
            "java_test_file_count": len(java_files),
        },
    }
