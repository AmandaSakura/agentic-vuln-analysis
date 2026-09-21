from pathlib import Path

import pytest

from cv_agent.evaluation.datasets.owasp_live import load_owasp_agentic_inputs, run_agentic_owasp_live
from cv_agent.harness import FULL_SYSTEM_HARNESS


def _write_owasp_fixture(raw_root: Path) -> None:
    benchmark_root = raw_root / "BenchmarkJava"
    source_root = (
        benchmark_root
        / "src"
        / "main"
        / "java"
        / "org"
        / "owasp"
        / "benchmark"
        / "testcode"
    )
    source_root.mkdir(parents=True)
    (benchmark_root / "expectedresults-1.2beta.csv").write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,cmdi,true,78\n",
        encoding="utf-8",
    )
    (source_root / "BenchmarkTest00001.java").write_text(
        """
        package org.owasp.benchmark.testcode;

        public class BenchmarkTest00001 {
            public void doGet(Object request, Object response) {
                doPost(request, response);
            }

            public void doPost(Object request, Object response) throws Exception {
                Runtime.getRuntime().exec("echo ok");
            }
        }
        """,
        encoding="utf-8",
    )


def test_owasp_agentic_loader_keeps_truth_out_of_candidate(tmp_path: Path):
    _write_owasp_fixture(tmp_path)

    inputs = load_owasp_agentic_inputs(
        tmp_path,
        case_ids=("BenchmarkTest00001",),
    )

    candidate = inputs.candidates[0]
    assert candidate.case_id == "BenchmarkTest00001"
    assert "BenchmarkTest00001.doGet" in candidate.path
    assert candidate.metadata == {}
    assert "true" not in candidate.query.casefold()
    assert inputs.labels["BenchmarkTest00001"].vulnerable is True


def test_owasp_agentic_loader_rejects_duplicate_cases(tmp_path: Path):
    _write_owasp_fixture(tmp_path)

    with pytest.raises(ValueError, match="duplicate OWASP case id"):
        load_owasp_agentic_inputs(
            tmp_path,
            case_ids=("BenchmarkTest00001", "BenchmarkTest00001"),
        )


def test_live_owasp_runner_requires_model_environment_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    _write_owasp_fixture(tmp_path)
    monkeypatch.delenv(FULL_SYSTEM_HARNESS.model.base_url_env, raising=False)
    monkeypatch.delenv(FULL_SYSTEM_HARNESS.model.model_env, raising=False)
    monkeypatch.delenv(FULL_SYSTEM_HARNESS.model.api_key_env, raising=False)

    with pytest.raises(ValueError, match="live model environment is incomplete"):
        run_agentic_owasp_live(
            tmp_path,
            case_ids=("BenchmarkTest00001",),
            system_ids=("E1",),
        )
