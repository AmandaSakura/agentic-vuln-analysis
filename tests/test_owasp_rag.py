from pathlib import Path

from cv_agent.owasp_rag import evaluate_owasp_rag, predict_owasp_rag
from cv_agent.types import OwaspLabel


def test_ast_call_graph_recovers_sink_from_servlet_delegate(tmp_path: Path):
    (tmp_path / "BenchmarkTest00001.java").write_text(
        """
        class BenchmarkTest00001 {
            void doGet(Request request, Response response) { doPost(request, response); }
            void doPost(Request request, Response response) {
                String value = request.getParameter("vector");
                new ProcessBuilder(value).start();
            }
        }
        """,
        encoding="utf-8",
    )

    predictions, diagnostics = predict_owasp_rag(tmp_path)

    assert diagnostics["parse_error_count"] == 0
    assert diagnostics["missing_entry_count"] == 0
    assert diagnostics["expert_call_count"] == {
        "V1": 1,
        "V2": 1,
        "V3": 1,
        "V4": 3,
        "V5": 2,
    }
    assert diagnostics["v5_vs_v4_expert_calls_saved"] == 1
    assert diagnostics["retrieval_top_k"] == 6
    assert diagnostics["context_token_budget_per_case"] == 2000
    assert all(
        count <= diagnostics["context_token_budget_per_case"]
        for count in diagnostics["max_context_token_count_per_case"].values()
    )
    assert diagnostics["verdict_path_count"] == {
        "V1": {"single": 1},
        "V2": {"single": 1},
        "V3": {"single": 1},
        "V4": {"slow": 1},
        "V5": {"fast": 1},
    }
    assert predictions == {
        "V1": {"BenchmarkTest00001": "ABSTAIN"},
        "V2": {"BenchmarkTest00001": "VULNERABLE"},
        "V3": {"BenchmarkTest00001": "VULNERABLE"},
        "V4": {"BenchmarkTest00001": "VULNERABLE"},
        "V5": {"BenchmarkTest00001": "VULNERABLE"},
    }


def test_missing_entry_is_counted_for_every_system(tmp_path: Path):
    (tmp_path / "BenchmarkTest00002.java").write_text(
        "class BenchmarkTest00002 { void doPost() {} }",
        encoding="utf-8",
    )

    predictions, diagnostics = predict_owasp_rag(tmp_path)

    assert diagnostics["missing_entry_cases"] == ["BenchmarkTest00002"]
    assert all(value == {"BenchmarkTest00002": "ABSTAIN"} for value in predictions.values())
    assert diagnostics["verdict_path_count"] == {
        system: {"missing_entry": 1} for system in ("V1", "V2", "V3", "V4", "V5")
    }


def test_owasp_metrics_keep_abstention_and_separate_attribution():
    labels = {
        "vulnerable": OwaspLabel(
            case_id="vulnerable", category="cmdi", vulnerable=True, cwe=78
        ),
        "benign": OwaspLabel(
            case_id="benign", category="cmdi", vulnerable=False, cwe=78
        ),
    }
    predictions = {
        "V1": {"vulnerable": "ABSTAIN", "benign": "ABSTAIN"},
        "V2": {"vulnerable": "ABSTAIN", "benign": "SAFE"},
        "V3": {"vulnerable": "VULNERABLE", "benign": "VULNERABLE"},
        "V4": {"vulnerable": "VULNERABLE", "benign": "ABSTAIN"},
        "V5": {"vulnerable": "VULNERABLE", "benign": "ABSTAIN"},
    }
    result = evaluate_owasp_rag(labels, predictions)
    assert result["primary_v3_vs_v2_strict_recall_gain_percentage_points"] == 100.0
    assert result["primary_v4_vs_v3_fpr_reduction_percent"] == 100.0
    assert result["systems"]["V4"]["primary_subset"]["coverage"] == 0.5
    assert result["primary_v4_vs_v3_coverage_delta_percentage_points"] == -50.0
    assert result["v5_vs_v4_label_disagreement_count"] == 0
