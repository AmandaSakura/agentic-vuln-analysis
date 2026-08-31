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
    assert diagnostics["expert_call_count_by_name"]["V4"] == {
        "authz": 1,
        "scan": 1,
        "taint": 1,
    }
    assert diagnostics["expert_call_count_by_name"]["V5"] == {
        "authz": 0,
        "scan": 1,
        "taint": 1,
    }
    assert diagnostics["verdict_path_by_label_count"]["V5"] == {
        "fast": {"VULNERABLE": 1}
    }
    assert diagnostics["retrieval_contract"]["V2"] == {
        "mode": "text",
        "top_k": 6,
        "base_context_tokens": 512,
        "augmentation_context_tokens": 1488,
        "graph_hops": 0,
        "total_context_tokens": 2000,
    }
    for system, count in diagnostics["max_context_token_count_per_case"].items():
        assert count <= diagnostics["retrieval_contract"][system]["total_context_tokens"]
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


def test_repository_wide_graph_reaches_cross_file_helper_without_lexical_shortcut(
    tmp_path: Path,
):
    for number in range(1, 8):
        class_name = f"BenchmarkTest{number:05d}"
        (tmp_path / f"{class_name}.java").write_text(
            f"""
            class {class_name} {{
                void doGet(Object request, Object response) {{ doPost(request, response); }}
                void doPost(Object request, Object response) {{ int value = 1; }}
            }}
            """,
            encoding="utf-8",
        )
    (tmp_path / "BenchmarkTest99999.java").write_text(
        """
        class BenchmarkTest99999 {
            void doGet(Object request, Object response) { doPost(request, response); }
            void doPost(Object request, Object response) { Shared.run("constant"); }
        }
        """,
        encoding="utf-8",
    )
    (tmp_path / "Shared.java").write_text(
        """
        class Shared {
            static void run(String value) { new ProcessBuilder(value).start(); }
        }
        """,
        encoding="utf-8",
    )

    predictions, diagnostics = predict_owasp_rag(tmp_path)

    assert diagnostics["source_case_count"] == 8
    assert diagnostics["corpus_source_file_count"] == 9
    assert diagnostics["corpus_method_document_count"] == 17
    assert predictions["V1"]["BenchmarkTest99999"] == "ABSTAIN"
    assert predictions["V2"]["BenchmarkTest99999"] == "ABSTAIN"
    assert predictions["V3"]["BenchmarkTest99999"] == "VULNERABLE"


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
