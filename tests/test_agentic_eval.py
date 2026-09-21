from cv_agent.agentic_eval import run_agentic_scripted_eval


def test_scripted_agentic_eval_reduces_false_positives_vs_graph_single():
    result = run_agentic_scripted_eval()

    assert result["claim_eligible"] is False
    assert result["runtime_mode"] == "scripted"
    systems = result["systems"]
    graph_single = systems["E3"]["confusion"]
    graph_multi = systems["E4"]["confusion"]
    graph_fast = systems["E5"]["confusion"]

    assert graph_single["population_false_positive_rate"] == 1.0
    assert graph_multi["population_false_positive_rate"] == 0.0
    assert graph_fast["population_false_positive_rate"] == 0.0
    assert systems["E4"]["relative_false_positive_reduction_vs_graph_single"] == 1.0
    assert systems["E5"]["relative_false_positive_reduction_vs_graph_single"] == 1.0


def test_scripted_agentic_eval_exercises_fast_and_slow_quorum_paths():
    result = run_agentic_scripted_eval()
    e5_traces = result["systems"]["E5"]["traces"]

    assert e5_traces["cross-file-1"]["label"] == "VULNERABLE"
    assert e5_traces["cross-file-1"]["path"] == "fast"
    assert [vote["expert"] for vote in e5_traces["cross-file-1"]["votes"]] == [
        "scan",
        "taint",
    ]

    assert e5_traces["guarded-delete-1"]["label"] == "ABSTAIN"
    assert e5_traces["guarded-delete-1"]["path"] == "slow"
    assert [vote["expert"] for vote in e5_traces["guarded-delete-1"]["votes"]] == [
        "scan",
        "taint",
        "authz",
    ]
