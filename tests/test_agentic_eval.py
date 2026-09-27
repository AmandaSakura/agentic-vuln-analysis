from cv_agent.evaluation.scripted import run_agentic_scripted_eval


def test_scripted_weak_evidence_does_not_claim_false_positive_improvement():
    # C1/C5/T16: scripted predictions are not sufficient validation evidence.
    result = run_agentic_scripted_eval()
    assert result["claim_eligible"] is False
    assert result["runtime_mode"] == "scripted"
    for system in result["systems"].values():
        assert set(system["predictions"].values()) == {"ABSTAIN"}
        assert system["confusion"]["coverage"] == 0.0
        assert system["confusion"]["population_false_positive_rate"] == 0.0
        assert system["relative_false_positive_reduction_vs_graph_single"] is None


def test_scripted_weak_votes_cannot_trigger_fast_quorum():
    result = run_agentic_scripted_eval()
    for case in result["systems"]["E5"]["traces"].values():
        assert case["label"] == "ABSTAIN"
        assert case["path"] == "slow"
        assert [vote["expert"] for vote in case["votes"]] == ["scan", "taint", "authz"]
        assert all(vote["label"] == "ABSTAIN" for vote in case["votes"])
    # The attempted material vote consumed a correction request; it was not
    # silently rewritten into a pre-scripted abstention before admission.
    assert result["systems"]["E3"]["traces"]["cross-file-1"]["model_calls"] == 3
