from cv_agent.evaluation.smoke import run_agentic_smoke


def test_agentic_smoke_is_scripted_non_claim_react_diagnostic():
    result = run_agentic_smoke()

    assert result["harness_id"] == "agentic-vulnerability-system-v1"
    assert result["runtime_mode"] == "scripted"
    assert result["claim_eligible"] is False
    assert result["verdict"]["path"] == "slow"
    assert len(result["verdict"]["votes"]) == 3
    assert all(vote["trace"] for vote in result["verdict"]["votes"])


    # C1/C5: the scan positive control has an actual bounded witness,
    # unlike the weak command proposals retained in the scripted evaluation.
    scan = result["verdict"]["votes"][0]
    assert scan["validation_status"] == "CONFIRMED"
    proof = scan["trace"][0]["observation"]
    assert proof["tool"] == "probe_python_eval"
    assert proof["validation_status"] == "CONFIRMED"
    assert proof["subject"]["property_id"] == "dynamic-evaluation"

    assert result["verdict"]["label"] == "ABSTAIN"
    assert result["verdict"]["votes"][1]["label"] == "ABSTAIN"
