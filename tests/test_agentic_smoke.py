from cv_agent.agentic_smoke import run_agentic_smoke


def test_agentic_smoke_is_scripted_non_claim_react_diagnostic():
    result = run_agentic_smoke()

    assert result["harness_id"] == "agentic-vulnerability-system-v1"
    assert result["runtime_mode"] == "scripted"
    assert result["claim_eligible"] is False
    assert result["verdict"]["path"] == "fast"
    assert len(result["verdict"]["votes"]) == 2
    assert all(vote["trace"] for vote in result["verdict"]["votes"])

