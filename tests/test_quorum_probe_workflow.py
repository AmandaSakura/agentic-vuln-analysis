import pytest

from cv_agent.harness import AgentSystemVersion
from cv_agent.evaluation.quorum_probe import run_probe_case


@pytest.mark.parametrize("case", ["C01", "C02"])
def test_weak_eval_flow_cannot_complete_quorum(case):
    # C1/C5/T16: the former fast positive borrowed a MAY_REACH-only ballot.
    full, _ = run_probe_case(case, AgentSystemVersion.E4_GRAPH_MULTI)
    fast, models = run_probe_case(case, AgentSystemVersion.E5_GRAPH_FAST)
    assert full.label == fast.label == "ABSTAIN"
    assert full.path == fast.path == "slow"
    assert full.model_calls == fast.model_calls
    assert full.tool_calls == fast.tool_calls
    assert len(fast.votes) == 3
    assert models["authz"].requests
    assert fast.runtime_mode.value == "scripted"
    for role in ("scan", "taint"):
        assert "Completed dependencies and prior own tasks: []" in models[role].requests[0][0][1].content
    planner_prompt = models["planner"].requests[0][0][1].content
    assert "probe_python_eval" in planner_prompt
    assert "verification_guidance" in planner_prompt
    scan, taint, _ = fast.votes
    assert taint.label == "ABSTAIN"
    if case == "C01":
        # The concrete witness remains valid; only the unsupported second vote is lost.
        assert scan.label == "VULNERABLE"
        assert scan.validation_status.value == "CONFIRMED"
        assert len(models["taint"].requests) == 3
        correction = models["taint"].requests[-1][0]
        assert any(message.role == "assistant" and '"VULNERABLE"' in (message.content or "")
                   for message in correction)
        assert "matching cited proof" in correction[-1].content
    else:
        assert all(vote.label == "ABSTAIN" for vote in fast.votes)


@pytest.mark.parametrize("label", ["VULNERABLE", "SAFE"])
@pytest.mark.parametrize("claimed_status", ["UNRESOLVED", "CONFIRMED", "REFUTED"])
def test_eval_may_flow_cannot_supply_material_vote(label, claimed_status):
    """C1/C5/T16: a real flow observation cannot become an eval proof by voting."""
    from cv_agent.agents.evidence_policy import InsufficientEvidenceError, validate_conclusion
    from cv_agent.domain.review import AgentExpertConclusion

    verdict, _ = run_probe_case("C01", AgentSystemVersion.E4_GRAPH_MULTI)
    scan, taint = verdict.votes[:2]
    observation = taint.trace[0].observation
    subject = scan.trace[0].observation.subject
    assert observation.tool == "trace_dataflow"
    import json
    assert json.loads(observation.content)["flow_status"] == "MAY_REACH"
    proposal = AgentExpertConclusion(
        expert="taint", label=label, validation_status=claimed_status, confidence=.9,
        evidence_ids=(observation.citation_id,), rationale="Static flow only.",
    )
    with pytest.raises(InsufficientEvidenceError, match="matching cited proof"):
        validate_conclusion(proposal, [taint.trace[0]], frozenset(), subject=subject)
    validate_conclusion(proposal.model_copy(update={"label": "ABSTAIN", "validation_status": "UNRESOLVED"}),
                        [taint.trace[0]], frozenset(), subject=subject)
