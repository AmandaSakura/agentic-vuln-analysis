import pytest

from cv_agent.harness import AgentSystemVersion
from cv_agent.evaluation.quorum_probe import run_probe_case


@pytest.mark.parametrize("case,label,path,saved_calls", [
    ("C01", "VULNERABLE", "fast", 2),
    ("C02", "ABSTAIN", "slow", 0),
])
def test_distinct_applicable_checks_reach_quorum_without_lowering_threshold(case, label, path, saved_calls):
    full, _ = run_probe_case(case, AgentSystemVersion.E4_GRAPH_MULTI)
    fast, models = run_probe_case(case, AgentSystemVersion.E5_GRAPH_FAST)
    assert full.label == fast.label == label
    assert full.path == "slow"
    assert fast.path == path
    assert full.model_calls - fast.model_calls == saved_calls
    assert full.tool_calls - fast.tool_calls == saved_calls // 2
    assert fast.runtime_mode.value == "scripted"
    assert {vote.trace[0].observation.tool for vote in fast.votes[:2]} == {
        "probe_python_eval", "trace_dataflow",
    }
    assert not set(fast.votes[0].evidence_ids) & set(fast.votes[1].evidence_ids)
    if label == "VULNERABLE":
        assert [vote.validation_status.value for vote in fast.votes] == ["CONFIRMED", "UNRESOLVED"]
        assert not models["authz"].requests
    else:
        assert len(fast.votes) == 3
        assert all(vote.label == "ABSTAIN" for vote in fast.votes)
    # No dependency on peer votes or observations is needed for these checks.
    for role in ("scan", "taint"):
        prompt = models[role].requests[0][0][1].content
        assert "Completed dependencies and prior own tasks: []" in prompt
    planner_prompt = models["planner"].requests[0][0][1].content
    assert "probe_python_eval" in planner_prompt
    assert "verification_guidance" in planner_prompt
