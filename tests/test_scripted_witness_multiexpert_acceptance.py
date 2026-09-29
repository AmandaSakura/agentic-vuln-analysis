"""Real synthetic workers feed ordinary E4 admission and fixed E5 ballots."""
from dataclasses import replace

import pytest

from cv_agent.evaluation.diagnostics.scripted_witness_multiexpert_acceptance import run_scripted_multiexpert_candidate
from cv_agent.harness import FULL_SYSTEM_HARNESS
from test_witness_protocol_continuation import _inputs, _complete


@pytest.mark.parametrize("quoted",[False,True])
def test_actual_e4_dependencies_and_budgets_share_one_witness(tmp_path,quoted):
    index,candidate,context=_inputs(tmp_path,quoted=quoted)
    context=replace(context,response_mode="compact")
    result=run_scripted_multiexpert_candidate(index,candidate,context,scenario_hypothesis=_complete(),nonce="MULTI12345678")
    verdict=result["verdict"]
    assert verdict["label"]==("ABSTAIN" if quoted else "VULNERABLE"),result
    assert verdict["path"]=="slow"
    assert [execution["task_id"] for execution in verdict["task_executions"]]==[
        "witness","construction-scan","construction-taint",None]
    assert all(execution["validator_completed"] for execution in verdict["task_executions"])
    assert result["executed_witness_attempts"]==1
    assert result["live_model_requests"]==0
    scan_scopes=[scope for scope in result["scopes"] if scope["role"]=="scan"]
    assert scan_scopes[0]["max_observation_tokens"]==4096
    assert scan_scopes[1]["max_observation_tokens"]==8192
    assert result["witness_attempts"][0]["observation_token_count"]<=1000
    assert result["witness_attempts"][0]["observation_truncated"] is False
    votes={vote["expert"]:vote for vote in verdict["votes"]}
    assert votes["authz"]["label"]=="ABSTAIN"
    assert votes["taint"]["label"]==("ABSTAIN" if quoted else "VULNERABLE")
    assert verdict["material_votes_sharing_validator_observation"]==(0 if quoted else 2)
    assert verdict["independent_validator_observations"]==(0 if quoted else 1)
    assert result["e5_fixed_ballot_replay"]["label_equivalent"] is True
    assert result["e5_additional_witness_executions"]==0
    taint_tools=result["requests"]["taint"][0]["tools"]
    assert "run_bounded_execution_witness" not in {tool["function"]["name"] for tool in taint_tools}
    assert TOOL not in next(expert for expert in FULL_SYSTEM_HARNESS.experts if expert.expert=="taint").tools
    assert "SAFE" not in {vote["label"] for vote in verdict["votes"]}


TOOL="run_bounded_execution_witness"


def test_inherited_literal_cannot_become_safe_in_taint(tmp_path):
    index,candidate,context=_inputs(tmp_path,quoted=True)
    result=run_scripted_multiexpert_candidate(index,candidate,replace(context,response_mode="compact"),
        scenario_hypothesis=_complete(),nonce="LITERALMULTI123",attempt_literal_safe=True)
    assert result["literal_safe_proposed"] is True
    assert result["verdict"]["label"]=="ABSTAIN"
    taint=next(vote for vote in result["verdict"]["votes"] if vote["expert"]=="taint")
    assert taint["label"]=="ABSTAIN"
    messages=[message["content"] for request in result["requests"]["taint"] for message in request["messages"]
              if message["content"] is not None]
    assert any("Validation error:" in message for message in messages)
    assert result["executed_witness_attempts"]==1
