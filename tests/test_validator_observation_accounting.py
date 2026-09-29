"""Final ballots count original delivered proofs, never citation or manifest copies."""
import pytest

from cv_agent.agents.validator_accounting import account_validator_observations
from cv_agent.domain.chat import ModelUsage
from cv_agent.domain.evidence import ReActStep, ValidationStatus
from cv_agent.domain.review import AgentExpertVote, ValidationPlan, ValidationSubtask, ValidationTaskExecution
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolRegistry
from cv_agent.tools.validation.registry import full_agent_tools
from test_bounded_witness_tool import _inputs, _call


def _physical(tmp_path):
    index, candidate, context, _ = _inputs(tmp_path / "checkout")
    registry = ToolRegistry(full_agent_tools(index, witness_contexts={candidate.repository_id: context},
        witness_nonce_factory=lambda: "ACCOUNTING12345678"), max_output_bytes=100000)
    call, observation, _ = _call(registry, index, candidate)
    assert observation.validation_status == ValidationStatus.CONFIRMED, observation.content
    step = ReActStep(step=1, model_id="offline", tool_call=call, observation=observation)
    return index, candidate, registry, step


def _vote(expert, trace, references, *, label="VULNERABLE", supporting=None, unresolved=()):
    return AgentExpertVote(expert=expert, label=label, confidence=.9,
        validation_status=ValidationStatus.CONFIRMED if label == "VULNERABLE" else ValidationStatus.UNRESOLVED,
        evidence_ids=tuple(references), supporting_observation_ids=tuple(references if supporting is None else supporting),
        unresolved_observation_ids=unresolved, rationale="Use only the original delivered proof.",
        runtime_mode="scripted", trace=tuple(trace), model_ids=("offline",), model_calls=2, tool_calls=max(1,len(trace)),
        tool_observation_token_count=0, usage=ModelUsage(input_tokens=0,output_tokens=0,total_tokens=0))


def _plan():
    return ValidationPlan(candidate_id="neutral-candidate", vulnerability_hypotheses=("command property",),
        rationale="A producer and its evidence consumer.", subtasks=(
            ValidationSubtask(task_id="producer",expert="scan",allowed_validator="run_bounded_execution_witness",
                objective="Produce a bounded witness.",success_condition="Observe its complete result."),
            ValidationSubtask(task_id="consumer",expert="taint",allowed_validator="inspect_command_construction",
                dependencies=("producer",),objective="Interpret the dependency.",success_condition="Inspect construction.")))


def test_two_final_experts_share_one_real_original_proof_with_aliases(tmp_path):
    index, candidate, _, step = _physical(tmp_path)
    scan = _vote("scan",(step,),(step.observation.citation_id,))
    # This consumer trace does not duplicate the original producer observation.
    taint = _vote("taint",(),(step.observation.evidence_ids[0],))
    executions=(ValidationTaskExecution(task_id="producer",vote=scan,validator_completed=True),
                ValidationTaskExecution(task_id="consumer",vote=taint,validator_completed=True))
    result = account_validator_observations((scan,taint),executions,candidate_subject(index,candidate),_plan())
    assert result.material_votes_sharing_validator_observation == 2
    assert result.independent_validator_observations == 1
    assert result.origins[0]["producer_execution_ordinal"] == 1
    assert result.origins[0]["producer_step_ordinal"] == 1
    assert result.origins[0]["material_experts"] == ("scan","taint")


def test_same_manifest_two_real_executions_are_two_origins_not_three_cumulative_copies(tmp_path):
    index, candidate, registry, first = _physical(tmp_path)
    call, observation, _ = _call(registry,index,candidate)
    assert observation.metadata["manifest_sha256"] == first.observation.metadata["manifest_sha256"]
    observation = observation.model_copy(update={"citation_id":"scan/tool:2"})
    second = ReActStep(step=2,model_id="offline",tool_call=call,observation=observation)
    one = _vote("scan",(first,),(first.observation.citation_id,))
    two = _vote("scan",(second,),(observation.citation_id,))
    aggregate = two.model_copy(update={"trace":(first,second), "evidence_ids":(first.observation.citation_id,observation.citation_id),
                                     "supporting_observation_ids":(first.observation.citation_id,observation.citation_id)})
    executions=(ValidationTaskExecution(task_id="first",vote=one),ValidationTaskExecution(task_id="second",vote=two))
    result=account_validator_observations((aggregate,),executions,candidate_subject(index,candidate))
    assert result.material_votes_sharing_validator_observation == 0
    assert result.independent_validator_observations == 2
    assert [origin["producer_execution_ordinal"] for origin in result.origins] == [1,2]


@pytest.mark.parametrize("failure",["error","clipped","suppressed","unresolved","preparation"])
def test_undelivered_or_unresolved_receipts_never_count_as_proofs(tmp_path,failure):
    index,candidate,_,step=_physical(tmp_path)
    observation=step.observation
    update={}
    if failure=="error": update={"status":"error", "validation_status":None,"fixture_proof":None,
                                "metadata":{**observation.metadata,"producer_completed":True,"witness_result_status":"CONFIRMED"}}
    elif failure=="clipped": update={"metadata":{**observation.metadata,"observation_truncated":True}}
    elif failure=="suppressed": update={"metadata":{**observation.metadata,"model_payload_suppressed":True}}
    elif failure=="unresolved": update={"validation_status":ValidationStatus.UNRESOLVED}
    else: update={"validation_status":ValidationStatus.UNRESOLVED,"fixture_proof":None,
                  "metadata":{**observation.metadata,"witness_attempted":False}}
    changed=step.model_copy(update={"observation":observation.model_copy(update=update)})
    vote=_vote("scan",(changed,),(observation.citation_id,))
    result=account_validator_observations((vote,),(ValidationTaskExecution(task_id="producer",vote=vote),),
                                        candidate_subject(index,candidate))
    assert result.independent_validator_observations == result.material_votes_sharing_validator_observation == 0


def test_superseded_material_ballot_and_unresolved_role_do_not_count(tmp_path):
    index,candidate,_,step=_physical(tmp_path)
    earlier=_vote("scan",(step,),(step.observation.citation_id,))
    last=_vote("scan",(),(),label="ABSTAIN")
    executions=(ValidationTaskExecution(task_id="producer",vote=earlier),ValidationTaskExecution(task_id="last",vote=last))
    result=account_validator_observations((last,),executions,candidate_subject(index,candidate))
    assert result.independent_validator_observations == result.material_votes_sharing_validator_observation == 0
    role=_vote("scan",(step,),(step.observation.citation_id,),supporting=(),unresolved=step.observation.evidence_ids)
    result=account_validator_observations((role,),(ValidationTaskExecution(task_id="producer",vote=role),),
                                        candidate_subject(index,candidate))
    assert result.independent_validator_observations == 0


def test_unrelated_peer_without_dependency_cannot_supply_an_origin(tmp_path):
    index,candidate,_,step=_physical(tmp_path)
    scan=_vote("scan",(step,),(step.observation.citation_id,))
    taint=_vote("taint",(),(step.observation.citation_id,))
    plan=_plan()
    plan=plan.model_copy(update={"subtasks":(plan.subtasks[0],plan.subtasks[1].model_copy(update={"dependencies":()}))})
    executions=(ValidationTaskExecution(task_id="producer",vote=scan),ValidationTaskExecution(task_id="consumer",vote=taint))
    result=account_validator_observations((scan,taint),executions,candidate_subject(index,candidate),plan)
    assert result.independent_validator_observations == 1
    assert result.material_votes_sharing_validator_observation == 0
