"""Final ballots are constrained by all actually delivered matching observations."""
import pytest

from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.domain.chat import ModelToolCall, ModelUsage
from cv_agent.domain.evidence import FixtureProofScope, ReActStep, ToolObservation
from cv_agent.domain.review import AgentExpertVote, ValidationTaskExecution
from cv_agent.domain.types import Candidate, CodeDocument
from cv_agent.harness import AgentSystemVersion
from cv_agent.retrieval import RepositoryIndex
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolRegistry
from cv_agent.tools.validation.registry import full_agent_tools


def setup_review():
    document = CodeDocument(repository_id="owned", path="entry.py", text="def entry():\n    return 42\n")
    index = RepositoryIndex([document])
    item = Candidate(candidate_id="owned-mode", case_id="owned-mode", repository_id="owned",
                     path=document.path, line=1, query="constant", property_id="owned-constant-value",
                     analysis_scope="The selected owned function's bounded constant value.")
    pipeline = AgenticPipeline(index=index, system=AgentSystemVersion.E4_GRAPH_MULTI, models={
        role: ScriptedChatModel([]) for role in ("planner", "scan", "taint", "authz")},
        tools=ToolRegistry(full_agent_tools(index), max_output_bytes=10000))
    return pipeline, item, candidate_subject(index, item)


def recorded_vote(role, subject, status, *, material=True):
    citation = f"{role}/tool:1"
    proof = FixtureProofScope(contract_id="owned-mode-contract", property_id=subject.property_id,
        coverage="candidate", method="complete_static_analysis", supported_statuses=("CONFIRMED", "REFUTED"))
    observation = ToolObservation(tool="run_fixture_test", status="ok", content='{"owned_fixture":true}',
        subject=subject, fixture_proof=proof, validation_status=status, citation_id=citation)
    step = ReActStep(step=1, model_id="scripted-owned", observation=observation,
        tool_call=ModelToolCall(call_id=citation, name="run_fixture_test", arguments={"case_id":"owned"}))
    return AgentExpertVote(expert=role, label=("VULNERABLE" if status == "CONFIRMED" else "SAFE") if material else "ABSTAIN",
        validation_status=status if material else "UNRESOLVED", confidence=.9,
        evidence_ids=(citation,), supporting_observation_ids=(citation,), rationale="A typed owned-fixture observation.",
        runtime_mode="scripted", trace=(step,), model_ids=("scripted-owned",), model_calls=2, tool_calls=1,
        tool_observation_token_count=100, usage=ModelUsage(input_tokens=10,output_tokens=5,total_tokens=15))


def state_for(item, votes):
    return {"candidate":item,"evidence":[],"context_prompt":"","context_token_count":0,
        "admission_records":(),"admission_subject_digest":None,"planner":None,"routing":None,
        "votes":list(votes),"verdict":None,"fast_checked":False,
        "task_executions":[ValidationTaskExecution(task_id=None,vote=vote,validator_completed=True) for vote in votes]}


@pytest.mark.parametrize("reverse", [False, True])
def test_late_matching_negative_proof_invalidates_earlier_material_quorum(reverse):
    pipeline,item,subject=setup_review()
    votes=[recorded_vote("scan",subject,"CONFIRMED"), recorded_vote("taint",subject,"CONFIRMED"),
           recorded_vote("authz",subject,"REFUTED",material=False)]
    if reverse:
        votes.reverse()
    result=pipeline._adjudicate(state_for(item,votes))["verdict"]
    assert result.label == "ABSTAIN"
    assert all(vote.label == "ABSTAIN" for vote in result.votes)
    assert len(result.task_executions) == 3
    assert result.model_calls == 6 and result.tool_calls == 3 and result.usage.total_tokens == 45
    assert any(execution.vote.label == "VULNERABLE" for execution in result.task_executions)


def test_unrelated_subject_does_not_remove_matching_positive_proofs():
    pipeline,item,subject=setup_review()
    unrelated=subject.model_copy(update={"candidate_id":"different-owned-candidate"})
    votes=[recorded_vote("scan",subject,"CONFIRMED"),recorded_vote("taint",subject,"CONFIRMED"),
           recorded_vote("authz",unrelated,"REFUTED",material=False)]
    result=pipeline._adjudicate(state_for(item,votes))["verdict"]
    assert result.label == "VULNERABLE"
    assert result.model_calls == 6 and result.tool_calls == 3


def test_unknown_later_observation_retains_matching_positive_proofs():
    pipeline,item,subject=setup_review()
    votes=[recorded_vote("scan",subject,"CONFIRMED"),recorded_vote("taint",subject,"CONFIRMED"),
           recorded_vote("authz",subject,"UNRESOLVED",material=False)]
    result=pipeline._adjudicate(state_for(item,votes))["verdict"]
    assert result.label == "VULNERABLE"
    assert result.independent_validator_observations == 2


def test_known_conflict_cannot_pass_the_fast_path_either():
    pipeline,item,subject=setup_review()
    votes=[recorded_vote("scan",subject,"CONFIRMED"),recorded_vote("taint",subject,"CONFIRMED"),
           recorded_vote("authz",subject,"REFUTED",material=False)]
    result=pipeline._try_fast(state_for(item,votes))
    assert result["verdict"] is None
