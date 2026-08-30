from __future__ import annotations

from cv_agent.consensus import QuorumPolicy
from cv_agent.retrieval import RepositoryIndex
from cv_agent.synthetic import cross_file_fixture, guarded_delete_fixture
from cv_agent.types import Candidate, CodeDocument, ExpertVote, SystemVersion
from cv_agent.workflow import AgentPipeline, PipelineConfig


def test_graph_retrieval_recovers_cross_file_sink():
    index, candidate = cross_file_fixture()
    local = AgentPipeline(index, PipelineConfig(system=SystemVersion.V1_LOCAL_SINGLE)).run(candidate)
    text = AgentPipeline(index, PipelineConfig(system=SystemVersion.V2_TEXT_SINGLE)).run(candidate)
    graph = AgentPipeline(index, PipelineConfig(system=SystemVersion.V3_GRAPH_SINGLE)).run(candidate)
    assert local.label == "ABSTAIN"
    assert text.label == "ABSTAIN"
    assert graph.label == "VULNERABLE"
    assert "graph:service.py" in graph.votes[0].evidence_ids


def test_pure_graph_does_not_use_a_disconnected_lexical_seed():
    documents = [
        CodeDocument(repository_id="repo", path="entry.py", text="def entry(): pass", defines=("entry",)),
        CodeDocument(
            repository_id="repo",
            path="disconnected.py",
            text="def target(): eval(user_input)",
            defines=("target",),
        ),
    ]
    candidate = Candidate(
        candidate_id="entry",
        case_id="entry",
        repository_id="repo",
        path="entry.py",
        line=1,
        query="target eval user_input",
    )
    index = RepositoryIndex(documents)
    assert [item.path for item in index.graph_search(candidate)] == ["entry.py"]
    assert "disconnected.py" in {item.path for item in index.hybrid_search(candidate)}


def test_call_graph_is_forward_directed():
    documents = [
        CodeDocument(
            repository_id="repo",
            path="caller.py",
            text="def caller(): return callee()",
            defines=("caller",),
            calls=("callee",),
        ),
        CodeDocument(
            repository_id="repo",
            path="callee.py",
            text="def callee(): return 1",
            defines=("callee",),
        ),
    ]
    index = RepositoryIndex(documents)
    caller = Candidate(
        candidate_id="caller",
        case_id="caller",
        repository_id="repo",
        path="caller.py",
        line=1,
        query="callee",
    )
    callee = caller.model_copy(update={"candidate_id": "callee", "path": "callee.py"})
    assert "callee.py" in {item.path for item in index.graph_search(caller)}
    assert "caller.py" not in {item.path for item in index.graph_search(callee)}
    assert "caller.py" in {
        item.path for item in index.graph_search(callee, direction="reverse")
    }


def test_ambiguous_bare_symbol_does_not_create_shortcuts():
    documents = [
        CodeDocument(
            repository_id="repo",
            path="caller.py",
            text="def caller(): run()",
            defines=("caller",),
            calls=("run",),
        ),
        CodeDocument(repository_id="repo", path="one.py", text="def run(): pass", defines=("run",)),
        CodeDocument(repository_id="repo", path="two.py", text="def run(): pass", defines=("run",)),
    ]
    candidate = Candidate(
        candidate_id="caller",
        case_id="caller",
        repository_id="repo",
        path="caller.py",
        line=1,
        query="run",
    )
    assert [item.path for item in RepositoryIndex(documents).graph_search(candidate)] == [
        "caller.py"
    ]


def test_fast_path_skips_third_expert_without_changing_label():
    document = CodeDocument(
        repository_id="repo",
        path="handler.py",
        text=(
            "def handle(request):\n"
            "    value = request.args['cmd']\n"
            "    return subprocess.run(value, shell=True)\n"
        ),
        defines=("handle",),
    )
    candidate = Candidate(
        candidate_id="handler",
        case_id="handler",
        repository_id="repo",
        path="handler.py",
        line=1,
        query="handle request",
    )
    index = RepositoryIndex([document])
    slow = AgentPipeline(index, PipelineConfig(system=SystemVersion.V4_GRAPH_MULTI)).run(candidate)
    fast = AgentPipeline(index, PipelineConfig(system=SystemVersion.V5_GRAPH_FAST_SLOW)).run(candidate)
    assert slow.label == fast.label == "VULNERABLE"
    assert slow.path == "slow"
    assert fast.path == "fast"
    assert len(slow.votes) == 3
    assert len(fast.votes) == 2


def test_guarded_disagreement_abstains_instead_of_claiming_safety():
    index, candidate = guarded_delete_fixture()
    single = AgentPipeline(index, PipelineConfig(system=SystemVersion.V3_GRAPH_SINGLE)).run(candidate)
    ensemble = AgentPipeline(index, PipelineConfig(system=SystemVersion.V5_GRAPH_FAST_SLOW)).run(candidate)
    assert single.label == "VULNERABLE"
    assert ensemble.label == "ABSTAIN"
    assert ensemble.path == "slow"
    assert len(ensemble.votes) == 3


def test_slow_policy_requires_two_material_votes():
    vote = ExpertVote(
        expert="scan",
        label="VULNERABLE",
        confidence=0.9,
        rationale="sink",
    )
    verdict = QuorumPolicy(fast_enabled=False).decide([vote])
    assert verdict.label == "ABSTAIN"
    assert verdict.path == "slow"


def test_early_quorum_matches_full_three_vote_majority():
    votes = [
        ExpertVote(expert="scan", label="VULNERABLE", confidence=0.9, rationale="sink"),
        ExpertVote(expert="taint", label="VULNERABLE", confidence=0.9, rationale="flow"),
        ExpertVote(expert="authz", label="SAFE", confidence=0.99, rationale="guard"),
    ]
    early = QuorumPolicy().try_fast(votes[:2])
    full = QuorumPolicy(fast_enabled=False).decide(votes)
    assert early is not None
    assert early.label == full.label == "VULNERABLE"
