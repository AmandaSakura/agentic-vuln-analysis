from __future__ import annotations

from cv_agent.agents.voting import QuorumPolicy
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentSystemVersion
from cv_agent.retrieval import RepositoryIndex
from cv_agent.baselines.synthetic import cross_file_fixture, guarded_delete_fixture
from cv_agent.domain.types import Candidate, CodeDocument, ExpertVote, SystemVersion
from cv_agent.baselines.workflow import AgentPipeline, PipelineConfig


def test_one_expert_cannot_form_a_quorum_with_duplicate_ballots():
    import pytest
    vote = ExpertVote(expert='scan', label='VULNERABLE', confidence=0.95, rationale='one check')
    for policy in (QuorumPolicy(), QuorumPolicy(fast_enabled=False)):
        with pytest.raises(ValueError, match='Duplicate expert'):
            policy.decide([vote, vote])
    with pytest.raises(ValueError, match='Duplicate expert'):
        QuorumPolicy().try_fast([vote, vote])


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


def test_text_search_prioritizes_explicit_path_queries():
    target = CodeDocument(
        repository_id="repo",
        path="src/backend/base/langflow/api/v1/api_key.py::delete_api_key@1-4",
        text="def delete_api_key():\n    return service.delete_api_key()\n",
        defines=("delete_api_key",),
    )
    noisy = CodeDocument(
        repository_id="repo",
        path="src/backend/base/langflow/__main__.py::<module>@1-120",
        text="\n".join("api key delete service" for _ in range(120)),
    )
    index = RepositoryIndex([noisy, target])

    assert index.text_search("api_key.py", top_k=1)[0].path == target.path


def test_text_search_boosts_explicit_filename_over_large_common_module():
    target = CodeDocument(
        repository_id="repo",
        path="mlflow/pyfunc/mlserver.py::get_cmd@1-4",
        text="def get_cmd(model_uri):\n    return model_uri\n",
        defines=("get_cmd",),
    )
    noisy = CodeDocument(
        repository_id="repo",
        path="mlflow/pyfunc/__init__.py::<module>@1-400",
        text="\n".join("model serving command model_uri backend pyfunc" for _ in range(400)),
    )
    index = RepositoryIndex([noisy, target])

    assert index.text_search("MLflow command injection mlserver.py model_uri", top_k=1)[0].path == target.path


def test_text_retrieval_keeps_get_cmd_helper_in_initial_command_context():
    candidate_doc = CodeDocument(
        repository_id="repo",
        path="mlflow/pyfunc/backend.py::PyFuncBackend.serve@1-20",
        text=(
            "def serve(model_uri):\n"
            "    command, command_env = mlserver.get_cmd(model_uri)\n"
            "    command = 'exec ' + command\n"
            "    return subprocess.Popen(['bash', '-c', command])\n"
        ),
        defines=("PyFuncBackend.serve",),
    )
    helper = CodeDocument(
        repository_id="repo",
        path="mlflow/pyfunc/mlserver.py::get_cmd@1-5",
        text=(
            "def get_cmd(model_uri):\n"
            "    cmd = f\"mlserver start {model_uri}\"\n"
            "    return cmd, {}\n"
        ),
        defines=("get_cmd", "mlflow.pyfunc.mlserver.get_cmd"),
    )
    noisy = [
        CodeDocument(
            repository_id="repo",
            path=f"mlflow/pyfunc/backend.py::noise_{index}@1-20",
            text="\n".join(
                "backend pyfunc serve command model_uri MLflow injection"
                for _ in range(20)
            ),
        )
        for index in range(12)
    ]
    candidate = Candidate(
        candidate_id="serve",
        case_id="serve",
        repository_id="repo",
        path=candidate_doc.path,
        line=1,
        query=(
            "MLflow command injection mlserver.py model_uri "
            "mlflow/pyfunc/backend.py subprocess.Popen"
        ),
    )
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E2_TEXT_SINGLE)
    evidence = RepositoryIndex([candidate_doc, *noisy, helper]).retrieve_context(
        candidate,
        mode=spec.retrieval,
        budget=spec.budget,
    )

    assert [item.path for item in evidence[:2]] == [candidate_doc.path, helper.path]


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
    assert ensemble.votes[-1].expert == "authz"


def test_injection_refutation_forms_a_real_safe_quorum():
    document = CodeDocument(
        repository_id="repo",
        path="handler.java",
        text=(
            'String param = request.getHeader("vector");\n'
            "int num = 106;\n"
            'String bar = (7*18) + num > 200 ? "safe" : param;\n'
            'String sql = "SELECT " + bar;\n'
            "statement.execute(sql);\n"
        ),
        defines=("handler",),
    )
    candidate = Candidate(
        candidate_id="handler",
        case_id="handler",
        repository_id="repo",
        path="handler.java",
        line=1,
        query="handler",
    )
    index = RepositoryIndex([document])

    single = AgentPipeline(index, PipelineConfig(system=SystemVersion.V3_GRAPH_SINGLE)).run(candidate)
    ensemble = AgentPipeline(index, PipelineConfig(system=SystemVersion.V4_GRAPH_MULTI)).run(candidate)

    assert single.label == "VULNERABLE"
    assert ensemble.label == "SAFE"
    assert [vote.expert for vote in ensemble.votes] == ["scan", "taint", "flow"]


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


def test_slow_policy_requires_quorum_even_for_unopposed_typed_validator_vote():
    votes = [
        ExpertVote(
            expert="scan",
            label="ABSTAIN",
            confidence=0.5,
            validation_status="UNRESOLVED",
            rationale="sink candidate only",
        ),
        ExpertVote(
            expert="taint",
            label="VULNERABLE",
            confidence=1.0,
            validation_status="CONFIRMED",
            rationale="confirmed source-to-sink trace",
        ),
        ExpertVote(
            expert="authz",
            label="ABSTAIN",
            confidence=0.99,
            validation_status="UNRESOLVED",
            rationale="outside authorization semantics",
        ),
    ]
    verdict = QuorumPolicy(fast_enabled=False).decide(votes)
    assert verdict.label == "ABSTAIN"
    assert verdict.path == "slow"
    assert "Fewer than 2" in verdict.rationale


def test_confirmed_vote_cannot_override_conflict_below_configured_quorum():
    votes = [
        ExpertVote(
            expert="taint", label="VULNERABLE", confidence=1.0,
            validation_status="CONFIRMED", rationale="static taint trace",
        ),
        ExpertVote(
            expert="scan", label="SAFE", confidence=0.9,
            validation_status="UNRESOLVED", rationale="conflicting code evidence",
        ),
    ]
    verdict = QuorumPolicy(fast_enabled=False, quorum=3).decide(votes)
    assert verdict.label == "ABSTAIN"


def test_slow_policy_does_not_accept_unresolved_single_material_vote():
    votes = [
        ExpertVote(
            expert="scan",
            label="ABSTAIN",
            confidence=0.5,
            validation_status="UNRESOLVED",
            rationale="sink candidate only",
        ),
        ExpertVote(
            expert="taint",
            label="SAFE",
            confidence=0.98,
            validation_status="UNRESOLVED",
            rationale="model inferred argument mapping but validator was unresolved",
        ),
        ExpertVote(
            expert="authz",
            label="ABSTAIN",
            confidence=0.99,
            validation_status="UNRESOLVED",
            rationale="outside authorization semantics",
        ),
    ]
    verdict = QuorumPolicy(fast_enabled=False).decide(votes)
    assert verdict.label == "ABSTAIN"


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


def test_early_exit_matches_full_review_across_labels_and_confidence_threshold():
    from itertools import product

    states = tuple(product(("VULNERABLE", "SAFE", "ABSTAIN"), (0.79, 0.80, 1.0)))
    for combination in product(states, repeat=3):
        votes = [
            ExpertVote(expert=role, label=label, confidence=confidence, rationale="counterfactual")
            for role, (label, confidence) in zip(("scan", "taint", "authz"), combination)
        ]
        early = QuorumPolicy().try_fast(votes[:2])
        if early is not None:
            assert early.label == QuorumPolicy(fast_enabled=False).decide(votes).label
