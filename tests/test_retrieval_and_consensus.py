from __future__ import annotations

import hashlib
import json

import pytest

from cv_agent.agents.voting import QuorumPolicy
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentSystemVersion, RetrievalBudget, RetrievalMode
from cv_agent.retrieval import RepositoryIndex
from cv_agent.baselines.synthetic import cross_file_fixture, guarded_delete_fixture
from cv_agent.domain.types import Candidate, CodeDocument, ExpertVote, SystemVersion
from cv_agent.baselines.workflow import AgentPipeline, PipelineConfig
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.evaluation.datasets.composition import load_advisory_config
from cv_agent.evaluation.datasets.advisory_source import build_pair_input
from cv_agent.runtime.paths import PROJECT_ROOT
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.validation.commands import command_construction
from cv_agent.tools.validation.models import CommandConstructionInput


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


def test_both_direction_graph_keeps_forward_command_helper_chain():
    candidate_doc = CodeDocument(
        repository_id="repo",
        path="backend.py::serve@1-5",
        text=(
            "def serve(model_uri):\n"
            "    local_path = _download_artifact_from_uri(model_uri)\n"
            "    command, _ = get_cmd(local_path)\n"
            "    return subprocess.Popen(['bash', '-c', command])\n"
        ),
        defines=("serve",),
        calls=("_download_artifact_from_uri", "get_cmd", "subprocess.Popen"),
    )
    download = CodeDocument(
        repository_id="repo",
        path="artifact_utils.py::_download_artifact_from_uri@1-3",
        text=(
            "def _download_artifact_from_uri(uri):\n"
            "    root, path = _get_root_uri_and_artifact_path(uri)\n"
            "    return path\n"
        ),
        defines=("_download_artifact_from_uri",),
        calls=("_get_root_uri_and_artifact_path",),
    )
    required = CodeDocument(
        repository_id="repo",
        path="artifact_utils.py::_get_root_uri_and_artifact_path@5-7",
        text="def _get_root_uri_and_artifact_path(uri):\n    return uri, uri\n",
        defines=("_get_root_uri_and_artifact_path",),
    )
    noise = [
        CodeDocument(
            repository_id="repo",
            path=f"noise.py::noisy_caller_{index}@1-20",
            text=(
                "def noisy_caller(uri):\n"
                "    # mlflow command injection backend pyfunc model server " * 40
                + "\n    return _download_artifact_from_uri(uri)\n"
            ),
            defines=(f"noisy_caller_{index}",),
            calls=("_download_artifact_from_uri",),
        )
        for index in range(8)
    ]
    candidate = Candidate(
        candidate_id="serve",
        case_id="serve",
        repository_id="repo",
        path=candidate_doc.path,
        line=1,
        query="mlflow command injection backend pyfunc model server",
    )
    evidence = RepositoryIndex([candidate_doc, download, required, *noise]).retrieve_context(
        candidate,
        mode=RetrievalMode.GRAPH,
        budget=RetrievalBudget(
            top_k=2,
            base_context_tokens=512,
            augmentation_context_tokens=2048,
            graph_hops=4,
            graph_direction="both",
            graph_ranking="distance",
        ),
    )

    assert [item.path for item in evidence] == [
        candidate_doc.path,
        download.path,
        required.path,
    ]


def test_source_resolved_same_file_callee_precedes_lexical_noise_without_admitting_decoy():
    entry = CodeDocument(
        repository_id="repo", path="entry.py::serve@1-3",
        text="def serve(uri):\n    return artifact._download(uri)\n",
        defines=("serve",), calls=("pkg.artifact._download",),
        import_aliases={"artifact": "pkg.artifact"},
    )
    download = CodeDocument(
        repository_id="repo", path="artifact.py::_download@1-3",
        text="def _download(uri):\n    return _root(uri)\n",
        defines=("pkg.artifact._download", "_download"), calls=("_root",),
    )
    root = CodeDocument(
        repository_id="repo", path="artifact.py::_root@5-6",
        text="def _root(uri):\n    return uri\n", defines=("_root",),
    )
    decoy = CodeDocument(
        repository_id="repo", path="decoy.py::_root@1-2",
        text="def _root(uri):\n    return 'decoy'\n", defines=("_root",),
    )
    noise = CodeDocument(
        repository_id="repo", path="noise.py::caller@1-2",
        text="def caller(uri):\n    return artifact._download(uri)\n" + "injection shell " * 80,
        defines=("caller",), calls=("pkg.artifact._download",),
    )
    index = RepositoryIndex([entry, download, root, decoy, noise])
    candidate = Candidate(
        candidate_id="serve", case_id="serve", repository_id="repo",
        path=entry.path, line=1, query="injection shell",
    )
    budget = RetrievalBudget(
        top_k=2, base_context_tokens=512, augmentation_context_tokens=2048,
        graph_hops=2, graph_direction="both", graph_ranking="distance",
    )
    evidence, records = index.retrieve_context_with_admission(
        candidate, mode=RetrievalMode.GRAPH, budget=budget,
    )
    paths = {item.path for item in evidence}
    assert paths == {entry.path, download.path, root.path}
    assert decoy.path not in paths
    root_record = next(record for record in records if record["path"] == root.path)
    assert root_record["status"] == "admitted"
    assert root_record["bound_call_source"] == download.path
    assert root_record["call_symbol"] == "_root"
    assert root_record["graph_distance"] == 2
    assert root_record["document_sha256"] == hashlib.sha256(root.text.encode()).hexdigest()

    one_slot = budget.model_copy(update={"top_k": 1})
    smaller, smaller_records = index.retrieve_context_with_admission(
        candidate, mode=RetrievalMode.GRAPH, budget=one_slot,
    )
    assert [item.path for item in smaller] == [entry.path, download.path]
    assert all(record["status"] == "admitted" for record in smaller_records if record["path"] == download.path)


def test_parameter_shadowed_same_name_definition_is_not_admitted():
    caller = CodeDocument(
        repository_id="repo", path="module.py::entry@1-2",
        text="def entry(_root):\n    return _root('x')\n",
        defines=("entry",), calls=("_root",), adapter_tier="ast",
    )
    unrelated = CodeDocument(
        repository_id="repo", path="module.py::_root@4-5",
        text="def _root(uri):\n    return uri\n",
        defines=("_root",), adapter_tier="ast",
    )
    index = RepositoryIndex([caller, unrelated])
    candidate = Candidate(
        candidate_id="entry", case_id="entry", repository_id="repo",
        path=caller.path, line=1, query="_root",
    )
    evidence, records = index.retrieve_context_with_admission(
        candidate, mode=RetrievalMode.GRAPH,
        budget=RetrievalBudget(
            top_k=1, base_context_tokens=512,
            augmentation_context_tokens=512, graph_hops=1,
        ),
    )
    assert [item.path for item in evidence] == [caller.path]
    assert any(
        record["path"] == unrelated.path
        and record["status"] == "skipped"
        and record["reason"] == "unbound_bare_call"
        for record in records
    )


@pytest.mark.parametrize("case_id", ["hp003_a", "hp003_b"])
def test_hp003_root_helper_is_admitted_but_does_not_automatically_prove_v_or_s(case_id):
    config = load_advisory_config(PROJECT_ROOT, "configs/profiles/advisory_matrix_v4.json")
    pair = next(pair for pair in config.pairs if pair.pair_id.startswith("hp003_"))
    case = next(case for case in pair.cases if case.case_id == case_id)
    index, candidate, _ = build_pair_input(PROJECT_ROOT, pair, case)
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)
    budget = spec.budget.model_copy(update={
        "graph_direction": config.graph_direction,
        "graph_ranking": config.graph_ranking,
    })
    observed_events: list[dict] = []
    pipeline = object.__new__(AgenticPipeline)
    pipeline.index = index
    pipeline.system_spec = spec.model_copy(update={"budget": budget})
    pipeline.retrieval_observer = observed_events.append
    state = pipeline._retrieve({"candidate": candidate})
    root_records = [
        item for item in state["admission_records"]
        if "::_get_root_uri_and_artifact_path@64-97" in item.path
    ]
    assert len(root_records) == 1
    assert root_records[0].status == "admitted"
    assert root_records[0].serialized_token_cost > 0
    assert len(state["evidence"]) <= budget.top_k + 1
    assert state["context_token_count"] <= budget.total_context_tokens
    assert observed_events[0]["event"] == "retrieval_admission"
    assert observed_events[0]["subject_digest"] == state["admission_subject_digest"]
    assert observed_events[0]["admission_records"] == [
        item.model_dump(mode="json") for item in state["admission_records"]
    ]

    scope = ToolExecutionScope(
        candidate_path=candidate.path,
        admitted_paths=frozenset(item.path for item in state["evidence"]),
        subject=candidate_subject(index, candidate),
        max_observation_tokens=8192,
    )
    observation = command_construction(
        index, CommandConstructionInput(source_path=candidate.path, max_hops=4), scope,
    )
    result = json.loads(observation.content)
    assert result["command_construction_status"] == "AMBIGUOUS"
    assert observation.validation_status.value == "UNRESOLVED"


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


def test_early_exit_matches_full_review_across_labels_and_confidence_values():
    from itertools import product

    states = tuple(product(("VULNERABLE", "SAFE", "ABSTAIN"), (0.1, 0.79, 0.80, 1.0)))
    saw_low_confidence_fast = False
    for combination in product(states, repeat=3):
        votes = [
            ExpertVote(expert=role, label=label, confidence=confidence, rationale="counterfactual")
            for role, (label, confidence) in zip(("scan", "taint", "authz"), combination)
        ]
        early = QuorumPolicy().try_fast(votes[:2])
        if early is not None:
            assert early.label == QuorumPolicy(fast_enabled=False).decide(votes).label
            if max(vote.confidence for vote in votes[:2]) < 0.80:
                saw_low_confidence_fast = True
    assert saw_low_confidence_fast
