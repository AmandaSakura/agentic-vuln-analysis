import json
from collections import Counter

import pytest

from cv_agent.tools.registry import ToolRegistry
from cv_agent.domain.chat import ModelReply, ModelToolCall
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.harness import AgentSystemVersion, FULL_SYSTEM_HARNESS
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import Candidate, CodeDocument, Evidence
from cv_agent.tools.validation import FixtureCase, FixtureOutcome, full_agent_tools
from cv_agent.domain.review import ValidationPlan


PATH = "entry.py"
VALIDATORS = {
    "scan": ("run_static_check", "path"),
    "taint": ("trace_dataflow", "source_path"),
    "authz": ("compare_route_and_service_guard", "route_path"),
}


def test_earlier_subtask_reserves_observation_budget_for_same_expert(monkeypatch):
    original = AgenticPipeline._engine
    scopes = []
    def capture(self, role, state):
        engine = original(self, role, state)
        if role == "scan":
            scopes.append((engine.scope.max_observation_tokens, engine.scope.observed_tokens))
        return engine
    monkeypatch.setattr(AgenticPipeline, "_engine", capture)
    run_plan([("t1", "scan", []), ("t2", "taint", ["t1"]),
              ("t3", "scan", ["t2"]), ("t4", "authz", ["t3"])], system="E4")
    budget = FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens
    assert len(scopes) == 2
    assert scopes[0][0] == budget // 2
    assert scopes[1][0] == budget
    assert 0 < scopes[1][1] <= scopes[0][0]


def run_plan(tasks, *, system="E5", labels=None):
    has_safe_prediction = any("SAFE" in votes for votes in (labels or {}).values())
    document = CodeDocument(
        repository_id="r", path=PATH,
        text=(
            "def entry(request):\n"
            "    require_permission(request.user, 'manage')\n"
            "    value = int(request.args['value'])\n"
            "    database.delete(value)\n"
            "    return eval(str(value))\n"
        ) if has_safe_prediction else "def entry(request):\n    return eval(request.args['value'])\n",
    )
    index = RepositoryIndex([document])
    candidate = Candidate(candidate_id="c", case_id="c", repository_id="r", path=PATH, line=1, query=document.text)
    plan = {
        "candidate_id": "c", "vulnerability_hypotheses": ["test candidate"],
        "subtasks": [{
            "task_id": task_id, "expert": role, "objective": f"inspect {task_id}",
            "dependencies": dependencies, "allowed_validator": VALIDATORS[role][0],
            "success_condition": f"evidence for {task_id} is assessed",
        } for task_id, role, dependencies in tasks],
        "rationale": "A test plan with explicit data dependencies.",
    }

    def tool_reply(role, ordinal=1):
        name, key = VALIDATORS.get(role, ("read_span", "path"))
        return ModelReply(model_id="scripted-test", tool_calls=(
            ModelToolCall(call_id=f"{role}-{ordinal}", name=name, arguments={key: PATH}),
        ))

    models = {"planner": ScriptedChatModel([
        tool_reply("planner"), ModelReply(model_id="scripted-test", content=json.dumps(plan)),
    ])}
    counts = Counter(role for _, role, _ in tasks)
    for role in ("scan", "taint", "authz"):
        replies = []
        for ordinal in range(1, max(1, counts[role]) + 1):
            label = (labels or {}).get(role, ["VULNERABLE"] * max(1, counts[role]))[ordinal - 1]
            reply = tool_reply(role, ordinal)
            evidence_ids = [f"{role}/tool:{ordinal}"]
            if role == "taint" and label == "SAFE":
                reply = reply.model_copy(update={"tool_calls": (
                    *reply.tool_calls,
                    ModelToolCall(call_id="taint-sanitizers", name="find_sanitizers",
                                  arguments={"path": PATH}),
                )})
                evidence_ids = ["taint/tool:2"]
            if role == "scan" and label == "SAFE":
                # The resumed scan can refine its hypothesis using the actual
                # sanitizer observed by its completed taint dependency.
                evidence_ids.append("taint/tool:2")
            replies.extend([
                reply,
                ModelReply(model_id="scripted-test", content=json.dumps({
                    "expert": role, "label": label, "confidence": 0.9,
                    "validation_status": "UNRESOLVED",
                    "evidence_ids": evidence_ids,
                    "rationale": f"result-from-{role}-{ordinal}",
                })),
            ])
        models[role] = ScriptedChatModel(replies)
    verdict = AgenticPipeline(
        index=index, system=AgentSystemVersion(system), models=models,
        tools=ToolRegistry(full_agent_tools(index), max_output_bytes=1_000_000),
    ).run(candidate)
    return verdict, models


@pytest.mark.parametrize("system", ["E4", "E5"])
def test_reverse_expert_dependencies_are_executed_and_results_are_passed(system):
    verdict, models = run_plan([
        ("A", "authz", []), ("T", "taint", ["A"]), ("S", "scan", ["T"]),
    ], system=system)
    assert [item.task_id for item in verdict.task_executions] == ["A", "T", "S"]
    assert verdict.path == "slow"  # Authz was a prerequisite, so it cannot be skipped.
    assert "authz/tool:1" in models["taint"].requests[0][0][1].content
    assert "taint/tool:1" in models["scan"].requests[0][0][1].content
    assert "result-from-authz-1" not in models["taint"].requests[0][0][1].content
    assert "result-from-taint-1" not in models["scan"].requests[0][0][1].content
    assert [vote.expert for vote in verdict.votes] == ["scan", "taint", "authz"]


def test_expert_can_resume_after_another_expert_and_fast_waits_for_its_final_vote():
    tasks = [
        ("S1", "scan", []), ("T", "taint", ["S1"]),
        ("S2", "scan", ["T"]), ("A", "authz", ["S2"]),
    ]
    labels = {"scan": ["VULNERABLE", "SAFE"], "taint": ["SAFE"], "authz": ["ABSTAIN"]}
    full, _ = run_plan(tasks, system="E4", labels=labels)
    fast, models = run_plan(tasks, labels=labels)
    assert fast.label == full.label == "SAFE"
    assert fast.path == "fast"
    assert [item.task_id for item in fast.task_executions] == ["S1", "T", "S2"]
    assert [vote.expert for vote in fast.votes] == ["scan", "taint"]
    assert fast.votes[0].model_calls == 4
    assert fast.votes[0].tool_calls == 2
    assert [step.observation.citation_id for step in fast.votes[0].trace] == ["scan/tool:1", "scan/tool:2"]
    second_scan_prompt = models["scan"].requests[2][0][1].content
    assert "result-from-scan-1" in second_scan_prompt
    assert "taint/tool:1" in second_scan_prompt
    assert "result-from-taint-1" not in second_scan_prompt
    assert not models["authz"].requests
    assert fast.model_calls == 8
    assert fast.tool_calls == 5
    assert fast.votes[0].evidence_ids == ("scan/tool:2", "taint/tool:2")
    assert fast.votes[1].trace[-1].observation.tool == "find_sanitizers"
    for vote in fast.votes:
        assert vote.tool_observation_token_count <= FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens


def test_repeated_tasks_do_not_give_one_expert_multiple_quorum_votes():
    verdict, _ = run_plan([
        ("S1", "scan", []), ("S2", "scan", ["S1"]),
        ("T", "taint", ["S2"]), ("A", "authz", ["T"]),
    ], labels={"scan": ["VULNERABLE", "VULNERABLE"], "taint": ["ABSTAIN"], "authz": ["SAFE"]})
    assert verdict.label == "ABSTAIN"
    assert verdict.path == "slow"
    assert len(verdict.votes) == 3
    assert len(verdict.task_executions) == 4


def test_dependent_expert_sees_peer_observations_without_peer_judgment():
    _, models = run_plan([('S', 'scan', []), ('T', 'taint', ['S'])], system='E4')
    prompt = models['taint'].requests[0][0][1].content
    assert 'scan/tool:1' in prompt
    assert 'finding_count' in prompt
    assert 'result-from-scan-1' not in prompt
    assert '"label":"VULNERABLE"' not in prompt


def test_fixture_subtask_must_be_dependency_for_later_planned_checks():
    document = CodeDocument(repository_id="r", path=PATH, text="def entry(value):\n    return value\n")
    index = RepositoryIndex([document])
    candidate = Candidate(candidate_id="c", case_id="c", repository_id="r", path=PATH, line=1, query="entry")
    fixture = FixtureCase("fixture", lambda: FixtureOutcome(status="CONFIRMED", summary="ok"))
    pipeline = AgenticPipeline(
        index=index,
        system=AgentSystemVersion.E4_GRAPH_MULTI,
        models={
            "planner": ScriptedChatModel([]),
            "scan": ScriptedChatModel([]),
            "taint": ScriptedChatModel([]),
            "authz": ScriptedChatModel([]),
        },
        tools=ToolRegistry(full_agent_tools(index, fixture_cases=(fixture,)), max_output_bytes=1_000_000),
    )
    missing_dependency = ValidationPlan.model_validate({
        "candidate_id": "c",
        "vulnerability_hypotheses": ["fixture-backed hypothesis"],
        "subtasks": [
            {
                "task_id": "S",
                "expert": "scan",
                "objective": "run fixture",
                "dependencies": [],
                "allowed_validator": "run_fixture_test",
                "success_condition": "fixture result is observed",
            },
            {
                "task_id": "T",
                "expert": "taint",
                "objective": "inspect flow",
                "dependencies": [],
                "allowed_validator": "trace_dataflow",
                "success_condition": "flow evidence is observed",
            },
        ],
        "rationale": "fixture then flow",
    })
    with pytest.raises(ValueError, match="depend on run_fixture_test"):
        pipeline._validate_plan(missing_dependency, candidate)
    corrected = missing_dependency.model_copy(update={
        "subtasks": (
            missing_dependency.subtasks[0],
            missing_dependency.subtasks[1].model_copy(update={"dependencies": ("S",)}),
        )
    })
    pipeline._validate_plan(corrected, candidate)


def test_chmod_permission_plan_requires_authz_access_control_task():
    document = CodeDocument(
        repository_id="r",
        path=PATH,
        text="def entry(tmp_dir):\n    os.chmod(tmp_dir, 0o777)\n",
    )
    index = RepositoryIndex([document])
    candidate = Candidate(
        candidate_id="c",
        case_id="c",
        repository_id="r",
        path=PATH,
        line=1,
        query="entry",
    )
    pipeline = AgenticPipeline(
        index=index,
        system=AgentSystemVersion.E4_GRAPH_MULTI,
        models={
            "planner": ScriptedChatModel([]),
            "scan": ScriptedChatModel([]),
            "taint": ScriptedChatModel([]),
            "authz": ScriptedChatModel([]),
        },
        tools=ToolRegistry(full_agent_tools(index), max_output_bytes=1_000_000),
    )
    scan_only = ValidationPlan.model_validate({
        "candidate_id": "c",
        "vulnerability_hypotheses": ["filesystem permission mode"],
        "subtasks": [
            {
                "task_id": "t1",
                "expert": "scan",
                "objective": "validate chmod mode",
                "dependencies": [],
                "allowed_validator": "validate_permission_mode",
                "success_condition": "mode evidence is observed",
            },
        ],
        "rationale": "chmod mode",
    })
    evidence = [Evidence(
        evidence_id=f"local:{PATH}",
        path=PATH,
        text=document.text,
        retrieval="local",
        score=1.0,
    )]

    with pytest.raises(ValueError, match="authz validate_permission_mode"):
        pipeline._validate_plan(scan_only, candidate, evidence)

    corrected = scan_only.model_copy(update={
        "subtasks": (
            *scan_only.subtasks,
            scan_only.subtasks[0].model_copy(update={
                "task_id": "t2",
                "expert": "authz",
                "objective": "validate chmod resource access semantics",
                "dependencies": ("t1",),
                "allowed_validator": "validate_permission_mode",
                "success_condition": "mode access-control evidence is observed",
            }),
        )
    })
    pipeline._validate_plan(corrected, candidate, evidence)


def test_get_cmd_command_plan_requires_scan_and_taint_construction_checks():
    backend = CodeDocument(
        repository_id="r",
        path=PATH,
        text=(
            "def entry(model_uri):\n"
            "    command, env = mlserver.get_cmd(model_uri)\n"
            "    return subprocess.Popen([\"bash\", \"-c\", command])\n"
        ),
        defines=("entry",),
        calls=("mlserver.get_cmd", "subprocess.Popen"),
    )
    helper = CodeDocument(
        repository_id="r",
        path="helper.py::get_cmd@1-3",
        text=(
            "def get_cmd(model_uri):\n"
            "    cmd = f\"run {model_uri}\"\n"
            "    return cmd, {}\n"
        ),
        defines=("mlserver.get_cmd", "get_cmd"),
    )
    index = RepositoryIndex([backend, helper])
    candidate = Candidate(
        candidate_id="c",
        case_id="c",
        repository_id="r",
        path=PATH,
        line=1,
        query="entry",
    )
    pipeline = AgenticPipeline(
        index=index,
        system=AgentSystemVersion.E4_GRAPH_MULTI,
        models={
            "planner": ScriptedChatModel([]),
            "scan": ScriptedChatModel([]),
            "taint": ScriptedChatModel([]),
            "authz": ScriptedChatModel([]),
        },
        tools=ToolRegistry(full_agent_tools(index), max_output_bytes=1_000_000),
    )
    taint_only = ValidationPlan.model_validate({
        "candidate_id": "c",
        "vulnerability_hypotheses": ["command construction"],
        "subtasks": [
            {
                "task_id": "t1",
                "expert": "taint",
                "objective": "inspect command construction",
                "dependencies": [],
                "allowed_validator": "inspect_command_construction",
                "success_condition": "construction evidence is observed",
            },
        ],
        "rationale": "get_cmd command",
    })
    evidence = [Evidence(
        evidence_id=f"local:{backend.path}",
        path=backend.path,
        text=backend.text + "\n" + helper.text,
        retrieval="local",
        score=1.0,
    )]

    with pytest.raises(ValueError, match="scan inspect_command_construction"):
        pipeline._validate_plan(taint_only, candidate, evidence)

    scan_only = taint_only.model_copy(update={
        "subtasks": (
            taint_only.subtasks[0].model_copy(update={
                "expert": "scan",
            }),
        )
    })
    with pytest.raises(ValueError, match="taint inspect_command_construction"):
        pipeline._validate_plan(scan_only, candidate, evidence)

    scoped_candidate = candidate.model_copy(update={
        "analysis_scope": "Assess command injection through get_cmd and subprocess.Popen.",
    })
    trimmed_evidence = [evidence[0].model_copy(update={
        "text": "def entry(model_uri):\n    command = mlserver.get_cmd(model_uri)\n",
    })]
    with pytest.raises(ValueError, match="taint inspect_command_construction"):
        pipeline._validate_plan(scan_only, scoped_candidate, trimmed_evidence)

    corrected = taint_only.model_copy(update={
        "subtasks": (
            taint_only.subtasks[0].model_copy(update={
                "expert": "scan",
            }),
            taint_only.subtasks[0].model_copy(update={
                "task_id": "t2",
                "dependencies": ("t1",),
            }),
        )
    })
    pipeline._validate_plan(corrected, candidate, evidence)

    redundant_static_scan = corrected.model_copy(update={
        "subtasks": (
            *corrected.subtasks,
            corrected.subtasks[0].model_copy(update={
                "task_id": "t3",
                "allowed_validator": "run_static_check",
                "dependencies": ("t1", "t2"),
                "objective": "repeat static command sink scan",
            }),
        )
    })
    with pytest.raises(ValueError, match="redundant scan validators"):
        pipeline._validate_plan(redundant_static_scan, candidate, evidence)


def test_assigned_validator_keeps_repository_inspection_available():
    _, models = run_plan([('S', 'scan', [])], system='E4')
    definitions = models['scan'].requests[0][1]
    names = {item['function']['name'] for item in definitions}
    assert {'run_static_check', 'read_span', 'get_callers', 'get_callees'} <= names
    assert 'probe_python_eval' not in names


def test_small_budget_cannot_be_borrowed_from_a_later_expert_subtask(monkeypatch):
    import cv_agent.agents.workflow as workflow
    modified = FULL_SYSTEM_HARNESS.model_copy(update={
        "react_loop": FULL_SYSTEM_HARNESS.react_loop.model_copy(update={
            "max_tool_observation_tokens": 400,
        }),
    })
    monkeypatch.setattr(workflow, "FULL_SYSTEM_HARNESS", modified)
    observed = {}
    original = ToolRegistry.invoke

    def capture(self, call, **kwargs):
        result = original(self, call, **kwargs)
        observed[kwargs.get("citation_id")] = result
        return result

    monkeypatch.setattr(ToolRegistry, "invoke", capture)
    with pytest.raises(RuntimeError):
        run_plan([("S1", "scan", []), ("S2", "scan", ["S1"])])
    assert observed["scan/tool:1"].status == "error"
    assert observed["scan/tool:1"].metadata["observation_truncated"] is True
    assert observed["scan/tool:1"].metadata["observation_token_count"] <= 200
    assert observed["scan/tool:2"].status == "error"
    assert observed["scan/tool:2"].metadata["observation_truncated"] is True
    assert sum(item.metadata["observation_token_count"] for citation, item in observed.items()
               if citation.startswith("scan/")) <= 200
