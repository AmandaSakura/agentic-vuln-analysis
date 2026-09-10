import json
from collections import Counter

import pytest

from cv_agent.agent_tools import ToolRegistry
from cv_agent.agent_types import ModelReply, ModelToolCall
from cv_agent.agentic_workflow import AgenticPipeline
from cv_agent.harness import AgentSystemVersion, FULL_SYSTEM_HARNESS
from cv_agent.model_runtime import ScriptedChatModel
from cv_agent.retrieval import RepositoryIndex
from cv_agent.types import Candidate, CodeDocument
from cv_agent.validation_tools import full_agent_tools


PATH = "entry.py"
VALIDATORS = {
    "scan": ("run_static_check", "path"),
    "taint": ("trace_dataflow", "source_path"),
    "authz": ("compare_route_and_service_guard", "route_path"),
}


def run_plan(tasks, *, system="E5", labels=None):
    document = CodeDocument(
        repository_id="r", path=PATH,
        text="def entry(request):\n    return eval(request.args['value'])\n",
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
            replies.extend([
                tool_reply(role, ordinal),
                ModelReply(model_id="scripted-test", content=json.dumps({
                    "expert": role, "label": label, "confidence": 0.9,
                    "validation_status": "UNRESOLVED",
                    "evidence_ids": [f"{role}/tool:{ordinal}"],
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
    assert "result-from-authz-1" in models["taint"].requests[0][0][1].content
    assert "result-from-taint-1" in models["scan"].requests[0][0][1].content
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
    assert "result-from-taint-1" in second_scan_prompt
    assert not models["authz"].requests
    assert fast.model_calls == 8
    assert fast.tool_calls == 4
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


def test_an_expert_resuming_a_task_does_not_receive_a_fresh_observation_budget(monkeypatch):
    import cv_agent.agentic_workflow as workflow
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
    assert observed["scan/tool:1"].status == "ok"
    assert observed["scan/tool:2"].status == "error"
    assert observed["scan/tool:2"].metadata["observation_truncated"] is True
