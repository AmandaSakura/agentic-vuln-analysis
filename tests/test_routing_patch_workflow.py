"""Offline workflow contracts for deterministic routing and scoped planner patches."""

import json

import pytest

from cv_agent.agents import routing, workflow
from cv_agent.agents.plan_policy import compose_plan, required_tasks
from cv_agent.domain.chat import ModelReply, ModelUsage
from cv_agent.domain.evidence import ToolObservation
from cv_agent.domain.review import RoutingDecision, RoutingResult
from cv_agent.domain.types import Candidate, CodeDocument
from cv_agent.harness import AgentRuntimeMode, AgentSystemVersion
from cv_agent.retrieval import RepositoryIndex
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolRegistry
from cv_agent.tools.validation import full_agent_tools


def _permission_case():
    source = "import os\ndef handle(path):\n    os.chmod(path, 0o777)\n"
    doc = CodeDocument(repository_id="r", path="entry.py", text=source)
    index = RepositoryIndex([doc])
    candidate = Candidate(
        candidate_id="c1", case_id="c1", repository_id="r", path=doc.path,
        line=2, query="chmod", property_id="chmod-mode-others-write",
        analysis_scope="Assess the chmod mode at this call.",
    )
    tools = ToolRegistry(full_agent_tools(index), max_output_bytes=100000)
    return index, candidate, tools


def _pipeline(index, tools, *, planner_replies=(), routing_model=None, system_name=None):
    planner = ScriptedChatModel(list(planner_replies))
    pipeline = workflow.AgenticPipeline(
        index=index, system=AgentSystemVersion.E4_GRAPH_MULTI,
        models={name: ScriptedChatModel([]) for name in ("scan", "taint", "authz")}
        | {"planner": planner},
        tools=tools, routing_model=routing_model, routing_spec_version=3,
        system_name=system_name,
    )
    return pipeline, planner


def _state(pipeline, candidate):
    return {
        "candidate": candidate, "planner": None, "routing": None,
        "votes": [], "task_executions": [], "verdict": None,
        "fast_checked": False,
        **pipeline._retrieve({"candidate": candidate}),
    }


def _fallback_routing(pipeline, state):
    candidate = state["candidate"]
    locked = required_tasks(
        candidate, state["evidence"], pipeline.tools, pipeline.system_spec,
        subject=candidate_subject(pipeline.index, candidate),
    )
    assert [(task.expert, task.allowed_validator) for task in locked] == [
        ("authz", "validate_permission_mode")
    ]
    before, origins = compose_plan(
        candidate.candidate_id, locked, {"scan": "run_static_check"},
        expert_order=pipeline.system_spec.expert_order,
    )
    decisions = {
        "scan": RoutingDecision(
            decision_id="validator.scan", choice="run_static_check",
            selected_probability=0.95, provider_confidence=0.95,
            threshold=0.85, accepted=True, action="llm_planner", reason="accepted",
        ),
        "taint": RoutingDecision(
            decision_id="validator.taint", choice="unknown",
            selected_probability=0.95, provider_confidence=0.95,
            threshold=0.85, accepted=False, action="llm_planner", reason="escape_option",
        ),
        "authz": RoutingDecision(
            decision_id="validator.authz", choice="unknown",
            selected_probability=0.95, provider_confidence=0.95,
            threshold=0.85, accepted=False, action="llm_planner", reason="escape_option",
        ),
    }
    return RoutingResult(
        runtime_mode=AgentRuntimeMode.SCRIPTED, spec_version=3, mode="active",
        observation=ToolObservation(tool="read_span", status="ok", content="os.chmod(path, 0o777)"),
        decisions=decisions, model_calls=0, tool_calls=1,
        tool_observation_token_count=100,
        usage=ModelUsage(input_tokens=0, output_tokens=0, total_tokens=0),
        plan=None, proposed_plan=before, locked_tasks=locked, task_origins=origins,
        escalation_reason="Additional taint check needs planner judgment.",
        fallback_scope="patch_subtasks",
    )


def _patch_payload(candidate_id="c1", *, task_id="patch-taint", expert="taint",
                   validator="trace_dataflow", dependencies=("jev-scan",)):
    return json.dumps({
        "candidate_id": candidate_id,
        "subtasks": [{
            "task_id": task_id, "expert": expert, "allowed_validator": validator,
            "objective": "Check the input flow.", "dependencies": list(dependencies),
            "success_condition": "Record the scoped result.",
        }],
        "rationale": "Complete the unresolved taint check.",
    })


def test_rule_arm_valid_plan_uses_zero_planner_requests(monkeypatch):
    index, candidate, tools = _permission_case()
    pipeline, planner = _pipeline(index, tools, system_name="E4_RULE_V1")
    monkeypatch.setattr(workflow, "run_planner", lambda *args, **kwargs: pytest.fail("planner called"))

    result = pipeline._plan(_state(pipeline, candidate))

    assert result["planner"] is None
    assert result["routing"].model_calls == 0
    assert result["routing"].task_origins[0].origin == "policy"
    assert planner.requests == []


def test_rule_arm_construction_error_is_not_a_semantic_fallback(monkeypatch):
    index, candidate, tools = _permission_case()
    pipeline, planner = _pipeline(index, tools, system_name="E4_RULE_V1")

    def broken_result(**kwargs):
        raise ValueError("routing result construction broke")

    monkeypatch.setattr(workflow, "RoutingResult", broken_result)
    with pytest.raises(ValueError, match="routing result construction broke"):
        pipeline._plan(_state(pipeline, candidate))
    assert planner.requests == []


def test_v3_fallback_only_patches_unresolved_role_and_retains_jev(monkeypatch):
    index, candidate, tools = _permission_case()
    pipeline, planner = _pipeline(
        index, tools, routing_model=ScriptedChatModel([]),
        planner_replies=[ModelReply(model_id="planner", content=_patch_payload())],
    )
    state = _state(pipeline, candidate)
    before = _fallback_routing(pipeline, state)
    monkeypatch.setattr(routing, "route_plan", lambda **kwargs: before)

    result = pipeline._plan(state)

    assert len(planner.requests) == 1
    assert planner.requests[0][1] == ()
    prompt = "\n".join(message.content or "" for message in planner.requests[0][0])
    assert "os.chmod(path, 0o777)" in prompt
    assert "jev-scan" in prompt
    assert "taint" in prompt
    assert result["planner"].tool_calls == 0
    assert result["routing"].proposed_plan == before.proposed_plan
    assert result["routing"].fallback_scope == "patch_subtasks"
    assert {(t.expert, t.allowed_validator) for t in result["planner"].plan.subtasks} == {
        ("authz", "validate_permission_mode"),
        ("scan", "run_static_check"),
        ("taint", "trace_dataflow"),
    }
    assert next(t for t in result["planner"].plan.subtasks if t.task_id == "patch-taint").dependencies == ("jev-scan",)
    assert [(o.task_id, o.origin) for o in result["routing"].task_origins] == [
        ("jev-scan", "jev"), ("patch-taint", "llm"), ("req-perm-authz", "policy")
    ]


@pytest.mark.parametrize("invalid", [
    _patch_payload(task_id="req-perm-authz", expert="authz", validator="run_static_check", dependencies=()),
    _patch_payload(task_id="different-authz", expert="authz", validator="validate_permission_mode", dependencies=()),
    _patch_payload(task_id="jev-scan", expert="scan", validator="run_static_check", dependencies=()),
    _patch_payload(task_id="extra-scan", expert="scan", validator="probe_python_eval", dependencies=()),
    json.dumps({"candidate_id": "c1", "subtasks": [], "rationale": "Delete locked work."}),
])
def test_v3_patch_rejects_locked_task_replacement(monkeypatch, invalid):
    index, candidate, tools = _permission_case()
    pipeline, planner = _pipeline(
        index, tools, routing_model=ScriptedChatModel([]),
        planner_replies=[ModelReply(model_id="planner", content=invalid),
                         ModelReply(model_id="planner", content=_patch_payload())],
    )
    state = _state(pipeline, candidate)
    monkeypatch.setattr(routing, "route_plan", lambda **kwargs: _fallback_routing(pipeline, state))

    result = pipeline._plan(state)

    assert len(planner.requests) == 2
    assert result["planner"].plan.subtasks[-1].allowed_validator == "validate_permission_mode"
    assert "validation error" in planner.requests[1][0][-1].content.casefold()
    if json.loads(invalid)["subtasks"] and json.loads(invalid)["subtasks"][0]["task_id"] != "extra-scan":
        assert "locked" in planner.requests[1][0][-1].content.casefold()


def test_v3_all_unknown_without_policy_tasks_uses_full_planner():
    from cv_agent.domain.types import Evidence

    doc = CodeDocument(repository_id="r", path="entry.py", text="def entry(): return 1\n")
    index = RepositoryIndex([doc])
    candidate = Candidate(
        candidate_id="c1", case_id="c1", repository_id="r", path=doc.path,
        line=1, query="entry", property_id="unknown-property",
    )
    tools = ToolRegistry(full_agent_tools(index), max_output_bytes=100000)
    evidence = [Evidence(
        evidence_id="e1", path=doc.path, text=doc.text,
        graph_distance=0, retrieval="local", score=1.0,
    )]

    def unknown_reply(messages, tool_defs):
        questions = json.loads(messages[0].content)["questions"]
        return ModelReply(model_id="jev", content=json.dumps({
            role: {
                "type": "choice", "choice": "unknown", "confidence": 1.0,
                "probabilities": {key: 1.0 if key == "unknown" else 0.0
                                  for key in question["criteria"]},
            }
            for role, question in questions.items()
        }))

    pipeline, _ = _pipeline(index, tools)
    result = routing.route_plan_v3(
        model=ScriptedChatModel([unknown_reply]), index=index, candidate=candidate,
        evidence=evidence, tools=tools, system_spec=pipeline.system_spec,
        min_probability=0.85,
    )
    assert result.plan is None
    assert result.locked_tasks == ()
    assert "No deterministic or accepted" in result.escalation_reason
