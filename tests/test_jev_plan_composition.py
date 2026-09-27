import json
from pathlib import Path
import pytest

from cv_agent.agents.routing import route_plan, route_plan_v3
from cv_agent.domain.chat import ModelReply
from cv_agent.domain.evidence import ValidationSubject
from cv_agent.domain.review import ValidationPlan, ValidationSubtask
from cv_agent.domain.types import Candidate, CodeDocument, Evidence
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentSystemVersion
from cv_agent.retrieval import RepositoryIndex
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.tools.registry import ToolRegistry
from cv_agent.tools.validation import full_agent_tools


BACKEND_CODE = """
def serve(model_uri):
    cmd, env = get_cmd(model_uri)
    subprocess.Popen(['bash', '-c', cmd])
"""


def _make_environment(code=BACKEND_CODE):
    doc = CodeDocument(repository_id="r", path="mlflow/pyfunc/backend.py", text=code, defines=("serve",), calls=("get_cmd", "subprocess.Popen"))
    index = RepositoryIndex([doc])
    candidate = Candidate(
        candidate_id="c_hp003",
        case_id="c_hp003",
        repository_id="r",
        path=doc.path,
        line=2,
        query="get_cmd",
        property_id="command-execution",
        analysis_scope="get_cmd shell-command subprocess.Popen bash -c",
    )
    evidence = [
        Evidence(evidence_id="e1", path=doc.path, text=code, graph_distance=0, retrieval="local", score=1.0)
    ]
    tools = ToolRegistry(full_agent_tools(index), max_output_bytes=100000)
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)
    return index, candidate, evidence, tools, spec


def test_v3_no_remaining_choice_zero_calls_policy_plan():
    # If tools only has inspect_command_construction (which is locked by policy for scan and taint)
    # and no other validators, there is NO remaining choice space for any expert!
    doc = CodeDocument(repository_id="r", path="mlflow/pyfunc/backend.py", text=BACKEND_CODE, defines=("serve",), calls=("get_cmd", "subprocess.Popen"))
    index = RepositoryIndex([doc])
    candidate = Candidate(
        candidate_id="c_hp003",
        case_id="c_hp003",
        repository_id="r",
        path=doc.path,
        line=2,
        query="get_cmd",
        property_id="command-execution",
        analysis_scope="get_cmd shell-command subprocess.Popen bash -c",
    )
    evidence = [
        Evidence(evidence_id="e1", path=doc.path, text=BACKEND_CODE, graph_distance=0, retrieval="local", score=1.0)
    ]
    # Filter tools to only inspect_command_construction and search/read tools
    all_tools = full_agent_tools(index)
    limited_tools = [t for t in all_tools if t.name in ("read_span", "inspect_command_construction")]
    tools = ToolRegistry(limited_tools, max_output_bytes=100000)
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)
    spec_two = spec.model_copy(update={"expert_order": ("scan", "taint")})

    model = ScriptedChatModel([])  # Must not be called!
    result = route_plan_v3(
        model=model,
        index=index,
        candidate=candidate,
        evidence=evidence,
        tools=tools,
        system_spec=spec_two,
        min_probability=0.85,
    )
    assert result.model_calls == 0
    assert result.escalation_reason == "no_remaining_choice"
    assert result.plan is not None
    assert len(result.plan.subtasks) == 2
    assert all(o.origin == "policy" for o in result.task_origins)


def test_v3_hp003_shape_scan_and_taint_policy_coverage():
    # Scan and taint locked by policy; taint and authz have optional choices.
    index, candidate, evidence, tools, spec = _make_environment()
    # Taint chooses unknown (escape option)
    # Authz chooses unknown (escape option)
    jev_reply = json.dumps({
        "taint": {
            "type": "choice",
            "choice": "unknown",
            "confidence": 0.9,
            "probabilities": {"unknown": 0.95, "trace_dataflow": 0.05},
        },
        "authz": {
            "type": "choice",
            "choice": "unknown",
            "confidence": 0.9,
            "probabilities": {"unknown": 0.95, "compare_route_and_service_guard": 0.05},
        },
    })
    model = ScriptedChatModel([ModelReply(model_id="jev-1", content=jev_reply)])
    result = route_plan_v3(
        model=model,
        index=index,
        candidate=candidate,
        evidence=evidence,
        tools=tools,
        system_spec=spec,
        min_probability=0.85,
    )
    assert result.model_calls == 1
    assert result.plan is not None
    # Mandatory tasks (scan & taint inspect_command_construction) retained by policy
    scan_task = next(t for t in result.plan.subtasks if t.expert == "scan")
    assert scan_task.allowed_validator == "inspect_command_construction"
    taint_task = next(t for t in result.plan.subtasks if t.expert == "taint")
    assert taint_task.allowed_validator == "inspect_command_construction"

    # Taint chose unknown, but policy kept mandatory taint task
    assert result.decisions["taint"].choice == "unknown"
    assert result.decisions["taint"].accepted is False

    # Task origins for both mandatory tasks remain policy!
    origin_map = {o.task_id: o.origin for o in result.task_origins}
    assert origin_map[scan_task.task_id] == "policy"
    assert origin_map[taint_task.task_id] == "policy"


def test_v3_genuine_optional_choice_accepted_and_applied():
    index, candidate, evidence, tools, spec = _make_environment()
    jev_reply = json.dumps({
        "taint": {
            "type": "choice",
            "choice": "unknown",
            "confidence": 0.9,
            "probabilities": {"unknown": 0.95, "trace_dataflow": 0.05},
        },
        "authz": {
            "type": "choice",
            "choice": "compare_route_and_service_guard",
            "confidence": 0.95,
            "probabilities": {"compare_route_and_service_guard": 0.92, "unknown": 0.08},
        },
    })
    model = ScriptedChatModel([ModelReply(model_id="jev-1", content=jev_reply)])
    result = route_plan_v3(
        model=model,
        index=index,
        candidate=candidate,
        evidence=evidence,
        tools=tools,
        system_spec=spec,
        min_probability=0.85,
    )
    assert result.model_calls == 1
    assert result.plan is not None
    assert result.decisions["authz"].accepted is True
    assert result.decisions["authz"].applied is True
    assert result.decisions["authz"].applied_reason == "applied_to_plan"
    origin_map = {o.task_id: o.origin for o in result.task_origins}
    assert origin_map["jev-authz"] == "jev"


def test_v3_shadow_and_off_modes():
    index, candidate, evidence, tools, spec = _make_environment()
    # 1. Off mode
    off_result = route_plan_v3(
        model=ScriptedChatModel([]),
        index=index,
        candidate=candidate,
        evidence=evidence,
        tools=tools,
        system_spec=spec,
        min_probability=0.85,
        mode="off",
    )
    assert off_result.model_calls == 0
    assert off_result.plan is None
    assert off_result.escalation_reason == "Routing disabled."

    # 2. Shadow mode
    jev_reply = json.dumps({
        "taint": {
            "type": "choice",
            "choice": "unknown",
            "confidence": 0.9,
            "probabilities": {"unknown": 0.95, "trace_dataflow": 0.05},
        },
        "authz": {
            "type": "choice",
            "choice": "compare_route_and_service_guard",
            "confidence": 0.95,
            "probabilities": {"compare_route_and_service_guard": 0.92, "unknown": 0.08},
        },
    })
    shadow_result = route_plan_v3(
        model=ScriptedChatModel([ModelReply(model_id="jev-1", content=jev_reply)]),
        index=index,
        candidate=candidate,
        evidence=evidence,
        tools=tools,
        system_spec=spec,
        min_probability=0.85,
        mode="shadow",
    )
    assert shadow_result.proposed_plan is not None
    assert shadow_result.plan is None  # Not applied in shadow mode
    assert "Shadow mode" in shadow_result.escalation_reason


def test_v3_conflicting_choice_recorded_and_rejected_others_preserved():
    # If scan choice contradicts mandatory obligation or is redundant, it is rejected, but authz choice is kept.
    index, candidate, evidence, tools, spec = _make_environment()
    # Say Jev answered for taint with an invalid validator or conflict, but authz is valid
    jev_reply = json.dumps({
        "taint": {
            "type": "choice",
            "choice": "unknown",  # escape
            "confidence": 0.95,
            "probabilities": {"unknown": 0.95, "trace_dataflow": 0.05},
        },
        "authz": {
            "type": "choice",
            "choice": "compare_route_and_service_guard",
            "confidence": 0.95,
            "probabilities": {"compare_route_and_service_guard": 0.95, "unknown": 0.05},
        },
    })
    model = ScriptedChatModel([ModelReply(model_id="jev-1", content=jev_reply)])
    result = route_plan_v3(
        model=model,
        index=index,
        candidate=candidate,
        evidence=evidence,
        tools=tools,
        system_spec=spec,
        min_probability=0.85,
    )
    assert result.model_calls == 1
    assert result.plan is not None
    assert result.decisions["authz"].accepted is True
    assert result.decisions["authz"].applied is True
    # Taint mandatory task is NOT lost!
    assert any(t.expert == "taint" and t.allowed_validator == "inspect_command_construction" for t in result.plan.subtasks)
