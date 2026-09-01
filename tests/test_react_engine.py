import json

from cv_agent.agent_tools import ToolExecutionScope, ToolRegistry, repository_tools
from cv_agent.agent_types import ModelReply, ModelToolCall, ModelUsage
from cv_agent.harness import FULL_SYSTEM_HARNESS
from cv_agent.model_runtime import ScriptedChatModel
from cv_agent.react_engine import ReActEngine, run_expert, run_planner
from cv_agent.retrieval import RepositoryIndex
from cv_agent.types import CodeDocument


ENTRY_PATH = "entry.py::entry@1-2"


def _registry() -> ToolRegistry:
    index = RepositoryIndex(
        [
            CodeDocument(
                repository_id="repo",
                path=ENTRY_PATH,
                text="def entry(value):\n    return eval(value)\n",
                defines=("entry",),
            )
        ]
    )
    return ToolRegistry(
        repository_tools(index),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )


def _scope() -> ToolExecutionScope:
    return ToolExecutionScope(
        admitted_paths=frozenset({ENTRY_PATH}),
        max_observation_tokens=(
            FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens
        ),
    )


def _tool_reply() -> ModelReply:
    return ModelReply(
        model_id="scripted-security-model",
        tool_calls=(
            ModelToolCall(
                call_id="call-1",
                name="read_span",
                arguments={"path": ENTRY_PATH},
            ),
        ),
        usage=ModelUsage(input_tokens=10, output_tokens=4, total_tokens=14),
    )


def test_react_expert_requires_tool_observation_and_attaches_trace():
    conclusion = {
        "expert": "scan",
        "label": "VULNERABLE",
        "confidence": 0.9,
        "validation_status": "CONFIRMED",
        "evidence_ids": [f"span:{ENTRY_PATH}"],
        "rationale": "The externally supplied value reaches eval.",
    }
    model = ScriptedChatModel(
        [
            _tool_reply(),
            ModelReply(
                model_id="scripted-security-model",
                content=json.dumps(conclusion),
                usage=ModelUsage(input_tokens=20, output_tokens=12, total_tokens=32),
            ),
        ]
    )
    engine = ReActEngine(
        model=model,
        tools=_registry(),
        scope=_scope(),
        harness=FULL_SYSTEM_HARNESS.react_loop,
    )

    vote = run_expert(
        engine,
        expert="scan",
        system_prompt="You are the scan specialist.",
        task_prompt="Inspect the entry candidate.",
        allowed_tools=("read_span",),
    )

    assert vote.runtime_mode.value == "scripted"
    assert vote.label == "VULNERABLE"
    assert vote.model_calls == 2
    assert vote.tool_calls == 1
    assert vote.tool_observation_token_count > 0
    assert vote.usage.total_tokens == 46
    assert vote.trace[0].observation.status == "ok"
    assert len(model.requests) == 2


def test_react_expert_rejects_final_answer_until_successful_tool_call():
    conclusion = {
        "expert": "scan",
        "label": "ABSTAIN",
        "confidence": 0.2,
        "validation_status": "UNRESOLVED",
        "evidence_ids": [],
        "rationale": "Insufficient evidence.",
    }
    model = ScriptedChatModel(
        [
            ModelReply(model_id="scripted", content=json.dumps(conclusion)),
            _tool_reply(),
            ModelReply(model_id="scripted", content=json.dumps(conclusion)),
        ]
    )
    engine = ReActEngine(
        model=model,
        tools=_registry(),
        scope=_scope(),
        harness=FULL_SYSTEM_HARNESS.react_loop,
    )

    vote = run_expert(
        engine,
        expert="scan",
        system_prompt="scan",
        task_prompt="inspect",
        allowed_tools=("read_span",),
    )

    assert vote.model_calls == 3
    assert vote.tool_calls == 1
    assert vote.usage.input_tokens is None
    assert vote.usage.output_tokens is None
    assert vote.usage.total_tokens is None


def test_react_partial_usage_fields_remain_unknown_instead_of_zero():
    conclusion = {
        "expert": "scan",
        "label": "VULNERABLE",
        "confidence": 0.8,
        "validation_status": "CONFIRMED",
        "evidence_ids": [f"span:{ENTRY_PATH}"],
        "rationale": "The source reaches eval.",
    }
    model = ScriptedChatModel(
        [
            _tool_reply(),
            ModelReply(
                model_id="partially-metered-model",
                content=json.dumps(conclusion),
                usage=ModelUsage(input_tokens=20),
            ),
        ]
    )
    engine = ReActEngine(
        model=model,
        tools=_registry(),
        scope=_scope(),
        harness=FULL_SYSTEM_HARNESS.react_loop,
    )

    vote = run_expert(
        engine,
        expert="scan",
        system_prompt="scan",
        task_prompt="inspect",
        allowed_tools=("read_span",),
    )

    assert vote.usage.input_tokens == 30
    assert vote.usage.output_tokens is None
    assert vote.usage.total_tokens is None


def test_react_planner_emits_candidate_specific_dependency_order():
    plan = {
        "candidate_id": "candidate-1",
        "vulnerability_hypotheses": ["command injection"],
        "subtasks": [
            {
                "task_id": "scan-sink",
                "objective": "Confirm the sensitive operation.",
                "expert": "scan",
                "allowed_validator": "run_static_check",
                "dependencies": [],
                "success_condition": "A command sink is present.",
            },
            {
                "task_id": "trace-input",
                "objective": "Trace untrusted input to the sink.",
                "expert": "taint",
                "allowed_validator": "compare_vulnerable_and_fixed",
                "dependencies": ["scan-sink"],
                "success_condition": "A source-to-sink path is established.",
            },
        ],
        "rationale": "The candidate calls a command execution API.",
    }
    model = ScriptedChatModel(
        [
            _tool_reply(),
            ModelReply(model_id="scripted-planner", content=json.dumps(plan)),
        ]
    )
    engine = ReActEngine(
        model=model,
        tools=_registry(),
        scope=_scope(),
        harness=FULL_SYSTEM_HARNESS.react_loop,
    )

    result = run_planner(
        engine,
        system_prompt="Plan security validation tasks.",
        task_prompt="Candidate candidate-1 invokes eval.",
        allowed_tools=("read_span",),
        max_subtasks=FULL_SYSTEM_HARNESS.planner_max_subtasks,
    )

    assert result.plan.candidate_id == "candidate-1"
    assert [task.task_id for task in result.plan.subtasks] == [
        "scan-sink",
        "trace-input",
    ]
    assert result.tool_calls == 1
    assert result.tool_observation_token_count > 0
