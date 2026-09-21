import json
import pytest

from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.repository import repository_tools
from cv_agent.domain.review import AgentExpertConclusion, ValidationPlan
from cv_agent.domain.chat import ModelReply, ModelToolCall, ModelUsage
from cv_agent.domain.evidence import ReActStep, ToolObservation, ValidationStatus
from cv_agent.harness import FULL_SYSTEM_HARNESS
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.agents.react import ReActEngine, run_expert, run_planner, parse_final_json, validate_conclusion
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import CodeDocument


ENTRY_PATH = "entry.py::entry@1-2"


def test_final_json_accepts_only_complete_wrappers():
    assert parse_final_json('```json\n{"label":"ABSTAIN"}\n```') == {"label":"ABSTAIN"}
    for text in ['explanation\n```json\n{}\n```', '```json\n{}\n```\nextra',
                 '```python\n{}\n```', '```json\n{}']:
        with pytest.raises(ValueError):
            parse_final_json(text)


def test_validation_plan_schema_bounds_planner_text_fields():
    schema = ValidationPlan.model_json_schema()
    subtask = schema["$defs"]["ValidationSubtask"]["properties"]
    assert schema["properties"]["rationale"]["maxLength"] == 600
    assert subtask["objective"]["maxLength"] == 280
    assert subtask["success_condition"]["maxLength"] == 220

    with pytest.raises(ValueError):
        ValidationPlan.model_validate({
            "candidate_id": "case:entry",
            "vulnerability_hypotheses": ["CWE-78"],
            "rationale": "x" * 601,
            "subtasks": [{
                "task_id": "t1",
                "objective": "locate sink",
                "expert": "scan",
                "allowed_validator": "run_static_check",
                "dependencies": [],
                "success_condition": "sink found",
            }],
        })


def test_expert_final_schema_bounds_rationale():
    schema = AgentExpertConclusion.model_json_schema()
    assert schema["properties"]["rationale"]["maxLength"] == 360

    with pytest.raises(ValueError):
        AgentExpertConclusion.model_validate({
            "expert": "scan",
            "label": "ABSTAIN",
            "confidence": 0.0,
            "validation_status": "UNRESOLVED",
            "evidence_ids": [],
            "rationale": "x" * 361,
        })


def test_last_existing_step_is_finalization_only_and_still_requires_evidence():
    conclusion = dict(expert="scan", label="ABSTAIN", confidence=0.2,
                      validation_status="UNRESOLVED", evidence_ids=[], rationale="Insufficient evidence")
    model = ScriptedChatModel([_tool_reply(), ModelReply(model_id="scripted",content=json.dumps(conclusion))])
    engine = ReActEngine(model=model, tools=_registry(), scope=_scope(),
                        harness=FULL_SYSTEM_HARNESS.react_loop.model_copy(update={"max_steps":2}))
    vote = run_expert(engine,expert="scan",system_prompt="Inspect",task_prompt="Review",
                      allowed_tools=("read_span",))
    assert vote.label == "ABSTAIN"
    assert vote.model_calls == 2
    assert model.requests[0][1]
    assert not model.requests[1][1]
    assert "final model step" in model.requests[1][0][-1].content
    assert "not your confidence" in model.requests[0][0][0].content
    assert "file:line markers are not tool paths" in model.requests[0][0][0].content
    assert "REFUTED, use label SAFE" in model.requests[0][0][0].content


def test_final_step_cannot_upgrade_a_read_to_typed_confirmation():
    conclusion = dict(expert="scan",label="VULNERABLE",confidence=1,
                      validation_status="CONFIRMED",evidence_ids=["tool:1"],rationale="Claim")
    model = ScriptedChatModel([_tool_reply(), ModelReply(model_id="scripted",content=json.dumps(conclusion))])
    engine = ReActEngine(model=model,tools=_registry(),scope=_scope(),
                        harness=FULL_SYSTEM_HARNESS.react_loop.model_copy(update={"max_steps":2}))
    with pytest.raises(RuntimeError,match="exhausted"):
        run_expert(engine,expert="scan",system_prompt="Inspect",task_prompt="Review",allowed_tools=("read_span",))


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
        "validation_status": "UNRESOLVED",
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


def test_penultimate_finalization_allows_schema_correction_without_tools():
    invalid = '{"expert":"scan","label":"VULNERABLE","confidence":0.9,"validation_status":"UNRESOLVED","evidence_ids":["span:entry.py::entry@1-2"], rationale":"bad"}'
    fixed = {
        "expert": "scan",
        "label": "VULNERABLE",
        "confidence": 0.9,
        "validation_status": "UNRESOLVED",
        "evidence_ids": [f"span:{ENTRY_PATH}"],
        "rationale": "The externally supplied value reaches eval.",
    }
    model = ScriptedChatModel([
        _tool_reply(),
        ModelReply(model_id="scripted-security-model", content=invalid),
        ModelReply(model_id="scripted-security-model", content=json.dumps(fixed)),
    ])
    engine = ReActEngine(
        model=model,
        tools=_registry(),
        scope=_scope(),
        harness=FULL_SYSTEM_HARNESS.react_loop.model_copy(update={"max_steps": 3}),
    )

    vote = run_expert(
        engine,
        expert="scan",
        system_prompt="scan",
        task_prompt="inspect",
        allowed_tools=("read_span",),
    )

    correction_messages = model.requests[2][0]
    rejected_index = next(
        i for i, message in enumerate(correction_messages)
        if message.role == "assistant" and message.content == invalid
    )
    assert "failed schema or evidence validation" in correction_messages[rejected_index + 1].content
    assert vote.model_calls == 3
    assert vote.label == "VULNERABLE"
    assert not model.requests[1][1]
    assert not model.requests[2][1]
    assert "tool-call budget is now closed" in model.requests[1][0][-1].content
    assert "no more tool calls are available" in model.requests[2][0][-1].content.lower()


def test_unresolved_safe_cannot_rely_only_on_source_read():
    weak_safe = {
        "expert": "scan",
        "label": "SAFE",
        "confidence": 0.9,
        "validation_status": "UNRESOLVED",
        "evidence_ids": [f"span:{ENTRY_PATH}"],
        "rationale": "No issue was visible in the local span.",
    }
    abstain = {
        "expert": "scan",
        "label": "ABSTAIN",
        "confidence": 0.2,
        "validation_status": "UNRESOLVED",
        "evidence_ids": [],
        "rationale": "Insufficient affirmative counter-evidence.",
    }
    model = ScriptedChatModel(
        [
            _tool_reply(),
            ModelReply(model_id="scripted-security-model", content=json.dumps(weak_safe)),
            ModelReply(model_id="scripted-security-model", content=json.dumps(abstain)),
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

    assert vote.label == "ABSTAIN"
    assert vote.model_calls == 3
    assert "SAFE/UNRESOLVED requires affirmative counter-evidence" in model.requests[-1][0][-1].content
    rejected = model.requests[-1][0][-2]
    assert rejected.role == "assistant"
    assert json.loads(rejected.content) == weak_safe


def test_unresolved_safe_cannot_rely_only_on_empty_repository_search():
    weak_safe = {
        "expert": "scan",
        "label": "SAFE",
        "confidence": 0.9,
        "validation_status": "UNRESOLVED",
        "evidence_ids": ["tool:1"],
        "rationale": "The repository search returned no matching symbols.",
    }
    abstain = {
        "expert": "scan",
        "label": "ABSTAIN",
        "confidence": 0.2,
        "validation_status": "UNRESOLVED",
        "evidence_ids": [],
        "rationale": "Search absence is not a safety proof.",
    }
    model = ScriptedChatModel(
        [
            ModelReply(
                model_id="scripted-security-model",
                tool_calls=(
                    ModelToolCall(
                        call_id="search-1",
                        name="search_symbols",
                        arguments={"query": "definitely_missing_symbol"},
                    ),
                ),
            ),
            ModelReply(model_id="scripted-security-model", content=json.dumps(weak_safe)),
            ModelReply(model_id="scripted-security-model", content=json.dumps(abstain)),
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
        allowed_tools=("search_symbols",),
    )

    assert vote.label == "ABSTAIN"
    assert vote.trace[0].observation.metadata["result_count"] == 0


def test_command_sanitized_observation_only_contradicts_when_referenced():
    read_observation = ToolObservation(
        tool="read_span",
        status="ok",
        content="def entry(value): return subprocess.Popen(value)",
        evidence_ids=(f"span:{ENTRY_PATH}",),
        citation_id="tool:1",
    )
    command_observation = ToolObservation(
        tool="inspect_command_construction",
        status="ok",
        content=json.dumps(
            {"command_construction_status": "SANITIZED", "status": "UNRESOLVED"}
        ),
        evidence_ids=("command_construction:entry.py",),
        citation_id="tool:2",
        validation_status=ValidationStatus.UNRESOLVED,
    )
    trace = [
        ReActStep(
            step=1,
            model_id="scripted",
            tool_call=ModelToolCall(call_id="read", name="read_span", arguments={}),
            observation=read_observation,
        ),
        ReActStep(
            step=2,
            model_id="scripted",
            tool_call=ModelToolCall(
                call_id="command",
                name="inspect_command_construction",
                arguments={},
            ),
            observation=command_observation,
        ),
    ]
    output = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=(f"span:{ENTRY_PATH}",),
        rationale="The cited source evidence supports the command risk.",
    )

    validate_conclusion(output, trace, frozenset())

    with pytest.raises(ValueError, match="command-construction counter-evidence"):
        validate_conclusion(
            output.model_copy(
                update={"evidence_ids": ("command_construction:entry.py",)}
            ),
            trace,
            frozenset(),
        )


def test_expert_identity_is_corrected_inside_existing_budget():
    conclusion = dict(expert="taint", label="ABSTAIN", confidence=0.2,
                      validation_status="UNRESOLVED", evidence_ids=[],
                      rationale="Insufficient evidence.")
    model = ScriptedChatModel([
        _tool_reply(),
        ModelReply(model_id="scripted", content=json.dumps(conclusion)),
        ModelReply(model_id="scripted", content=json.dumps({**conclusion, "expert":"scan"})),
    ])
    engine = ReActEngine(model=model, tools=_registry(), scope=_scope(),
                        harness=FULL_SYSTEM_HARNESS.react_loop)
    vote = run_expert(engine, expert="scan", system_prompt="Inspect code.",
                      task_prompt="Review entry.", allowed_tools=("read_span",))
    assert vote.expert == "scan"
    assert vote.model_calls == 3
    assert any("expected scan, got taint" in (message.content or "")
               for message in model.requests[-1][0])
    assert "assigned expert identity is scan" in model.requests[0][0][0].content


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
        "validation_status": "UNRESOLVED",
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


@pytest.mark.parametrize("other_role", ["counter_observation_ids", "unresolved_observation_ids"])
def test_safe_evidence_role_error_explains_how_to_correct_citation(other_role):
    observation = ToolObservation(
        tool="inspect_command_construction", status="ok",
        content='{"command_construction_status":"SANITIZED"}',
        evidence_ids=("command:entry",), citation_id="tool:1",
        validation_status=ValidationStatus.UNRESOLVED,
    )
    trace = [ReActStep(
        step=1, model_id="scripted",
        tool_call=ModelToolCall(call_id="inspect", name=observation.tool, arguments={}),
        observation=observation,
    )]
    output = AgentExpertConclusion(
        expert="taint", label="SAFE", confidence=0.8,
        validation_status=ValidationStatus.UNRESOLVED,
        evidence_ids=("tool:1",), rationale="Observed shell quoting.",
        **{other_role: ("tool:1",)},
    )
    with pytest.raises(ValueError, match="supporting_observation_ids"):
        validate_conclusion(output, trace, frozenset())
    corrected = output.model_copy(update={
        other_role: (), "supporting_observation_ids": ("tool:1",),
    })
    validate_conclusion(corrected, trace, frozenset())
    # Merely reclassifying a source read must still not establish safety.
    read = observation.model_copy(update={"tool": "read_span", "content": "source"})
    with pytest.raises(ValueError, match="affirmative"):
        validate_conclusion(corrected, [trace[0].model_copy(update={"observation": read})],
                            frozenset())


def test_overlong_rationale_feedback_gives_exact_length_and_short_target():
    bad = dict(expert='scan', label='VULNERABLE', confidence=0.8,
               validation_status='UNRESOLVED', evidence_ids=['tool:1'],
               rationale='Observed source reaches eval. ' * 20)
    good = dict(bad, rationale='Observed input reaches eval.')
    model = ScriptedChatModel([
        _tool_reply(), ModelReply(model_id='scripted', content=json.dumps(bad)),
        ModelReply(model_id='scripted', content=json.dumps(good)),
    ])
    engine = ReActEngine(model=model, tools=_registry(), scope=_scope(),
                        harness=FULL_SYSTEM_HARNESS.react_loop.model_copy(update={'max_steps': 3}))
    vote = run_expert(engine, expert='scan', system_prompt='Inspect', task_prompt='Review',
                      allowed_tools=('read_span',))
    feedback = '\n'.join(m.content or '' for m in model.requests[-1][0] if m.role == 'user')
    assert f'rationale has {len(bad["rationale"])} characters' in feedback
    assert 'at most 360 characters' in feedback
    assert 'one sentence under 180 characters' in feedback
    assert vote.rationale == good['rationale']
    assert vote.label == 'VULNERABLE'
    assert vote.model_calls == 3
