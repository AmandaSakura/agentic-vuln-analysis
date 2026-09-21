import json

import pytest

from cv_agent.agent_tools import (
    AgentTool,
    ReadSpanInput,
    ToolExecutionScope,
    ToolRegistry,
    repository_tools,
)
from cv_agent.agent_types import (
    ModelReply,
    ModelToolCall,
    ModelUsage,
    ToolObservation,
)
from cv_agent.agentic_workflow import AgenticPipeline
from cv_agent.harness import (
    FULL_SYSTEM_HARNESS,
    AgentRuntimeMode,
    AgentSystemVersion,
)
from cv_agent.model_runtime import OpenAICompatibleChatModel, ScriptedChatModel
from cv_agent.retrieval import RepositoryIndex, prompt_token_upper_bound as context_text_token_count
from cv_agent.types import Candidate, CodeDocument, FrozenModel
from cv_agent.validation_tools import full_agent_tools


ENTRY_PATH = "handler.py::handle@1-3"


class LiveStubModel(ScriptedChatModel):
    runtime_mode = AgentRuntimeMode.LIVE


def _index_and_candidate(
    *,
    query: str | None = None,
    metadata: dict[str, object] | None = None,
    source: str | None = None,
) -> tuple[RepositoryIndex, Candidate]:
    document = CodeDocument(
        repository_id="repo",
        path=ENTRY_PATH,
        text=source if source is not None else (
            "def handle(request):\n"
            "    command = request.args['command']\n"
            "    return eval(command)\n"
        ),
        defines=("handle",),
    )
    index = RepositoryIndex([document])
    candidate = Candidate(
        candidate_id="candidate-1",
        case_id="case-1",
        repository_id="repo",
        path=ENTRY_PATH,
        line=1,
        query=document.text if query is None else query,
        metadata={} if metadata is None else metadata,
    )
    return index, candidate


def _tool_reply(role: str) -> ModelReply:
    name, key = {
        "scan": ("run_static_check", "path"),
        "taint": ("trace_dataflow", "source_path"),
        "authz": ("compare_route_and_service_guard", "route_path"),
    }.get(role, ("read_span", "path"))
    return ModelReply(
        model_id=f"scripted-{role}",
        tool_calls=(
            ModelToolCall(
                call_id=f"{role}-read",
                name=name,
                arguments={key: ENTRY_PATH},
            ),
        ),
    )


def _planner_model(
    *,
    scan_validator: str = "run_static_check",
) -> ScriptedChatModel:
    plan = {
        "candidate_id": "candidate-1",
        "vulnerability_hypotheses": ["code injection"],
        "subtasks": [
            {
                "task_id": "locate-sink",
                "objective": "Confirm the eval operation.",
                "expert": "scan",
                "allowed_validator": scan_validator,
                "dependencies": [],
                "success_condition": "The sink is externally reachable.",
            },
            {
                "task_id": "trace-command",
                "objective": "Trace request input to eval.",
                "expert": "taint",
                "allowed_validator": "trace_dataflow",
                "dependencies": ["locate-sink"],
                "success_condition": "An unsanitized path reaches eval.",
            },
            {
                "task_id": "check-guard",
                "objective": "Determine whether authorization is relevant.",
                "expert": "authz",
                "allowed_validator": "compare_route_and_service_guard",
                "dependencies": ["locate-sink"],
                "success_condition": "Authorization relevance is resolved.",
            },
        ],
        "rationale": "The route passes request data to dynamic evaluation.",
    }
    return ScriptedChatModel(
        [
            _tool_reply("planner"),
            ModelReply(model_id="scripted-planner", content=json.dumps(plan)),
        ]
    )


def _expert_model(
    expert: str,
    *,
    label: str,
    confidence: float,
    validation_status: str,
    report_usage: bool = False,
) -> ScriptedChatModel:
    conclusion = {
        "expert": expert,
        "label": label,
        "confidence": confidence,
        "validation_status": validation_status,
        "evidence_ids": [f"{expert}/tool:1"],
        "rationale": f"{expert} completed its assigned validation task.",
    }
    tool_reply = _tool_reply(expert)
    if expert == "taint" and label == "SAFE":
        tool_reply = tool_reply.model_copy(update={"tool_calls": (
            *tool_reply.tool_calls,
            ModelToolCall(call_id="taint-sanitizers", name="find_sanitizers",
                          arguments={"path": ENTRY_PATH}),
        )})
        conclusion["evidence_ids"] = ["taint/tool:2"]
    conclusion_reply = ModelReply(
        model_id=f"scripted-{expert}",
        content=json.dumps(conclusion),
    )
    if report_usage:
        tool_reply = tool_reply.model_copy(
            update={
                "usage": ModelUsage(
                    input_tokens=10,
                    output_tokens=4,
                    total_tokens=14,
                )
            }
        )
        conclusion_reply = conclusion_reply.model_copy(
            update={
                "usage": ModelUsage(
                    input_tokens=20,
                    output_tokens=12,
                    total_tokens=32,
                )
            }
        )
    return ScriptedChatModel([tool_reply, conclusion_reply])


def _models() -> dict[str, ScriptedChatModel]:
    return {
        "planner": _planner_model(),
        "scan": _expert_model(
            "scan",
            label="VULNERABLE",
            confidence=0.9,
            validation_status="UNRESOLVED",
        ),
        "taint": _expert_model(
            "taint",
            label="VULNERABLE",
            confidence=0.9,
            validation_status="UNRESOLVED",
        ),
        "authz": _expert_model(
            "authz",
            label="ABSTAIN",
            confidence=0.9,
            validation_status="UNRESOLVED",
        ),
    }


def _pipeline(
    system: AgentSystemVersion,
    models: dict[str, ScriptedChatModel],
    *,
    source: str | None = None,
) -> tuple[AgenticPipeline, Candidate]:
    index, candidate = _index_and_candidate(source=source)
    tools = ToolRegistry(
        full_agent_tools(index),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )
    return (
        AgenticPipeline(
            index=index,
            system=system,
            models=models,
            tools=tools,
        ),
        candidate,
    )


def _complete_tool_registry(index: RepositoryIndex) -> ToolRegistry:
    tools = list(repository_tools(index))
    names = {tool.name for tool in tools}
    required = set(FULL_SYSTEM_HARNESS.validation.validators)
    for expert in FULL_SYSTEM_HARNESS.experts:
        required.update(expert.tools)

    def placeholder(name: str):
        def handle(
            arguments: FrozenModel,
            scope: ToolExecutionScope,
        ) -> ToolObservation:
            del arguments, scope
            return ToolObservation(tool=name, status="ok", content="placeholder")

        return handle

    for name in sorted(required - names):
        tools.append(
            AgentTool(
                name=name,
                description="Typed test placeholder.",
                input_model=ReadSpanInput,
                handler=placeholder(name),
            )
        )
    return ToolRegistry(
        tools,
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )


def test_planner_can_inspect_context_with_the_configured_observation_budget():
    models = _models()
    pipeline, candidate = _pipeline(AgentSystemVersion.E4_GRAPH_MULTI, models)

    result = pipeline.run(candidate)

    assert result.planner is not None
    assert 0 < result.planner.tool_observation_token_count <= (
        FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens
    )
    assert len(models["planner"].requests) == 2
    assert result.label == "VULNERABLE"


def test_agentic_fast_quorum_skips_authz_and_matches_full_review():
    full_models = _models()
    fast_models = _models()
    full_pipeline, candidate = _pipeline(
        AgentSystemVersion.E4_GRAPH_MULTI,
        full_models,
    )
    fast_pipeline, _ = _pipeline(
        AgentSystemVersion.E5_GRAPH_FAST,
        fast_models,
    )

    full = full_pipeline.run(candidate)
    fast = fast_pipeline.run(candidate)

    assert full.label == fast.label == "VULNERABLE"
    assert full.path == "slow"
    assert fast.path == "fast"
    assert len(full.votes) == 3
    assert len(fast.votes) == 2
    assert len(full_models["authz"].requests) == 2
    assert len(fast_models["authz"].requests) == 0
    assert fast.planner is not None
    assert [task.expert for task in fast.planner.plan.subtasks] == [
        "scan",
        "taint",
        "authz",
    ]
    assert fast.model_calls == 6
    assert fast.tool_calls == 3
    assert fast.runtime_mode == AgentRuntimeMode.SCRIPTED
    assert fast.context_token_count == (
        fast.retrieval_context_token_count + fast.tool_observation_token_count
    )
    assert fast.tool_observation_token_count > 0
    assert fast.usage.total_tokens is None


def test_agentic_fast_system_falls_back_on_conflict_and_matches_full_review():
    full_models = _models()
    fast_models = _models()
    for models in (full_models, fast_models):
        models["taint"] = _expert_model(
            "taint",
            label="SAFE",
            confidence=0.9,
            validation_status="UNRESOLVED",
        )
        models["authz"] = _expert_model(
            "authz", label="SAFE", confidence=0.9, validation_status="UNRESOLVED",
        )

    # The two SAFE predictions have observable counter-evidence. The first scan
    # still predicts a possible eval issue so the quorum must resolve conflict.
    guarded_source = (
        "def handle(request):\n"
        "    require_permission(request.user, 'manage')\n"
        "    command = int(request.args['command'])\n"
        "    database.delete(command)\n"
        "    return eval(str(command))\n"
    )

    full_pipeline, candidate = _pipeline(
        AgentSystemVersion.E4_GRAPH_MULTI,
        full_models,
        source=guarded_source,
    )
    fast_pipeline, _ = _pipeline(
        AgentSystemVersion.E5_GRAPH_FAST,
        fast_models,
        source=guarded_source,
    )

    full = full_pipeline.run(candidate)
    fast = fast_pipeline.run(candidate)

    assert full.label == fast.label == "SAFE"
    assert full.path == fast.path == "slow"
    assert len(full.votes) == len(fast.votes) == 3
    assert len(fast_models["authz"].requests) == 2
    assert fast.model_calls == full.model_calls
    assert fast.tool_calls == full.tool_calls


def test_candidate_query_and_metadata_are_not_model_visible_or_unaccounted():
    secret = "ORACLE_GROUND_TRUTH_" * 2_000
    index, candidate = _index_and_candidate(
        query=secret,
        metadata={"ground_truth": secret},
    )
    scan = _expert_model(
        "scan",
        label="VULNERABLE",
        confidence=0.9,
        validation_status="UNRESOLVED",
    )
    tools = ToolRegistry(
        full_agent_tools(index),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )
    verdict = AgenticPipeline(
        index=index,
        system=AgentSystemVersion.E1_LOCAL_SINGLE,
        models={"scan": scan},
        tools=tools,
    ).run(candidate)
    user_prompt = scan.requests[0][0][1].content or ""
    task_prompt = user_prompt.split("\n\nUse the registered tools", maxsplit=1)[0]
    context_prompt = task_prompt.split(
        "\nAssigned validation subtasks:",
        maxsplit=1,
    )[0]

    assert secret not in user_prompt
    assert "ground_truth" not in user_prompt
    assert verdict.retrieval_context_token_count == context_text_token_count(
        context_prompt
    )
    assert verdict.retrieval_context_token_count <= (
        FULL_SYSTEM_HARNESS.system_spec(
            AgentSystemVersion.E1_LOCAL_SINGLE
        ).budget.total_context_tokens
    )


def test_cross_role_partial_usage_remains_unknown_in_verdict_aggregate():
    models = _models()
    models["scan"] = _expert_model(
        "scan",
        label="VULNERABLE",
        confidence=0.9,
        validation_status="UNRESOLVED",
        report_usage=True,
    )
    pipeline, candidate = _pipeline(
        AgentSystemVersion.E5_GRAPH_FAST,
        models,
    )

    verdict = pipeline.run(candidate)

    assert verdict.votes[0].usage.total_tokens == 46
    assert verdict.votes[1].usage.total_tokens is None
    assert verdict.usage.input_tokens is None
    assert verdict.usage.output_tokens is None
    assert verdict.usage.total_tokens is None


def test_live_pipeline_rejects_partial_smoke_tool_registry():
    index, _ = _index_and_candidate()
    tools = ToolRegistry(
        repository_tools(index),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )
    live = OpenAICompatibleChatModel(
        base_url="http://127.0.0.1:1/v1",
        model="unused-test-model",
        api_key=None,
        temperature=0.0,
        timeout_seconds=1,
    )
    models = {role: live for role in ("planner", "scan", "taint", "authz")}

    with pytest.raises(ValueError, match="lacks required Harness tools"):
        AgenticPipeline(
            index=index,
            system=AgentSystemVersion.E5_GRAPH_FAST,
            models=models,
            tools=tools,
        )


def test_runtime_mode_cannot_be_spoofed_by_a_scripted_subclass():
    index, _ = _index_and_candidate()
    models = {
        role: LiveStubModel([])
        for role in ("planner", "scan", "taint", "authz")
    }

    with pytest.raises(ValueError, match="untrusted chat-model runtime"):
        AgenticPipeline(
            index=index,
            system=AgentSystemVersion.E5_GRAPH_FAST,
            models=models,
            tools=_complete_tool_registry(index),
        )


@pytest.mark.parametrize("validator,error_fragment", [
    ("run_loopback_http_case", "which cannot execute it"),
    ("scan", "unregistered validator"),
    ("read_span", "unregistered validator"),
    ("run_fixture_test", "unavailable for this run"),
])
def test_planner_invalid_validator_is_rejected_and_can_be_corrected(validator, error_fragment):
    models = _models()
    models["planner"] = _planner_model(scan_validator=validator)
    models["planner"]._replies.append(_planner_model()._replies[-1])
    pipeline, candidate = _pipeline(
        AgentSystemVersion.E4_GRAPH_MULTI,
        models,
    )

    verdict = pipeline.run(candidate)
    assert verdict.planner.model_calls == 3
    assert error_fragment in models["planner"].requests[2][0][-1].content
    assert verdict.planner.plan.subtasks[0].allowed_validator == "run_static_check"


@pytest.mark.parametrize("system", [AgentSystemVersion.E4_GRAPH_MULTI, AgentSystemVersion.E5_GRAPH_FAST])
def test_unopposed_typed_validator_status_does_not_replace_workflow_quorum(system):
    models = _models()
    for role in ("taint", "authz"):
        models[role] = _expert_model(
            role, label="ABSTAIN", confidence=0.9, validation_status="UNRESOLVED",
        )
    # A real bounded probe is confirmation; the static taint tool no longer is.
    models["planner"] = _planner_model(scan_validator="probe_python_eval")
    models["scan"] = ScriptedChatModel([
        ModelReply(model_id="offline", tool_calls=(ModelToolCall(
            call_id="probe", name="probe_python_eval", arguments={"source_path": ENTRY_PATH}),)),
        ModelReply(model_id="offline", content=json.dumps(dict(expert="scan", label="VULNERABLE",
            confidence=1.0, validation_status="CONFIRMED", evidence_ids=["scan/tool:1"],
            rationale="Two inputs reached builtin eval"))),
    ])
    index, candidate = _index_and_candidate()
    from cv_agent.python_ast import parse_python_source
    index = RepositoryIndex(span.document for span in parse_python_source(
        "repo", "handler.py", index.document(ENTRY_PATH).text))
    pipeline = AgenticPipeline(index=index, system=system, models=models,
        tools=ToolRegistry(full_agent_tools(index), max_output_bytes=1000000))
    verdict = pipeline.run(candidate)
    scan = next(vote for vote in verdict.votes if vote.expert == "scan")
    ballot = next(vote for vote in pipeline._consensus_votes(list(verdict.votes)) if vote.expert == "scan")
    assert scan.validation_status.value == ballot.validation_status == "CONFIRMED"
    assert ballot.evidence_ids == ("scan/tool:1",)
    assert verdict.label == "ABSTAIN"
    assert verdict.path == "slow"
    assert "Fewer than 2" in verdict.rationale
    assert len(verdict.votes) == 3


def test_planner_receives_registered_validator_names_for_each_expert():
    models = _models()
    pipeline, candidate = _pipeline(AgentSystemVersion.E4_GRAPH_MULTI, models)
    pipeline.run(candidate)
    prompt = models["planner"].requests[0][0][1].content
    context = json.loads(prompt.split("Planning context: ", 1)[1].split("\nPlanning capabilities: ", 1)[0])
    capabilities = json.loads(
        prompt.split("Planning capabilities: ", 1)[1].split("\n\nUse the registered tools", 1)[0]
    )
    assert context["candidate"]["path"] == candidate.path
    assert context["retrieved_evidence_index"][0]["path"] == candidate.path
    assert "retrieved_code" not in context
    assert "request.args" not in prompt
    assert capabilities["maximum_subtasks"] == FULL_SYSTEM_HARNESS.planner_max_subtasks
    assert "Read the candidate span once" in context["instruction"]
    assert "requires independent expert ballots" in capabilities["verification_guidance"]
    assert "Keep the plan compact" in capabilities["final_json_contract"]
    assert capabilities["allowed_validators_by_expert"] == {
        "scan": ["run_static_check"],
        "taint": ["trace_dataflow"],
        "authz": ["compare_route_and_service_guard"],
    }
