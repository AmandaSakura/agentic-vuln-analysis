import json

import pytest

from cv_agent.tools.registry import AgentTool, ToolExecutionScope, ToolRegistry
from cv_agent.tools.repository import ReadSpanInput, repository_tools
from cv_agent.domain.chat import ModelReply, ModelToolCall, ModelUsage
from cv_agent.domain.evidence import FixtureProofScope, ToolObservation, ValidationStatus
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentRuntimeMode, AgentSystemVersion
from cv_agent.runtime.model import OpenAICompatibleChatModel, ScriptedChatModel
from cv_agent.retrieval import RepositoryIndex, prompt_token_upper_bound as context_text_token_count
from cv_agent.domain.types import Candidate, CodeDocument, FrozenModel
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.validation import FixtureCase, FixtureOutcome, full_agent_tools


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
        property_id="dynamic-evaluation",
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
    # C1/C5: keep rejected proposals observable when a test deliberately asks
    # for a material label without proof; a correction is an additional call.
    correction = ModelReply(model_id=f"scripted-{expert}", content=json.dumps({
        **conclusion, "label": "ABSTAIN", "validation_status": "UNRESOLVED",
    }))
    return ScriptedChatModel([tool_reply, conclusion_reply, correction])


def _models() -> dict[str, ScriptedChatModel]:
    return {
        "planner": _planner_model(),
        "scan": _expert_model(
            "scan",
            label="ABSTAIN",
            confidence=0.9,
            validation_status="UNRESOLVED",
        ),
        "taint": _expert_model(
            "taint",
            label="ABSTAIN",
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
    assert result.label == "ABSTAIN"


def _proven_command_pipeline(system, models):
    # C1/C5: scheduling positives require real, matching command proofs.
    pipeline, candidate = _pipeline(system, models, source="import os\ndef handle(value):\n    os.system(value)\n")
    candidate = candidate.model_copy(update={"line": 2, "property_id": "command-execution", "input_parameters": ("value",)})
    plan_reply = models["planner"]._replies[-1]
    plan = json.loads(plan_reply.content)
    for task in plan["subtasks"][:2]:
        task["allowed_validator"] = "inspect_command_construction"
    models["planner"]._replies[-1] = plan_reply.model_copy(update={"content": json.dumps(plan)})
    for role in ("scan", "taint"):
        models[role] = _expert_model(role, label="VULNERABLE", confidence=.9, validation_status="UNRESOLVED")
        models[role]._replies[0] = ModelReply(model_id="scripted-command", tool_calls=(
            ModelToolCall(call_id=role+"-inspect", name="inspect_command_construction", arguments={"source_path": ENTRY_PATH}),))
    # The pipeline holds the supplied model mapping.
    pipeline.models.update(models)
    return pipeline, candidate


def test_agentic_fast_quorum_skips_authz_and_matches_full_review():
    full_models = _models()
    fast_models = _models()
    full_pipeline, candidate = _proven_command_pipeline(
        AgentSystemVersion.E4_GRAPH_MULTI,
        full_models,
    )
    fast_pipeline, _ = _proven_command_pipeline(
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


def test_agentic_fast_system_rejects_unsupported_safe_votes_and_matches_full_review():
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

    assert full.label == fast.label == "ABSTAIN"
    assert full.path == fast.path == "slow"
    assert len(full.votes) == len(fast.votes) == 3
    assert len(fast_models["authz"].requests) == 3
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
        label="ABSTAIN",
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
        label="ABSTAIN",
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
    candidate = candidate.model_copy(update={"property_id": "dynamic-evaluation", "input_parameters": ("request",)})
    from cv_agent.code_adapters.python import parse_python_source
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


def test_no_planner_scan_uses_registered_fixture_as_implicit_validator():
    document = CodeDocument(
        repository_id="repo",
        path=ENTRY_PATH,
        text=(
            "def handle(value):\n"
            "    command = get_cmd(value)\n"
            "    return subprocess.Popen(['bash', '-c', command])\n"
        ),
        defines=("handle",),
    )
    index = RepositoryIndex([document])
    candidate = Candidate(
        candidate_id="case-1",
        case_id="case-1",
        repository_id="repo",
        path=ENTRY_PATH,
        line=1,
        query="command fixture",
        property_id="command-execution",
        input_parameters=("value",),
    )
    fixture = FixtureCase(
        "case-1",
        lambda: FixtureOutcome(status="CONFIRMED", summary="bounded command witness"),
        subject=candidate_subject(index, candidate),
        proof_scope=FixtureProofScope(
            contract_id="contract-1",
            property_id="command-execution",
            coverage="candidate",
            method="bounded_execution",
            supported_statuses=(ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
        ),
    )
    model = ScriptedChatModel([
        ModelReply(model_id="offline", tool_calls=(ModelToolCall(
            call_id="fixture", name="run_fixture_test", arguments={"case_id": "case-1"},
        ),)),
        ModelReply(model_id="offline", content=json.dumps({
            "expert": "scan",
            "label": "VULNERABLE",
            "confidence": 1.0,
            "validation_status": "CONFIRMED",
            "evidence_ids": ["scan/tool:1", "fixture:case-1"],
            "supporting_observation_ids": ["scan/tool:1"],
            "counter_observation_ids": [],
            "unresolved_observation_ids": [],
            "rationale": "Registered fixture confirmed the candidate command property.",
        })),
    ])
    pipeline = AgenticPipeline(
        index=index,
        system=AgentSystemVersion.E3_GRAPH_SINGLE,
        models={"scan": model},
        tools=ToolRegistry(
            full_agent_tools(index, fixture_cases=(fixture,)),
            max_output_bytes=1_000_000,
        ),
    )

    verdict = pipeline.run(candidate)

    first_tool_names = {item["function"]["name"] for item in model.requests[0][1]}
    assert first_tool_names == {"run_fixture_test"}
    assert verdict.label == "VULNERABLE"
    assert verdict.votes[0].validation_status == ValidationStatus.CONFIRMED


PERMISSION_PATH = "tmpdir.py::get_or_create_tmp_dir@1-8"


def _permission_index_and_candidate(
    mode: str = "0o777", guard: str = "is_in_databricks_runtime() and get_repl_id() is not None",
    *, literal_body: bool = False,
) -> tuple[RepositoryIndex, Candidate]:
    shared_path = "'/tmp/mlflow'" if literal_body else "os.path.join('/tmp', 'mlflow')"
    private_path = "'/tmp/model'" if literal_body else "tempfile.mkdtemp()"
    cleanup = "pass" if literal_body else "atexit.register(shutil.rmtree, path, ignore_errors=True)"
    document = CodeDocument(
        repository_id="repo",
        path=PERMISSION_PATH,
        text=(
            "def get_or_create_tmp_dir():\n"
            f"    if {guard}:\n"
            f"        path = {shared_path}\n"
            "    else:\n"
            f"        path = {private_path}\n"
            f"        os.chmod(path, {mode})\n"
            f"        {cleanup}\n"
            "    return path\n"
        ),
        defines=("get_or_create_tmp_dir",),
    )
    index = RepositoryIndex([document])
    candidate = Candidate(
        property_id="chmod-mode-others-write",
        candidate_id="candidate-permission",
        case_id="case-permission",
        repository_id="repo",
        path=PERMISSION_PATH,
        line=1,
        query=document.text,
        analysis_scope="Assess only this exact source snapshot and candidate span.",
    )
    return index, candidate


def _permission_models(label: str, validation_status: str) -> dict[str, ScriptedChatModel]:
    plan = {
        "candidate_id": "candidate-permission",
        "vulnerability_hypotheses": ["filesystem permission weakness"],
        "subtasks": [
            {
                "task_id": "scan-mode",
                "objective": "Type the literal chmod mode sequence.",
                "expert": "scan",
                "allowed_validator": "validate_permission_mode",
                "dependencies": [],
                "success_condition": "The literal mode sequence is typed.",
            },
            {
                "task_id": "authz-mode",
                "objective": "Type the resource access mode.",
                "expert": "authz",
                "allowed_validator": "validate_permission_mode",
                "dependencies": ["scan-mode"],
                "success_condition": "The literal mode sequence is typed.",
            },
        ],
        "rationale": "Filesystem permission candidate.",
    }

    def expert(role: str) -> ScriptedChatModel:
        return ScriptedChatModel([
            ModelReply(model_id="offline", tool_calls=(ModelToolCall(
                call_id=f"{role}-permission", name="validate_permission_mode",
                arguments={"path": PERMISSION_PATH}),)),
            ModelReply(model_id="offline", content=json.dumps({
                "expert": role,
                "label": label,
                "confidence": 0.9,
                "validation_status": validation_status,
                "evidence_ids": [f"{role}/tool:1"],
                "rationale": "The candidate-bound validator typed the literal chmod mode.",
            })),
        ])

    return {
        "planner": ScriptedChatModel([
            ModelReply(model_id="offline", tool_calls=(ModelToolCall(
                call_id="planner-read", name="read_span",
                arguments={"path": PERMISSION_PATH}),)),
            ModelReply(model_id="offline", content=json.dumps(plan)),
        ]),
        "scan": expert("scan"),
        "authz": expert("authz"),
        "taint": ScriptedChatModel([
            ModelReply(model_id="offline", tool_calls=(ModelToolCall(
                call_id="taint-sources", name="find_sources",
                arguments={"path": PERMISSION_PATH}),)),
            ModelReply(model_id="offline", content=json.dumps({
                "expert": "taint",
                "label": "ABSTAIN",
                "confidence": 0.0,
                "validation_status": "UNRESOLVED",
                "evidence_ids": [],
                "rationale": "A filesystem mode is not a taint sink.",
            })),
        ]),
    }


def _permission_pipeline(index: RepositoryIndex, models) -> AgenticPipeline:
    return AgenticPipeline(
        index=index,
        system=AgentSystemVersion.E4_GRAPH_MULTI,
        models=models,
        tools=ToolRegistry(
            full_agent_tools(index),
            max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
        ),
    )


@pytest.mark.parametrize("mode", ["0o777", "0o750"])
def test_a_call_shaped_permission_guard_without_summary_abstains(mode):
    # C2/C3 migration (was: call-shaped guard reached a material verdict with
    # quorum): the guard calls have no verified purity summary, so the mode
    # validator stays UNRESOLVED and no material quorum may form. History
    # (hp001 scores) is not a constraint per contract. The scripted experts
    # first overclaim a typed verdict, are rejected by the gate, then abstain:
    # the production correction path, not a silent pass-through.
    index, candidate = _permission_index_and_candidate(mode)
    models = _permission_models("VULNERABLE", "CONFIRMED")
    for role in ("scan", "authz"):
        tool_reply, conclusion = models[role]._replies
        models[role] = ScriptedChatModel([
            tool_reply, conclusion,
            ModelReply(model_id="offline", content=json.dumps({
                "expert": role,
                "label": "ABSTAIN",
                "confidence": 0.0,
                "validation_status": "UNRESOLVED",
                "evidence_ids": [],
                "rationale": "Guard calls lack purity summaries; mode unjudgeable.",
            })),
        ])
    verdict = _permission_pipeline(index, models).run(candidate)

    assert verdict.label == "ABSTAIN"
    # A completed validator returning UNRESOLVED still satisfies scheduling
    # dependencies; this differs from never executing the validator at all.
    assert models["authz"].requests
    assert not verdict.blocked_tasks
    assert all(item.validator_completed is True for item in verdict.task_executions)
    assert not any(
        vote.label == "VULNERABLE" and vote.validation_status == ValidationStatus.CONFIRMED
        for vote in verdict.votes
    )


@pytest.mark.parametrize("transitive", [False, True])
def test_incomplete_validator_blocks_dependent_task_without_fabricating_calls(transitive):
    index, candidate = _permission_index_and_candidate(guard="enabled", literal_body=True)
    models = _permission_models("VULNERABLE", "CONFIRMED")
    if transitive:
        reply = models["planner"]._replies[-1]
        plan = json.loads(reply.content)
        plan["subtasks"].append({
            "task_id": "scan-followup", "expert": "scan",
            "allowed_validator": "validate_permission_mode", "dependencies": ["authz-mode"],
            "objective": "Recheck after authorization validation.",
            "success_condition": "Required predecessor validation completed.",
        })
        models["planner"]._replies[-1] = reply.model_copy(update={"content": json.dumps(plan)})
    read = ModelReply(model_id="offline", tool_calls=(ModelToolCall(
        call_id="read", name="read_span", arguments={"path": PERMISSION_PATH}),))
    abstain = ModelReply(model_id="offline", content=json.dumps({
        "expert": "scan", "label": "ABSTAIN", "confidence": 0.0,
        "validation_status": "UNRESOLVED", "evidence_ids": [],
        "rationale": "Assigned validator was never executed.",
    }))
    models["scan"] = ScriptedChatModel([read] * 6 + [abstain] * 2)
    result = _permission_pipeline(index, models).run(candidate)
    assert result.label == "ABSTAIN"
    assert not models["authz"].requests
    scan = next(item for item in result.task_executions if item.task_id == "scan-mode")
    assert scan.validator_completed is False
    expected_blocked = [("authz-mode", ("scan-mode",))]
    if transitive:
        expected_blocked.append(("scan-followup", ("authz-mode",)))
    assert [(item.task_id, item.dependencies) for item in result.blocked_tasks] == expected_blocked
    assert result.model_calls == sum(len(model.requests) for model in models.values())
    assert {item.vote.expert for item in result.task_executions} == {"scan", "taint"}


def test_a_refused_repeat_does_not_stop_the_expert_from_concluding():
    # C3 mechanism test: use a pure guard AND a body without unknown calls so the permission
    # validator still types the mode; the call-shaped guard migration lives in
    # test_a_call_shaped_permission_guard_without_summary_abstains.
    index, candidate = _permission_index_and_candidate(guard="False", literal_body=True)
    models = _permission_models("VULNERABLE", "CONFIRMED")
    tool_reply, conclusion = models["scan"]._replies
    models["scan"] = ScriptedChatModel([tool_reply, tool_reply, conclusion])

    verdict = _permission_pipeline(index, models).run(candidate)

    assert verdict.label == "VULNERABLE"
    scan = next(vote for vote in verdict.votes if vote.expert == "scan")
    assert [step.observation.status for step in scan.trace] == ["ok", "blocked"]
    assert scan.trace[0].observation.citation_id in scan.trace[1].observation.content
    # The refused repeat is not evidence: the conclusion still rests on the one
    # successful validator observation it already had.
    assert scan.evidence_ids == ("scan/tool:1",)
    authz = next(vote for vote in verdict.votes if vote.expert == "authz")
    assert authz.evidence_ids == ("authz/tool:1",)


def test_repeated_polling_spends_steps_but_still_yields_a_verdict():
    # The budget closes the tool phase before the last two model steps, so a model
    # that keeps re-asking must still finalize from the one observation it has rather
    # than failing the cell. This is the shape the held-out matrix cells hit.
    # C3 mechanism test: pure guard and body keep the mode validator typed (see the
    # call-shaped guard migration test for the C2/C3 behavior).
    index, candidate = _permission_index_and_candidate(guard="False", literal_body=True)
    models = _permission_models("VULNERABLE", "CONFIRMED")
    tool_reply, conclusion = models["scan"]._replies
    harness = FULL_SYSTEM_HARNESS.react_loop
    models["scan"] = ScriptedChatModel(
        [tool_reply] * (harness.max_steps - 2) + [conclusion]
    )

    verdict = _permission_pipeline(index, models).run(candidate)

    assert verdict.label == "VULNERABLE"
    scan = next(vote for vote in verdict.votes if vote.expert == "scan")
    statuses = [step.observation.status for step in scan.trace]
    assert statuses.count("ok") == 1
    assert statuses[1:] == ["blocked"] * (harness.max_steps - 3)
    assert scan.model_calls == harness.max_steps - 1


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


@pytest.mark.parametrize('system', list(AgentSystemVersion))
@pytest.mark.parametrize('property_id', [None, '', '   '])
def test_public_workflow_rejects_undeclared_property_before_model_calls(system, property_id):
    models = _models()
    pipeline, candidate = _pipeline(system, models)
    candidate = candidate.model_copy(update={'property_id': property_id})
    with pytest.raises(ValueError, match='property_id'):
        pipeline.run(candidate)
    assert all(not model.requests for model in models.values())
