from cv_agent.agents.applicability import (
    ApplicabilityVerdict,
    evaluate_expert_applicability_v1,
)
from cv_agent.domain.review import ValidationPlan, ValidationSubtask
from cv_agent.domain.types import Candidate
from cv_agent.tools.identity import candidate_subject


def test_command_execution_excludes_authz():
    candidate = Candidate(
        candidate_id="c1",
        case_id="c1",
        repository_id="r",
        path="backend.py",
        line=1,
        query="get_cmd",
        property_id="command-execution",
        analysis_scope="Shell command execution only.",
    )
    verdict = evaluate_expert_applicability_v1(candidate, "authz")
    assert verdict.status == "not_applicable"
    assert "authorization boundary" in verdict.reason


def test_explicit_task_makes_expert_applicable():
    candidate = Candidate(
        candidate_id="c1",
        case_id="c1",
        repository_id="r",
        path="backend.py",
        line=1,
        query="get_cmd",
        property_id="command-execution",
    )
    plan = ValidationPlan(
        candidate_id="c1",
        vulnerability_hypotheses=("test",),
        subtasks=(
            ValidationSubtask(
                task_id="t1",
                expert="authz",
                allowed_validator="compare_route_and_service_guard",
                objective="Check guards.",
                dependencies=(),
                success_condition="ok",
            ),
        ),
        rationale="test",
    )
    verdict = evaluate_expert_applicability_v1(candidate, "authz", plan=plan)
    assert verdict.status == "applicable"


def test_hp001_race_property_remains_undetermined():
    candidate = Candidate(
        candidate_id="c1",
        case_id="c1",
        repository_id="r",
        path="file_utils.py",
        line=1,
        query="chmod",
        property_id="temporary-directory-race",
    )
    # Temporary directory race may involve file system attackers and caller authorization
    for expert in ("scan", "taint", "authz"):
        verdict = evaluate_expert_applicability_v1(candidate, expert)
        assert verdict.status == "undetermined"


def test_unknown_property_remains_undetermined():
    candidate = Candidate(
        candidate_id="c1",
        case_id="c1",
        repository_id="r",
        path="other.py",
        line=1,
        query="unknown",
        property_id=None,
    )
    for expert in ("scan", "taint", "authz"):
        verdict = evaluate_expert_applicability_v1(candidate, expert)
        assert verdict.status == "undetermined"


def test_command_execution_with_auth_scope_remains_undetermined():
    candidate = Candidate(
        candidate_id="c1",
        case_id="c1",
        repository_id="r",
        path="backend.py",
        line=1,
        query="get_cmd",
        property_id="command-execution",
        analysis_scope="Assess user auth guard before command execution",
    )
    verdict = evaluate_expert_applicability_v1(candidate, "authz")
    assert verdict.status == "undetermined"


def test_command_execution_without_narrow_scope_remains_undetermined():
    candidate = Candidate(
        candidate_id="c1", case_id="c1", repository_id="r", path="backend.py",
        line=1, query="get_cmd", property_id="command-execution",
    )
    assert evaluate_expert_applicability_v1(candidate, "authz").status == "undetermined"
    mixed = candidate.model_copy(update={
        "analysis_scope": "Shell command execution and access control only."
    })
    assert evaluate_expert_applicability_v1(mixed, "authz").status == "undetermined"


def test_workflow_skips_not_applicable_expert():
    import json
    from cv_agent.agents.workflow import AgenticPipeline
    from cv_agent.domain.chat import ModelReply, ModelToolCall
    from cv_agent.domain.types import CodeDocument
    from cv_agent.harness import AgentSystemVersion
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.runtime.model import ScriptedChatModel
    from cv_agent.tools.registry import ToolRegistry
    from cv_agent.tools.validation import full_agent_tools

    doc = CodeDocument(repository_id="r", path="entry.py", text="def entry(): pass\n")
    index = RepositoryIndex([doc])
    tools = ToolRegistry(full_agent_tools(index), max_output_bytes=100000)
    candidate = Candidate(
        candidate_id="c1",
        case_id="c1",
        repository_id="r",
        path="entry.py",
        line=1,
        query="cmd",
        property_id="command-execution",
        analysis_scope="shell command execution only",
    )

    # The narrow command scope excludes authz only under the opted-in policy.
    reply_scan = ModelReply(
        model_id="scan-model",
        content=json.dumps({
            "expert": "scan",
            "label": "ABSTAIN",
            "confidence": 0.5,
            "validation_status": "UNRESOLVED",
            "evidence_ids": [],
            "supporting_observation_ids": [],
            "counter_observation_ids": [],
            "unresolved_observation_ids": [],
            "rationale": "Evidence incomplete.",
        }),
    )
    reply_taint = ModelReply(
        model_id="taint-model",
        content=json.dumps({
            "expert": "taint",
            "label": "ABSTAIN",
            "confidence": 0.5,
            "validation_status": "UNRESOLVED",
            "evidence_ids": [],
            "supporting_observation_ids": [],
            "counter_observation_ids": [],
            "unresolved_observation_ids": [],
            "rationale": "Evidence incomplete.",
        }),
    )
    plan_obj = ValidationPlan(
        candidate_id="c1",
        vulnerability_hypotheses=("vulnerability",),
        subtasks=(
            ValidationSubtask(task_id="t_scan", expert="scan", allowed_validator="run_static_check", objective="scan", dependencies=(), success_condition="ok"),
            ValidationSubtask(task_id="t_taint", expert="taint", allowed_validator="trace_dataflow", objective="taint", dependencies=(), success_condition="ok"),
        ),
        rationale="plan without authz",
    )
    pipeline_e4 = AgenticPipeline(
        index=index,
        system=AgentSystemVersion.E4_GRAPH_MULTI,
        models={
            "planner": ScriptedChatModel([
                ModelReply(model_id="p", tool_calls=(ModelToolCall(call_id="c1", name="read_span", arguments={"path": "entry.py"}),)),
                ModelReply(model_id="p", content=plan_obj.model_dump_json()),
            ]),
            "scan": ScriptedChatModel([
                ModelReply(model_id="scan-model", tool_calls=(ModelToolCall(call_id="s1", name="run_static_check", arguments={"path": "entry.py"}),)),
                reply_scan,
            ]),
            "taint": ScriptedChatModel([
                ModelReply(model_id="taint-model", tool_calls=(ModelToolCall(call_id="t1", name="trace_dataflow", arguments={"source_path": "entry.py"}),)),
                reply_taint,
            ]),
            "authz": ScriptedChatModel([]),  # authz should NEVER be called!
        },
        tools=tools,
        expert_policy="applicable_v1",
    )
    verdict = pipeline_e4.run(candidate)
    assert verdict.label == "ABSTAIN"
    assert tuple(v.expert for v in verdict.votes) == ("scan", "taint")
    assert "authz" not in [v.expert for v in verdict.votes]
    assert set(verdict.skipped_experts) == {"authz"}
    assert "authorization boundary" in verdict.skipped_experts["authz"]
    assert pipeline_e4.models["authz"].requests == []

    fixed_models = {
        "planner": ScriptedChatModel([
            ModelReply(model_id="p", tool_calls=(ModelToolCall(
                call_id="c1", name="read_span", arguments={"path": "entry.py"}
            ),)),
            ModelReply(model_id="p", content=plan_obj.model_dump_json()),
        ]),
        "scan": ScriptedChatModel([
            ModelReply(model_id="scan", tool_calls=(ModelToolCall(
                call_id="s1", name="run_static_check", arguments={"path": "entry.py"}
            ),)),
            reply_scan,
        ]),
        "taint": ScriptedChatModel([
            ModelReply(model_id="taint", tool_calls=(ModelToolCall(
                call_id="t1", name="trace_dataflow", arguments={"source_path": "entry.py"}
            ),)),
            reply_taint,
        ]),
        "authz": ScriptedChatModel([
            ModelReply(model_id="authz", tool_calls=(ModelToolCall(
                call_id="a1", name="compare_route_and_service_guard",
                arguments={"route_path": "entry.py"},
            ),)),
            ModelReply(model_id="authz", content=json.dumps({
                **json.loads(reply_scan.content), "expert": "authz",
            })),
        ]),
    }
    fixed = AgenticPipeline(
        index=index, system=AgentSystemVersion.E4_GRAPH_MULTI,
        models=fixed_models, tools=tools,
    )
    fixed_verdict = fixed.run(candidate)
    assert tuple(v.expert for v in fixed_verdict.votes) == ("scan", "taint", "authz")
    assert fixed_models["authz"].requests
    assert "skipped_experts" not in fixed_verdict.model_dump()


def test_workflow_insufficient_applicable_roles(monkeypatch):
    import json
    from cv_agent.agents.workflow import AgenticPipeline
    from cv_agent.domain.chat import ModelReply, ModelToolCall
    from cv_agent.domain.types import CodeDocument
    from cv_agent.harness import AgentSystemVersion
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.runtime.model import ScriptedChatModel
    from cv_agent.tools.registry import ToolRegistry
    from cv_agent.tools.validation import full_agent_tools

    doc = CodeDocument(repository_id="r", path="entry.py", text="def entry(): pass\n")
    index = RepositoryIndex([doc])
    tools = ToolRegistry(full_agent_tools(index), max_output_bytes=100000)
    candidate = Candidate(
        candidate_id="c1",
        case_id="c1",
        repository_id="r",
        path="entry.py",
        line=1,
        query="cmd",
        property_id="command-execution",
        analysis_scope="shell command execution only",
    )
    reply_scan = ModelReply(
        model_id="scan-model",
        content=json.dumps({
            "expert": "scan",
            "label": "ABSTAIN",
            "confidence": 0.5,
            "validation_status": "UNRESOLVED",
            "evidence_ids": [],
            "supporting_observation_ids": [],
            "counter_observation_ids": [],
            "unresolved_observation_ids": [],
            "rationale": "Evidence incomplete.",
        }),
    )
    # Simulate a later policy category that also excludes taint. The E4 harness
    # and its quorum remain unchanged while only scan is applicable.
    from cv_agent.agents import applicability

    evaluate = applicability.evaluate_expert_applicability_v1

    def one_role_only(candidate, expert, plan=None):
        if expert == "taint":
            return ApplicabilityVerdict(
                expert="taint", status="not_applicable",
                reason="Synthetic narrow-scope exclusion for the quorum test.",
            )
        return evaluate(candidate, expert, plan=plan)

    monkeypatch.setattr(applicability, "evaluate_expert_applicability_v1", one_role_only)
    plan_obj = ValidationPlan(
        candidate_id="c1",
        vulnerability_hypotheses=("vulnerability",),
        subtasks=(
            ValidationSubtask(task_id="t_scan", expert="scan", allowed_validator="run_static_check", objective="scan", dependencies=(), success_condition="ok"),
        ),
        rationale="plan with only scan",
    )
    pipeline = AgenticPipeline(
        index=index,
        system=AgentSystemVersion.E4_GRAPH_MULTI,
        models={
            "planner": ScriptedChatModel([
                ModelReply(model_id="p", tool_calls=(ModelToolCall(call_id="c1", name="read_span", arguments={"path": "entry.py"}),)),
                ModelReply(model_id="p", content=plan_obj.model_dump_json()),
            ]),
            "scan": ScriptedChatModel([
                ModelReply(model_id="scan-model", tool_calls=(ModelToolCall(call_id="s1", name="run_static_check", arguments={"path": "entry.py"}),)),
                reply_scan,
            ]),
            "taint": ScriptedChatModel([]),
            "authz": ScriptedChatModel([]),
        },
        tools=tools,
        expert_policy="applicable_v1",
    )
    verdict = pipeline.run(candidate)
    assert verdict.label == "ABSTAIN"
    assert "insufficient_applicable_roles" in verdict.rationale
    assert set(verdict.skipped_experts) == {"taint", "authz"}
    assert pipeline.models["taint"].requests == []
    assert pipeline.models["authz"].requests == []


def test_applicable_policy_keeps_explicit_dependency_role():
    from cv_agent.agents.workflow import AgenticPipeline
    from cv_agent.domain.chat import ModelUsage
    from cv_agent.domain.review import RoutingResult
    from cv_agent.domain.types import CodeDocument
    from cv_agent.harness import AgentRuntimeMode, AgentSystemVersion
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.runtime.model import ScriptedChatModel
    from cv_agent.tools.registry import ToolRegistry
    from cv_agent.tools.validation import full_agent_tools

    doc = CodeDocument(repository_id="r", path="backend.py", text="def handle(): pass\n")
    index = RepositoryIndex([doc])
    candidate = Candidate(
        candidate_id="c1", case_id="c1", repository_id="r", path=doc.path,
        line=1, query="command", property_id="command-execution",
        analysis_scope="Shell command execution only.",
    )
    plan = ValidationPlan(
        candidate_id="c1", vulnerability_hypotheses=("Check scoped command.",),
        subtasks=(
            ValidationSubtask(
                task_id="guard", expert="authz",
                allowed_validator="compare_route_and_service_guard",
                objective="Inspect guard.", dependencies=(), success_condition="Record guard.",
            ),
            ValidationSubtask(
                task_id="sink", expert="scan", allowed_validator="run_static_check",
                objective="Inspect sink.", dependencies=("guard",),
                success_condition="Record sink.",
            ),
            ValidationSubtask(
                task_id="flow", expert="taint", allowed_validator="trace_dataflow",
                objective="Inspect flow.", dependencies=("guard",),
                success_condition="Record flow.",
            ),
        ),
        rationale="Guard precedes other checks.",
    )
    pipeline = AgenticPipeline(
        index=index, system=AgentSystemVersion.E4_GRAPH_MULTI,
        models={role: ScriptedChatModel([]) for role in ("planner", "scan", "taint", "authz")},
        tools=ToolRegistry(full_agent_tools(index), max_output_bytes=100000),
        expert_policy="applicable_v1",
    )
    state = {
        "candidate": candidate, "planner": None,
        "routing": RoutingResult(
            runtime_mode=AgentRuntimeMode.SCRIPTED, mode="off", model_calls=0,
            tool_calls=0, usage=ModelUsage(), plan=plan,
        ),
        "votes": [], "task_executions": [],
    }
    assert pipeline._next_task(state)[1].task_id == "guard"


def test_shared_evaluation_entry_forwards_opted_in_policy(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from cv_agent.evaluation import execution
    from cv_agent.domain.types import CodeDocument
    from cv_agent.harness import AgentSystemVersion
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.runtime.budget import Budget
    from cv_agent.runtime.journal import Journal

    seen = []

    class PipelineStub:
        def __init__(self, **kwargs):
            seen.append(kwargs["expert_policy"])

        def run(self, candidate):
            return SimpleNamespace(
                label="ABSTAIN",
                model_dump=lambda **kwargs: {
                    "label": "ABSTAIN", "expert_policy": "applicable_v1",
                    "skipped_experts": {"authz": "narrow command scope"},
                },
            )

    monkeypatch.setattr(execution, "AgenticPipeline", PipelineStub)
    index = RepositoryIndex([CodeDocument(
        repository_id="r", path="entry.py", text="def entry(): pass\n"
    )])
    candidate = Candidate(
        candidate_id="c1", case_id="c1", repository_id="r", path="entry.py",
        line=1, query="command", property_id="command-execution",
        analysis_scope="Shell command execution only.",
    )
    row = execution.run_candidate(
        index, candidate, AgentSystemVersion.E4_GRAPH_MULTI,
        Journal(tmp_path / "events.jsonl"), Budget(5, 10),
        model_config={
            "base_url": "https://offline.invalid/v1", "model": "offline",
            "temperature": 0, "timeout_seconds": 1,
        },
        api_key="offline", expert_policy="applicable_v1",
    )
    assert row["status"] == "abstained"
    assert row["verdict"]["skipped_experts"] == {"authz": "narrow command scope"}
    assert seen == ["applicable_v1"]


def test_applicable_quorum_needs_two_material_ballots_and_fixed_still_schedules_authz():
    from cv_agent.agents.workflow import AgenticPipeline
    from cv_agent.domain.chat import ModelUsage
    from cv_agent.domain.review import AgentExpertVote, RoutingResult, ValidationTaskExecution
    from cv_agent.domain.types import CodeDocument
    from cv_agent.harness import AgentRuntimeMode, AgentSystemVersion
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.runtime.model import ScriptedChatModel
    from cv_agent.tools.registry import ToolRegistry
    from cv_agent.tools.validation import full_agent_tools

    doc = CodeDocument(repository_id="r", path="entry.py", text="def entry(): pass\n")
    index = RepositoryIndex([doc])
    candidate = Candidate(
        candidate_id="c1", case_id="c1", repository_id="r", path=doc.path,
        line=1, query="command", property_id="command-execution",
        analysis_scope="Shell command execution only.",
    )
    plan = ValidationPlan(
        candidate_id="c1", vulnerability_hypotheses=("Check command.",),
        subtasks=(
            ValidationSubtask(
                task_id="scan-task", expert="scan", allowed_validator="run_static_check",
                objective="Scan.", dependencies=(), success_condition="Record scan.",
            ),
            ValidationSubtask(
                task_id="taint-task", expert="taint", allowed_validator="trace_dataflow",
                objective="Trace.", dependencies=(), success_condition="Record flow.",
            ),
        ),
        rationale="Check two independent specialties.",
    )
    tools = ToolRegistry(full_agent_tools(index), max_output_bytes=100000)
    models = {role: ScriptedChatModel([]) for role in ("planner", "scan", "taint", "authz")}
    applicable = AgenticPipeline(
        index=index, system=AgentSystemVersion.E4_GRAPH_MULTI,
        models=models, tools=tools, expert_policy="applicable_v1",
    )
    fixed = AgenticPipeline(
        index=index, system=AgentSystemVersion.E4_GRAPH_MULTI,
        models=models, tools=tools,
    )

    def make_vote(role, label):
        return AgentExpertVote(
            expert=role, label=label, confidence=0.9,
            validation_status="UNRESOLVED", evidence_ids=(),
            rationale="Synthetic ballot for adjudication policy.",
            runtime_mode=AgentRuntimeMode.SCRIPTED, trace=(), model_ids=(role,),
            model_calls=1, tool_calls=1, tool_observation_token_count=0,
            usage=ModelUsage(input_tokens=1, output_tokens=1, total_tokens=2),
        )

    def state(second_label):
        votes = [make_vote("scan", "VULNERABLE"), make_vote("taint", second_label)]
        return {
            "candidate": candidate, "planner": None,
            "routing": RoutingResult(
                runtime_mode=AgentRuntimeMode.SCRIPTED, mode="off",
                model_calls=0, tool_calls=0, plan=plan,
            ),
            "votes": votes,
            "task_executions": [
                ValidationTaskExecution(task_id=task.task_id, vote=vote, validator_completed=True)
                for task, vote in zip(plan.subtasks, votes)
            ],
            "context_token_count": 0, "verdict": None, "fast_checked": False,
            "admission_subject_digest": candidate_subject(index, candidate).source_digest,
            "admission_records": (),
        }

    assert applicable._next_task(state("VULNERABLE")) is None
    assert fixed._next_task(state("VULNERABLE")) == ("authz", None)
    winning = applicable._adjudicate(state("VULNERABLE"))["verdict"]
    assert winning.label == "VULNERABLE"
    assert set(winning.skipped_experts) == {"authz"}
    divided = applicable._adjudicate(state("ABSTAIN"))["verdict"]
    assert divided.label == "ABSTAIN"
