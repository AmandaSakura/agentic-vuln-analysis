from cv_agent.agents.plan_policy import (
    TaskOrigin,
    compose_plan,
    has_candidate_fixture,
    is_command_construction_candidate,
    is_permission_candidate,
    required_tasks,
    validate_plan_policy,
)
import pytest

from cv_agent.domain.evidence import FixtureProofScope, ValidationStatus, ValidationSubject
from cv_agent.domain.chat import ModelReply, ModelToolCall
from cv_agent.domain.review import ValidationPlan, ValidationSubtask
from cv_agent.domain.types import Candidate, CodeDocument, Evidence
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentSystemVersion
from cv_agent.retrieval import RepositoryIndex
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation import FixtureCase, FixtureOutcome, full_agent_tools
from cv_agent.tools.validation.models import FixtureCapability


def _make_tools(fixtures=(), text="def entry():\n    get_cmd()\n    os.chmod()\n"):
    index = RepositoryIndex([CodeDocument(repository_id="r", path="entry.py", text=text)])
    return ToolRegistry(full_agent_tools(index, fixture_cases=fixtures), max_output_bytes=100000)


def test_command_construction_obligations():
    candidate = Candidate(
        candidate_id="c1",
        case_id="c1",
        repository_id="r",
        path="entry.py",
        line=1,
        query="get_cmd",
        property_id="command-execution",
        analysis_scope="get_cmd shell-command subprocess.Popen",
    )
    tools = _make_tools()
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)

    required = required_tasks(candidate, None, tools, spec)
    assert len(required) == 2
    validators = {(t.expert, t.allowed_validator) for t in required}
    assert validators == {
        ("scan", "inspect_command_construction"),
        ("taint", "inspect_command_construction"),
    }


def test_permission_obligations():
    candidate = Candidate(
        candidate_id="c1",
        case_id="c1",
        repository_id="r",
        path="entry.py",
        line=1,
        query="chmod",
        property_id="temporary-directory-race",
        analysis_scope="os.chmod mode check",
    )
    tools = _make_tools()
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)

    required = required_tasks(candidate, None, tools, spec)
    assert any(t.expert == "authz" and t.allowed_validator == "validate_permission_mode" for t in required)


def test_qualified_fixture_obligation_takes_precedence():
    # C1: the fixture subject must include the candidate's declared scope.
    subject = ValidationSubject(
        candidate_id="c1",
        repository_id="r",
        property_id="command-execution",
        entry_path="entry.py",
        entry_line=1,
        source_digest="sha" * 16,
        analysis_scope="get_cmd subprocess.Popen",
    )
    candidate = Candidate(
        candidate_id="c1",
        case_id="c1",
        repository_id="r",
        path="entry.py",
        line=1,
        query="get_cmd",
        property_id="command-execution",
        analysis_scope="get_cmd subprocess.Popen",
    )
    proof_scope = FixtureProofScope(
        contract_id="contract_qualified",
        property_id="command-execution",
        coverage="candidate",
        method="bounded_execution",
        supported_statuses=(ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
    )
    fixture = FixtureCase("c1", lambda: FixtureOutcome(status="CONFIRMED", summary="ok"), subject=subject, proof_scope=proof_scope)
    tools = _make_tools(fixtures=(fixture,))
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)

    required = required_tasks(candidate, None, tools, spec, subject=subject)
    assert len(required) == 1
    assert required[0].allowed_validator == "run_fixture_test"


def test_weak_local_fixture_does_not_suppress_command_obligation():
    subject = ValidationSubject(
        candidate_id="c1",
        repository_id="r",
        property_id="command-execution",
        entry_path="entry.py",
        entry_line=1,
        source_digest="sha" * 16,
    )
    candidate = Candidate(
        candidate_id="c1",
        case_id="c1",
        repository_id="r",
        path="entry.py",
        line=1,
        query="get_cmd",
        property_id="command-execution",
        analysis_scope="get_cmd subprocess.Popen",
    )
    weak_proof = FixtureProofScope(
        contract_id="contract_weak",
        property_id="command-execution",
        coverage="local",
        method="source_pattern",
        supported_statuses=(ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
    )
    fixture = FixtureCase("c1", lambda: FixtureOutcome(status="CONFIRMED", summary="ok"), subject=subject, proof_scope=weak_proof)
    tools = _make_tools(fixtures=(fixture,))
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)

    required = required_tasks(candidate, None, tools, spec, subject=subject)
    # Weak fixture does NOT suppress command obligation!
    validators = {t.allowed_validator for t in required}
    assert "inspect_command_construction" in validators
    assert "run_fixture_test" not in validators


def test_compose_plan_origins_and_deduplication():
    required = (
        ValidationSubtask(
            task_id="req-1",
            expert="scan",
            allowed_validator="inspect_command_construction",
            objective="obj",
            dependencies=(),
            success_condition="cond",
        ),
        ValidationSubtask(
            task_id="req-2",
            expert="taint",
            allowed_validator="inspect_command_construction",
            objective="obj",
            dependencies=(),
            success_condition="cond",
        ),
    )
    # Jev chose inspect_command_construction for scan (already required), and compare_guard for authz (optional)
    accepted_choices = {
        "scan": "inspect_command_construction",
        "authz": "compare_route_and_service_guard",
    }

    plan, origins = compose_plan("c1", required, accepted_choices)
    origin_map = {o.task_id: o.origin for o in origins}

    # scan inspect_command_construction was mandatory from policy, so origin is policy!
    assert origin_map["req-1"] == "policy"
    assert origin_map["req-2"] == "policy"
    # authz compare_route_and_service_guard was optional and chosen by Jev, so origin is jev!
    assert origin_map["jev-authz"] == "jev"

    # Total tasks = 3 (no duplicate scan tasks)
    assert len(plan.subtasks) == 3


def test_compose_plan_fixture_dependencies():
    required = (
        ValidationSubtask(
            task_id="req-fix",
            expert="scan",
            allowed_validator="run_fixture_test",
            objective="obj",
            dependencies=(),
            success_condition="cond",
        ),
    )
    accepted = {"taint": "trace_dataflow"}
    plan, origins = compose_plan("c1", required, accepted)
    taint_task = next(t for t in plan.subtasks if t.expert == "taint")
    assert "req-fix" in taint_task.dependencies


def _command_candidate_and_subject():
    candidate = Candidate(
        candidate_id="c1",
        case_id="c1",
        repository_id="r",
        path="entry.py",
        line=1,
        query="get_cmd",
        property_id="command-execution",
        analysis_scope="get_cmd shell-command subprocess.Popen",
    )
    subject = ValidationSubject(
        candidate_id="c1",
        repository_id="r",
        entry_path="entry.py",
        entry_line=1,
        source_digest="sha" * 16,
        property_id="command-execution",
        analysis_scope=candidate.analysis_scope,
    )
    return candidate, subject


def _task(task_id, expert, validator, dependencies=()):
    return ValidationSubtask(
        task_id=task_id,
        expert=expert,
        allowed_validator=validator,
        objective="Collect evidence",
        dependencies=dependencies,
        success_condition="Record result",
    )


@pytest.mark.parametrize("contract,subject_change", [
    (None, None),
    (("local", "bounded_execution", "command-execution", (ValidationStatus.CONFIRMED,)), None),
    (("candidate", "source_pattern", "command-execution", (ValidationStatus.CONFIRMED,)), None),
    (("candidate", "bounded_execution", "other-property", (ValidationStatus.CONFIRMED,)), None),
    (("candidate", "bounded_execution", "command-execution", ()), None),
    (("candidate", "bounded_execution", "command-execution", (ValidationStatus.CONFIRMED,)), "source_digest"),
])
def test_nonqualifying_fixture_cannot_waive_command_tasks(contract, subject_change):
    candidate, subject = _command_candidate_and_subject()
    fixture_subject = (
        subject.model_copy(update={"source_digest": "other" * 12})
        if subject_change == "source_digest" else subject
    )
    proof = None if contract is None else FixtureProofScope(
        contract_id="candidate-proof",
        coverage=contract[0],
        method=contract[1],
        property_id=contract[2],
        supported_statuses=contract[3],
    )
    fixture = FixtureCase(
        "c1", lambda: FixtureOutcome(status="CONFIRMED", summary="measurement"),
        subject=fixture_subject, proof_scope=proof,
    )
    tools = _make_tools(fixtures=(fixture,))
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)

    required = required_tasks(candidate, None, tools, spec, subject=subject)
    assert {(t.expert, t.allowed_validator) for t in required} == {
        ("scan", "inspect_command_construction"),
        ("taint", "inspect_command_construction"),
    }
    fixture_only = ValidationPlan(
        candidate_id="c1",
        vulnerability_hypotheses=("command execution",),
        subtasks=(_task("fixture", "scan", "run_fixture_test"),),
        rationale="Fixture measurement",
    )
    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_plan_policy(
            fixture_only, harness=FULL_SYSTEM_HARNESS, system_spec=spec,
            tools=tools, candidate=candidate, subject=subject,
        )


def test_qualified_fixture_can_waive_command_tasks_and_mismatched_candidate_cannot():
    candidate, subject = _command_candidate_and_subject()
    proof = FixtureProofScope(
        contract_id="candidate-proof",
        coverage="candidate",
        method="bounded_execution",
        property_id="command-execution",
        supported_statuses=(ValidationStatus.CONFIRMED,),
    )
    fixture = FixtureCase(
        "c1", lambda: FixtureOutcome(status="CONFIRMED", summary="witness"),
        subject=subject, proof_scope=proof,
    )
    tools = _make_tools(fixtures=(fixture,))
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)
    plan = ValidationPlan(
        candidate_id="c1",
        vulnerability_hypotheses=("command execution",),
        subtasks=(_task("fixture", "scan", "run_fixture_test").model_copy(
            update={"fixture_case_id": "c1"}
        ),),
        rationale="Bounded witness",
    )
    assert has_candidate_fixture(tools, subject)
    assert [t.allowed_validator for t in required_tasks(candidate, None, tools, spec, subject=subject)] == ["run_fixture_test"]
    validate_plan_policy(
        plan, harness=FULL_SYSTEM_HARNESS, system_spec=spec,
        tools=tools, candidate=candidate, subject=subject,
    )

    different_candidate = candidate.model_copy(update={"property_id": "other-property"})
    assert {t.allowed_validator for t in required_tasks(different_candidate, None, tools, spec, subject=subject)} == {
        "inspect_command_construction"
    }
    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_plan_policy(
            plan, harness=FULL_SYSTEM_HARNESS, system_spec=spec,
            tools=tools, candidate=different_candidate, subject=subject,
        )


def test_weak_fixture_remains_diagnostic_alongside_command_tasks():
    candidate, subject = _command_candidate_and_subject()
    fixture = FixtureCase(
        "c1", lambda: FixtureOutcome(status="CONFIRMED", summary="pattern"),
        subject=subject,
        proof_scope=FixtureProofScope(
            contract_id="local-pattern", property_id="command-execution",
            coverage="local", method="source_pattern",
            supported_statuses=(ValidationStatus.CONFIRMED,),
        ),
    )
    tools = _make_tools(fixtures=(fixture,))
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)
    required = required_tasks(candidate, None, tools, spec, subject=subject)
    plan, _ = compose_plan(
        "c1", required, {}, patch_tasks=(_task("diagnostic", "scan", "run_fixture_test"),)
    )
    assert [t.task_id for t in plan.subtasks] == ["diagnostic", "req-cmd-scan", "req-cmd-taint"]
    assert all("diagnostic" in t.dependencies for t in plan.subtasks[1:])
    validate_plan_policy(
        plan, harness=FULL_SYSTEM_HARNESS, system_spec=spec,
        tools=tools, candidate=candidate, subject=subject,
    )


def test_qualified_fixture_does_not_drop_independent_permission_obligation():
    candidate, subject = _command_candidate_and_subject()
    candidate = candidate.model_copy(update={"analysis_scope": "get_cmd subprocess.Popen os.chmod"})
    subject = subject.model_copy(update={"analysis_scope": candidate.analysis_scope})
    fixture = FixtureCase(
        "c1", lambda: FixtureOutcome(status="CONFIRMED", summary="witness"),
        subject=subject,
        proof_scope=FixtureProofScope(
            contract_id="command-witness", property_id="command-execution",
            coverage="candidate", method="bounded_execution",
            supported_statuses=(ValidationStatus.CONFIRMED,),
        ),
    )
    tools = _make_tools(fixtures=(fixture,))
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)
    required = required_tasks(candidate, None, tools, spec, subject=subject)
    assert {(t.expert, t.allowed_validator) for t in required} == {
        ("scan", "run_fixture_test"),
        ("authz", "validate_permission_mode"),
    }
    plan, _ = compose_plan("c1", required, {})
    validate_plan_policy(
        plan, harness=FULL_SYSTEM_HARNESS, system_spec=spec,
        tools=tools, candidate=candidate, subject=subject,
    )


def test_mixed_fixture_waiver_is_bound_to_qualified_case():
    candidate, subject = _command_candidate_and_subject()
    strong = FixtureCase(
        "strong", lambda: FixtureOutcome(status="CONFIRMED", summary="witness"),
        subject=subject,
        proof_scope=FixtureProofScope(
            contract_id="bounded-witness", property_id="command-execution",
            coverage="candidate", method="bounded_execution",
            supported_statuses=(ValidationStatus.CONFIRMED,),
        ),
    )
    weak = FixtureCase(
        "weak", lambda: FixtureOutcome(status="CONFIRMED", summary="pattern"),
        subject=subject,
        proof_scope=FixtureProofScope(
            contract_id="local-pattern", property_id="command-execution",
            coverage="local", method="source_pattern",
            supported_statuses=(ValidationStatus.CONFIRMED,),
        ),
    )
    tools = _make_tools(fixtures=(weak, strong))
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)

    required = required_tasks(candidate, None, tools, spec, subject=subject)
    assert len(required) == 1
    assert required[0].fixture_case_id == "strong"
    plan, _ = compose_plan("c1", required, {})
    validate_plan_policy(
        plan, harness=FULL_SYSTEM_HARNESS, system_spec=spec,
        tools=tools, candidate=candidate, subject=subject,
    )
    for fixture_case_id in (None, "weak"):
        unqualified = ValidationPlan(
            candidate_id="c1",
            vulnerability_hypotheses=("command execution",),
            subtasks=(_task("fixture", "scan", "run_fixture_test").model_copy(
                update={"fixture_case_id": fixture_case_id}
            ),),
            rationale="Unqualified fixture task",
        )
        with pytest.raises(ValueError, match="inspect_command_construction"):
            validate_plan_policy(
                unqualified, harness=FULL_SYSTEM_HARNESS, system_spec=spec,
                tools=tools, candidate=candidate, subject=subject,
            )


def test_bound_fixture_scope_refuses_weak_case_before_execution():
    _, subject = _command_candidate_and_subject()
    strong = FixtureCase(
        "strong", lambda: FixtureOutcome(status="CONFIRMED", summary="witness"),
        subject=subject,
        proof_scope=FixtureProofScope(
            contract_id="bounded-witness", property_id="command-execution",
            coverage="candidate", method="bounded_execution",
            supported_statuses=(ValidationStatus.CONFIRMED,),
        ),
    )
    weak = FixtureCase(
        "weak", lambda: FixtureOutcome(status="CONFIRMED", summary="pattern"),
        subject=subject,
        proof_scope=FixtureProofScope(
            contract_id="local-pattern", property_id="command-execution",
            coverage="local", method="source_pattern",
            supported_statuses=(ValidationStatus.CONFIRMED,),
        ),
    )
    tools = _make_tools(fixtures=(strong, weak))
    scope = ToolExecutionScope(
        admitted_paths=frozenset({"entry.py"}), candidate_path="entry.py",
        subject=subject, max_observation_tokens=10000,
        fixture_case_id="strong",
    )
    denied = tools.invoke(
        ModelToolCall(call_id="weak", name="run_fixture_test", arguments={"case_id": "weak"}),
        allowed=("run_fixture_test",), scope=scope,
    )
    assert denied.status == "blocked"
    assert denied.validation_status is None
    permitted = tools.invoke(
        ModelToolCall(call_id="strong", name="run_fixture_test", arguments={"case_id": "strong"}),
        allowed=("run_fixture_test",), scope=scope,
    )
    assert permitted.status == "ok"
    assert permitted.validation_status == ValidationStatus.CONFIRMED


def test_rule_task_blocks_model_attempt_to_run_weak_fixture_then_accepts_bound_case():
    text = (
        "def entry(value):\n"
        "    command = get_cmd(value)\n"
        "    return subprocess.Popen(['bash', '-c', command])\n"
    )
    index = RepositoryIndex([CodeDocument(repository_id="r", path="entry.py", text=text)])
    candidate, _ = _command_candidate_and_subject()
    subject = candidate_subject(index, candidate)
    strong = FixtureCase(
        "strong", lambda: FixtureOutcome(status="CONFIRMED", summary="bounded witness"),
        subject=subject,
        proof_scope=FixtureProofScope(
            contract_id="bounded-witness", property_id="command-execution",
            coverage="candidate", method="bounded_execution",
            supported_statuses=(ValidationStatus.CONFIRMED,),
        ),
    )
    weak = FixtureCase(
        "weak", lambda: FixtureOutcome(status="CONFIRMED", summary="pattern"),
        subject=subject,
        proof_scope=FixtureProofScope(
            contract_id="local-pattern", property_id="command-execution",
            coverage="local", method="source_pattern",
            supported_statuses=(ValidationStatus.CONFIRMED,),
        ),
    )
    scan_model = ScriptedChatModel([
        ModelReply(model_id="scan", tool_calls=(ModelToolCall(
            call_id="try-weak", name="run_fixture_test", arguments={"case_id": "weak"},
        ),)),
        ModelReply(model_id="scan", tool_calls=(ModelToolCall(
            call_id="run-strong", name="run_fixture_test", arguments={"case_id": "strong"},
        ),)),
        ModelReply(model_id="scan", content='{'
            '"expert":"scan","label":"VULNERABLE","confidence":0.9,'
            '"validation_status":"CONFIRMED",'
            '"evidence_ids":["scan/tool:2","fixture:strong"],'
            '"supporting_observation_ids":["scan/tool:2"],'
            '"counter_observation_ids":[],"unresolved_observation_ids":[], '
            '"rationale":"Bounded fixture confirmed this candidate."}'),
    ])
    pipeline = AgenticPipeline(
        index=index,
        system=AgentSystemVersion.E4_GRAPH_MULTI,
        system_name="E4_RULE_V1",
        tools=ToolRegistry(full_agent_tools(index, fixture_cases=(weak, strong)), max_output_bytes=100000),
        models={
            "planner": ScriptedChatModel([]), "scan": scan_model,
            "taint": ScriptedChatModel([]), "authz": ScriptedChatModel([]),
        },
    )
    evidence = [Evidence(evidence_id="local:entry.py", path="entry.py", text=text, retrieval="local", score=1.0)]
    state = {
        "candidate": candidate, "evidence": evidence, "context_prompt": "offline",
        "context_token_count": 0, "votes": [], "task_executions": [],
        "planner": None, "routing": None, "verdict": None, "fast_checked": False,
    }
    state.update(pipeline._plan(state))
    assert state["routing"].plan.subtasks[0].fixture_case_id == "strong"
    update = pipeline._run_scan(state)
    execution = update["task_executions"][0]
    assert execution.validator_completed is True
    assert [step.observation.status for step in execution.vote.trace] == ["blocked", "ok"]
    assert execution.vote.trace[0].observation.validation_status is None
    assert execution.vote.trace[1].observation.evidence_ids == ("fixture:strong",)
    assert execution.vote.label == "VULNERABLE"


def test_compose_plan_preserves_cross_expert_dependencies():
    guard = _task("guard", "authz", "compare_route_and_service_guard")
    sink = _task("sink", "scan", "inspect_command_construction", ("guard",))
    plan, origins = compose_plan("c1", (guard,), {}, patch_tasks=(sink,))
    assert [task.task_id for task in plan.subtasks] == ["guard", "sink"]
    assert [origin.origin for origin in origins] == ["policy", "llm"]


def test_compose_plan_remaps_dependencies_on_deduplicated_tasks():
    required = (_task("req-scan", "scan", "inspect_command_construction"),)
    patch = (
        _task("patch-scan", "scan", "inspect_command_construction"),
        _task("patch-taint", "taint", "trace_dataflow", ("patch-scan",)),
    )
    plan, origins = compose_plan("c1", required, {}, patch_tasks=patch)
    assert [task.task_id for task in plan.subtasks] == ["req-scan", "patch-taint"]
    assert plan.subtasks[1].dependencies == ("req-scan",)
    assert [origin.origin for origin in origins] == ["policy", "llm"]


def test_compose_plan_rejects_task_id_collisions_and_cycles():
    with pytest.raises(ValueError, match="duplicate task id"):
        compose_plan("c1", (_task("same", "scan", "inspect_command_construction"),), {},
                     patch_tasks=(_task("same", "taint", "trace_dataflow"),))
    with pytest.raises(ValueError, match="cycle"):
        compose_plan("c1", (), {}, patch_tasks=(
            _task("a", "scan", "run_static_check", ("b",)),
            _task("b", "taint", "trace_dataflow", ("a",)),
        ))


def test_compose_plan_adds_patch_fixture_as_dependency():
    plan, _ = compose_plan(
        "c1", (_task("scan", "scan", "inspect_command_construction"),), {},
        patch_tasks=(_task("fixture", "taint", "run_fixture_test"),),
    )
    assert [task.task_id for task in plan.subtasks] == ["fixture", "scan"]
    assert plan.subtasks[1].dependencies == ("fixture",)


def test_compose_plan_rejects_duplicate_task_with_new_dependencies():
    with pytest.raises(ValueError, match="duplicate validator.*dependencies"):
        compose_plan("c1", (_task("req-scan", "scan", "inspect_command_construction"),), {},
                     patch_tasks=(
                         _task("guard", "authz", "compare_route_and_service_guard"),
                         _task("patch-scan", "scan", "inspect_command_construction", ("guard",)),
                     ))
