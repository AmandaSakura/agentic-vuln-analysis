"""Deterministic validation-plan policies, obligation derivation and plan composition."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Literal

from cv_agent.agents.evidence_policy import fixture_can_support_candidate
from cv_agent.domain.evidence import ValidationStatus, ValidationSubject
from cv_agent.domain.review import TaskOrigin, ValidationPlan, ValidationSubtask


def planning_context_text(
    candidate: Candidate, evidence: Iterable[Evidence] | None = None
) -> str:
    evidence_text = "\n".join(item.text for item in (evidence or ()))
    return "\n".join(
        item for item in (evidence_text, candidate.analysis_scope or "") if item
    )


def is_permission_candidate(planning_text: str) -> bool:
    return "os.chmod" in planning_text


def is_command_construction_candidate(planning_text: str) -> bool:
    return "get_cmd" in planning_text and (
        "subprocess.Popen" in planning_text
        or "bash" in planning_text
        or ".execute(" in planning_text
        or "命令注入" in planning_text
        or "command injection" in planning_text.casefold()
    )


def has_candidate_fixture(
    tools: ToolRegistry,
    subject: ValidationSubject | None,
    candidate: Candidate | None = None,
) -> bool:
    return bool(qualified_fixture_case_ids(tools, subject, candidate))


def qualified_fixture_case_ids(
    tools: ToolRegistry,
    subject: ValidationSubject | None,
    candidate: Candidate | None = None,
) -> tuple[str, ...]:
    """Case IDs whose registered proof can support this complete subject."""
    if subject is None or "run_fixture_test" not in tools.available_names:
        return ()
    if candidate is not None and not _subject_matches_candidate(subject, candidate):
        return ()
    return tuple(sorted(
        capability.case_id
        for capability in tools.candidate_fixture_capabilities(subject)
        if capability.subject == subject
        and any(
            fixture_can_support_candidate(capability.proof_scope, subject, status)
            for status in (ValidationStatus.CONFIRMED, ValidationStatus.REFUTED)
        )
    ))


def _subject_matches_candidate(subject: ValidationSubject, candidate: Candidate) -> bool:
    """A caller-supplied subject must describe the candidate being planned."""
    return (
        subject.candidate_id == candidate.candidate_id
        and subject.repository_id == candidate.repository_id
        and subject.entry_path == candidate.path
        and subject.entry_line == candidate.line
        and subject.property_id == candidate.property_id
        and subject.input_parameters == candidate.input_parameters
        and subject.entry_boolean_arguments == candidate.entry_boolean_arguments
        and subject.entry_condition_assumptions == candidate.entry_condition_assumptions
        and subject.entry_value_assumptions == candidate.entry_value_assumptions
        and subject.analysis_scope == candidate.analysis_scope
    )


def required_tasks(
    candidate: Candidate,
    evidence: Iterable[Evidence] | None,
    tools: ToolRegistry,
    system_spec: AgentSystemHarness,
    *,
    subject: ValidationSubject | None = None,
) -> tuple[ValidationSubtask, ...]:
    """Derive deterministic mandatory subtasks required by system policies."""
    text = planning_context_text(candidate, evidence)
    tasks: list[ValidationSubtask] = []

    # A qualified fixture can replace the command checks, but not an
    # independent permission obligation in the same candidate context.
    fixture_case_ids = qualified_fixture_case_ids(tools, subject, candidate)
    qualified_fixture = bool(fixture_case_ids) and "scan" in system_spec.expert_order
    if qualified_fixture:
        tasks.append(
            ValidationSubtask(
                task_id="req-fixture-1",
                expert="scan",
                allowed_validator="run_fixture_test",
                fixture_case_id=fixture_case_ids[0],
                objective="Execute registered candidate-bound fixture witness.",
                dependencies=(),
                success_condition="Record concrete fixture test results; do not infer safety from absence.",
            )
        )

    # 2. Command construction obligation
    if (
        not qualified_fixture
        and is_command_construction_candidate(text)
        and "inspect_command_construction" in tools.available_names
    ):
        if "scan" in system_spec.expert_order:
            tasks.append(
                ValidationSubtask(
                    task_id="req-cmd-scan",
                    expert="scan",
                    allowed_validator="inspect_command_construction",
                    objective="Inspect admitted get_cmd shell-command construction.",
                    dependencies=(),
                    success_condition="Record sanitized or unsanitized shell arguments.",
                )
            )
        if "taint" in system_spec.expert_order:
            tasks.append(
                ValidationSubtask(
                    task_id="req-cmd-taint",
                    expert="taint",
                    allowed_validator="inspect_command_construction",
                    objective="Trace parameter dataflow to shell command construction.",
                    dependencies=(),
                    success_condition="Record tainted parameter reachability to shell execution.",
                )
            )

    # 3. Filesystem permission mode obligation
    if is_permission_candidate(text) and "validate_permission_mode" in tools.available_names:
        if "authz" in system_spec.expert_order:
            tasks.append(
                ValidationSubtask(
                    task_id="req-perm-authz",
                    expert="authz",
                    allowed_validator="validate_permission_mode",
                    objective="Validate os.chmod permissions mode behavior in candidate span.",
                    dependencies=(),
                    success_condition="Record others-writable permission mode or non-others-writable enforcement.",
                )
            )

    return tuple(tasks)


def compose_plan(
    candidate_id: str,
    required: Iterable[ValidationSubtask],
    accepted_choices: Mapping[str, str],  # expert -> allowed_validator
    patch_tasks: Iterable[ValidationSubtask] = (),
    *,
    expert_order: tuple[str, ...] = ("scan", "taint", "authz"),
) -> tuple[ValidationPlan, tuple[TaskOrigin, ...]]:
    """Compose mandatory policy tasks, accepted model choices, and patch tasks."""
    subtasks: list[ValidationSubtask] = []
    origins: list[TaskOrigin] = []
    by_key: dict[tuple[str, str], ValidationSubtask] = {}
    id_to_key: dict[str, tuple[str, str]] = {}
    aliases: dict[str, str] = {}
    duplicates: list[tuple[ValidationSubtask, ValidationSubtask]] = []

    def add_task(task: ValidationSubtask, origin: TaskOrigin) -> None:
        key = (task.expert, task.allowed_validator)
        if task.task_id in id_to_key and id_to_key[task.task_id] != key:
            raise ValueError(f"duplicate task id {task.task_id} names different validators")
        id_to_key[task.task_id] = key
        if key in by_key:
            canonical = by_key[key]
            aliases[task.task_id] = canonical.task_id
            duplicates.append((task, canonical))
            return
        by_key[key] = task
        subtasks.append(task)
        origins.append(origin)

    # 1. Mandatory policy tasks always come first
    for task in required:
        add_task(task, TaskOrigin(task_id=task.task_id, origin="policy"))

    # 2. Accepted optional choices (e.g. from Jev)
    for expert in expert_order:
        if expert not in accepted_choices:
            continue
        validator = accepted_choices[expert]
        key = (expert, validator)
        if key in by_key:
            # Already covered by a mandatory policy task; origin remains policy
            continue
        task_id = f"jev-{expert}"
        subtask = ValidationSubtask(
            task_id=task_id,
            expert=expert,
            allowed_validator=validator,
            objective=f"Collect candidate-bound evidence with {validator}.",
            dependencies=(),
            success_condition="Record supporting, counter and unresolved evidence; do not infer safety from absence.",
        )
        add_task(
            subtask,
            TaskOrigin(
                task_id=task_id,
                origin="jev",
                decision_id=f"validator.{expert}",
            ),
        )

    # 3. Patch tasks (e.g. from LLM)
    for task in patch_tasks:
        add_task(task, TaskOrigin(task_id=task.task_id, origin="llm"))

    # 4. If fixture tasks exist, all non-fixture tasks must depend on them
    fixture_ids = tuple(t.task_id for t in subtasks if t.allowed_validator == "run_fixture_test")
    adjusted: list[ValidationSubtask] = []
    for task in subtasks:
        dependencies = tuple(dict.fromkeys(aliases.get(dep, dep) for dep in task.dependencies))
        if task.allowed_validator != "run_fixture_test":
            dependencies = tuple(dict.fromkeys((*dependencies, *fixture_ids)))
        adjusted.append(task.model_copy(update={"dependencies": dependencies}))
    subtasks = adjusted

    # Deterministic topological sort: preserve dependencies, break ties with expert_order
    task_map = {t.task_id: t for t in subtasks}
    subtask_ids = set(task_map)
    for duplicate, canonical in duplicates:
        remapped = {aliases.get(dep, dep) for dep in duplicate.dependencies}
        missing = remapped - subtask_ids
        if missing:
            raise ValueError(f"validation task {duplicate.task_id} has unknown dependencies: {sorted(missing)}")
        if not remapped.issubset(task_map[canonical.task_id].dependencies):
            raise ValueError(
                f"duplicate validator task {duplicate.task_id} adds dependencies to {canonical.task_id}"
            )
    in_deps: dict[str, set[str]] = {}
    for task in subtasks:
        missing = set(task.dependencies) - subtask_ids
        if missing:
            raise ValueError(f"validation task {task.task_id} has unknown dependencies: {sorted(missing)}")
        in_deps[task.task_id] = set(task.dependencies)

    def tie_breaker(t: ValidationSubtask) -> tuple[int, int, str]:
        is_fixture = 0 if t.allowed_validator == "run_fixture_test" else 1
        expert_idx = (
            expert_order.index(t.expert) if t.expert in expert_order else 99
        )
        return (is_fixture, expert_idx, t.task_id)

    ordered: list[ValidationSubtask] = []
    while in_deps:
        ready = [task_map[tid] for tid, deps in in_deps.items() if not deps]
        if not ready:
            raise ValueError(f"dependency cycle detected in validation plan: {sorted(in_deps)}")
        ready.sort(key=tie_breaker)
        chosen = ready[0]
        ordered.append(chosen)
        del in_deps[chosen.task_id]
        for deps in in_deps.values():
            deps.discard(chosen.task_id)

    subtasks = ordered
    origin_map = {o.task_id: o for o in origins}
    ordered_origins = tuple(origin_map[t.task_id] for t in subtasks if t.task_id in origin_map)

    plan = ValidationPlan(
        candidate_id=candidate_id,
        vulnerability_hypotheses=("Candidate requires evidence-based security review.",),
        subtasks=tuple(subtasks),
        rationale="Composed deterministic policy tasks with validated routing decisions.",
    )
    return plan, ordered_origins


def validate_plan_policy(
    plan: ValidationPlan,
    *,
    harness: EndToEndHarness,
    system_spec: AgentSystemHarness,
    tools: ToolRegistry,
    candidate: Candidate,
    evidence: list[Evidence] | None = None,
    subject: ValidationSubject | None = None,
) -> None:
    """Validate a validation plan against expert mandates, tool availability, and obligations."""
    if plan.candidate_id != candidate.candidate_id:
        raise ValueError("planner output carries the wrong candidate identity")
    if len(plan.subtasks) > harness.planner_max_subtasks:
        raise ValueError("planner exceeded maximum_subtasks")
    scheduled = set(system_spec.expert_order)
    validators = set(harness.validation.validators) & set(tools.names)
    for task in plan.subtasks:
        if task.expert not in scheduled:
            raise ValueError(
                f"planner assigned task {task.task_id} to unscheduled expert {task.expert}"
            )
        if task.allowed_validator not in validators:
            raise ValueError(
                f"planner selected unregistered validator {task.allowed_validator}"
            )
        expert_tools = set(
            next(e for e in harness.experts if e.expert == task.expert).tools
        )
        if task.allowed_validator not in expert_tools:
            raise ValueError(
                f"planner assigned validator {task.allowed_validator} to expert "
                f"{task.expert}, which cannot execute it"
            )
        if task.allowed_validator not in tools.available_names:
            raise ValueError(
                f"validator {task.allowed_validator} is unavailable for this run; "
                "choose from Planning capabilities"
            )

    planned_validators = {task.allowed_validator for task in plan.subtasks}
    text = planning_context_text(candidate, evidence)

    # Fixture tasks
    fixture_tasks = [
        task.task_id
        for task in plan.subtasks
        if task.allowed_validator == "run_fixture_test"
    ]

    # Permission checks
    if "validate_permission_mode" in tools.available_names and is_permission_candidate(text):
        if "validate_permission_mode" not in planned_validators:
            raise ValueError(
                "planner must schedule validate_permission_mode for os.chmod "
                "filesystem permission candidates"
            )
        if "authz" in system_spec.expert_order and not any(
            t.expert == "authz" and t.allowed_validator == "validate_permission_mode"
            for t in plan.subtasks
        ):
            raise ValueError(
                "planner must assign authz validate_permission_mode for os.chmod "
                "resource access-control semantics"
            )

    # Check if there is a qualified candidate-level fixture for this candidate
    qualified_fixture_ids = set(qualified_fixture_case_ids(tools, subject, candidate))
    has_qualified_fixture = any(
        task.allowed_validator == "run_fixture_test"
        and task.fixture_case_id in qualified_fixture_ids
        for task in plan.subtasks
    )

    # Command construction checks
    cmd_candidate = is_command_construction_candidate(text)
    if cmd_candidate and not has_qualified_fixture:
        if "inspect_command_construction" not in planned_validators:
            raise ValueError(
                "planner must schedule inspect_command_construction for admitted "
                "get_cmd shell-command candidates"
            )
        if "scan" in system_spec.expert_order and not any(
            t.expert == "scan" and t.allowed_validator == "inspect_command_construction"
            for t in plan.subtasks
        ):
            raise ValueError(
                "planner must assign scan inspect_command_construction for admitted "
                "get_cmd shell-command candidates"
            )
        if "taint" in system_spec.expert_order and not any(
            t.expert == "taint" and t.allowed_validator == "inspect_command_construction"
            for t in plan.subtasks
        ):
            raise ValueError(
                "planner must assign taint inspect_command_construction for admitted "
                "get_cmd shell-command candidates"
            )
        redundant_scan = [
            t
            for t in plan.subtasks
            if t.expert == "scan"
            and t.allowed_validator != "inspect_command_construction"
            and t.allowed_validator != "run_fixture_test"
        ]
        if redundant_scan:
            raise ValueError(
                "planner must not schedule redundant scan validators after "
                "scan inspect_command_construction for admitted get_cmd "
                "shell-command candidates"
            )

    if fixture_tasks:
        dependencies = {task.task_id: set(task.dependencies) for task in plan.subtasks}

        def reaches(start: str, target: str) -> bool:
            pending = list(dependencies[start])
            seen: set[str] = set()
            while pending:
                curr = pending.pop()
                if curr == target:
                    return True
                if curr in seen:
                    continue
                seen.add(curr)
                pending.extend(dependencies.get(curr, ()))
            return False

        for task in plan.subtasks:
            if task.allowed_validator == "run_fixture_test":
                continue
            if not any(reaches(task.task_id, ft) for ft in fixture_tasks):
                raise ValueError(
                    "planner must make non-fixture subtasks depend on run_fixture_test "
                    "so concrete validator evidence is visible"
                )
