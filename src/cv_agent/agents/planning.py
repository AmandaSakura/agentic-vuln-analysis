"""Pure planner prompts and plan policy with explicit runtime dependencies."""
from __future__ import annotations

import json

from cv_agent.domain.review import ValidationPlan
from cv_agent.harness import AgentSystemHarness, EndToEndHarness, ExpertAgentHarness
from cv_agent.tools.registry import ToolRegistry
from cv_agent.domain.types import Candidate, Evidence


def expert_spec(harness: EndToEndHarness, name: str) -> ExpertAgentHarness:
    matches = [expert for expert in harness.experts if expert.expert == name]
    if len(matches) != 1:
        raise ValueError(f"full-system Harness lacks expert {name}")
    return matches[0]


def render_planner_prompt(
    *,
    harness: EndToEndHarness,
    system_spec: AgentSystemHarness,
    tools: ToolRegistry,
    candidate: Candidate,
    evidence: list[Evidence],
) -> str:
    validators = set(harness.validation.validators) & set(tools.available_names)
    planner_context = {
        "candidate": {
            "candidate_id": candidate.candidate_id,
            "line": candidate.line,
            "path": candidate.path,
            "repository_id": candidate.repository_id,
            **({"analysis_scope": candidate.analysis_scope} if candidate.analysis_scope is not None else {}),
        },
        "retrieved_evidence_index": [
            {
                "evidence_id": item.evidence_id,
                "graph_distance": item.graph_distance,
                "path": item.path,
                "retrieval": item.retrieval,
            }
            for item in evidence
        ],
        "instruction": (
            "The evidence index lists paths, not source contents. "
            "Read the candidate span once with read_span before planning; "
            "do not browse the repository during planning."
        ),
    }
    capabilities = {
        "maximum_subtasks": harness.planner_max_subtasks,
        "expert_mandates": {
            name: expert_spec(harness, name).mandate for name in system_spec.expert_order
        },
        "verification_guidance": (
            "Arrange distinct applicable checks of the same candidate, not votes from "
            "unrelated specialties. For supported Python eval injection, assign scan "
            "probe_python_eval at the entry and taint trace_dataflow; these checks can "
            "run without depending on one another's conclusions. A static sink search "
            "only locates a candidate. Prefer registered execution fixtures when available "
            "and relevant. Use authz for permission problems; outside scope it may abstain. "
            "For os.chmod filesystem permission candidates, assign scan "
            "validate_permission_mode and, when authz is scheduled, assign authz "
            "validate_permission_mode for resource access-control semantics. For command "
            "execution through admitted get_cmd helpers, assign scan and taint "
            "inspect_command_construction before making an unsanitized shell-command judgment. "
            "When a run_fixture_test subtask is available for this candidate, schedule it "
            "before other advisory-scoped checks and make later non-fixture subtasks depend "
            "on it so they can see the concrete validator observation. "
            "Static checks provide hypotheses, not CONFIRMED or REFUTED evidence. "
            "The declared quorum requires independent expert ballots; one validator "
            "result does not replace it. Do not request agreement, duplicate one validator "
            "result as independent verification, or infer SAFE from an inconclusive probe. "
            "If available capabilities cannot establish two applicable checks, retain that limitation."
        ),
        "allowed_validators_by_expert": {
            name: sorted(set(expert_spec(harness, name).tools) & validators)
            for name in system_spec.expert_order
        },
        "validator_descriptions": {
            definition["function"]["name"]: definition["function"]["description"]
            for definition in tools.definitions(sorted(validators))
        },
        "final_json_contract": (
            "Keep the plan compact: prefer three or fewer subtasks. Every subtask object "
            "must include task_id explicitly, using t1/t2/t3 in order; dependencies must "
            "refer to those ids. Keep rationale under 120 characters, and keep each "
            "objective and success_condition under 120 characters. Do not include code "
            "excerpts, prose outside JSON, or Markdown fences."
        ),
    }
    return (
        "Planning context: "
        + json.dumps(planner_context, sort_keys=True, separators=(",", ":"))
        + "\nPlanning capabilities: "
        + json.dumps(capabilities, sort_keys=True, separators=(",", ":"))
    )


def validate_plan(
    plan: ValidationPlan,
    *,
    harness: EndToEndHarness,
    system_spec: AgentSystemHarness,
    tools: ToolRegistry,
    candidate: Candidate,
    evidence: list[Evidence] | None = None,
) -> None:
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
        expert_tools = set(expert_spec(harness, task.expert).tools)
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
    fixture_tasks = [
        task.task_id for task in plan.subtasks
        if task.allowed_validator == "run_fixture_test"
    ]
    evidence_text = "\n".join(item.text for item in (evidence or ()))
    planning_text = "\n".join(
        item
        for item in (evidence_text, candidate.analysis_scope or "")
        if item
    )
    planned_validators = {task.allowed_validator for task in plan.subtasks}
    if (
        "validate_permission_mode" in tools.available_names
        and "os.chmod" in planning_text
        and "validate_permission_mode" not in planned_validators
    ):
        raise ValueError(
            "planner must schedule validate_permission_mode for os.chmod "
            "filesystem permission candidates"
        )
    if (
        "validate_permission_mode" in tools.available_names
        and "os.chmod" in planning_text
        and "authz" in system_spec.expert_order
        and not any(
            task.expert == "authz"
            and task.allowed_validator == "validate_permission_mode"
            for task in plan.subtasks
        )
    ):
        raise ValueError(
            "planner must assign authz validate_permission_mode for os.chmod "
            "resource access-control semantics"
        )
    command_construction_candidate = (
        "inspect_command_construction" in tools.available_names
        and "get_cmd" in planning_text
        and (
            "subprocess.Popen" in planning_text
            or "bash" in planning_text
            or ".execute(" in planning_text
            or "命令注入" in planning_text
            or "command injection" in planning_text.casefold()
        )
    )
    if (
        command_construction_candidate
        and "inspect_command_construction" not in planned_validators
    ):
        raise ValueError(
            "planner must schedule inspect_command_construction for admitted "
            "get_cmd shell-command candidates"
        )
    if (
        command_construction_candidate
        and "scan" in system_spec.expert_order
        and not any(
            task.expert == "scan"
            and task.allowed_validator == "inspect_command_construction"
            for task in plan.subtasks
        )
    ):
        raise ValueError(
            "planner must assign scan inspect_command_construction for admitted "
            "get_cmd shell-command candidates"
        )
    if (
        command_construction_candidate
        and "taint" in system_spec.expert_order
        and not any(
            task.expert == "taint"
            and task.allowed_validator == "inspect_command_construction"
            for task in plan.subtasks
        )
    ):
        raise ValueError(
            "planner must assign taint inspect_command_construction for admitted "
            "get_cmd shell-command candidates"
        )
    if command_construction_candidate:
        redundant_scan = [
            task for task in plan.subtasks
            if task.expert == "scan"
            and task.allowed_validator != "inspect_command_construction"
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
                current = pending.pop()
                if current == target:
                    return True
                if current in seen:
                    continue
                seen.add(current)
                pending.extend(dependencies.get(current, ()))
            return False

        for task in plan.subtasks:
            if task.allowed_validator == "run_fixture_test":
                continue
            if not any(reaches(task.task_id, fixture_task) for fixture_task in fixture_tasks):
                raise ValueError(
                    "planner must make non-fixture subtasks depend on run_fixture_test "
                    "so concrete validator evidence is visible"
                )
