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
    locked_tasks: tuple[ValidationSubtask, ...] = (),
) -> str:
    validators = set(harness.validation.validators) & set(tools.available_names)
    planner_context = {
        "candidate": {
            "candidate_id": candidate.candidate_id,
            "line": candidate.line,
            "path": candidate.path,
            "repository_id": candidate.repository_id,
            **({"analysis_scope": candidate.analysis_scope} if candidate.analysis_scope is not None else {}),
            **({"property_id": candidate.property_id} if candidate.property_id is not None else {}),
        },
        **({"locked_mandatory_tasks": [
            {"task_id": t.task_id, "expert": t.expert, "allowed_validator": t.allowed_validator}
            for t in locked_tasks
        ]} if locked_tasks else {}),
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
            + (" Mandatory tasks in locked_mandatory_tasks are locked and immutable; "
               "only propose additional non-redundant subtasks." if locked_tasks else "")
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
    subject: ValidationSubject | None = None,
) -> None:
    from cv_agent.agents.plan_policy import validate_plan_policy
    validate_plan_policy(
        plan,
        harness=harness,
        system_spec=system_spec,
        tools=tools,
        candidate=candidate,
        evidence=evidence,
        subject=subject,
    )
