"""Independent expert applicability policy (applicable_v1).

Evaluates whether an expert is applicable, not applicable, or undetermined for a
given candidate and property obligation. E4/E5 baselines remain fixed by default.
"""
from __future__ import annotations

import re
from typing import Literal

from cv_agent.domain.review import ValidationPlan
from cv_agent.domain.types import Candidate, FrozenModel
from cv_agent.harness import ExpertName


class ApplicabilityVerdict(FrozenModel):
    expert: ExpertName
    status: Literal["applicable", "not_applicable", "undetermined"]
    reason: str


def evaluate_expert_applicability_v1(
    candidate: Candidate,
    expert: ExpertName,
    plan: ValidationPlan | None = None,
) -> ApplicabilityVerdict:
    """Evaluate expert applicability under the applicable_v1 policy."""
    # 1. If an active plan explicitly assigns tasks to this expert, it is applicable
    if plan is not None and any(task.expert == expert for task in plan.subtasks):
        return ApplicabilityVerdict(
            expert=expert,
            status="applicable",
            reason=f"Plan explicitly scheduled tasks for {expert}.",
        )

    # 1.1 If any other task in the plan depends on a task from this expert, it cannot be skipped
    if plan is not None:
        own_tasks = {t.task_id for t in plan.subtasks if t.expert == expert}
        if any(set(t.dependencies) & own_tasks for t in plan.subtasks if t.expert != expert):
            return ApplicabilityVerdict(
                expert=expert,
                status="applicable",
                reason=f"Other tasks in plan depend on {expert}.",
            )

    # 2. Pure shell consumption command-execution without authz scope does not require authz
    if candidate.property_id == "command-execution" and expert == "authz":
        scope = (candidate.analysis_scope or "").casefold()
        if re.search(
            r"\b(auth|authorization|authentication|access|guard|permission|owner|ownership|"
            r"token|role|user|tenant|privilege|acl|session|identity|login)\b",
            scope,
        ):
            return ApplicabilityVerdict(
                expert=expert,
                status="undetermined",
                reason="Candidate mentions authorization or permission concepts; authz expert remains scheduled.",
            )
        if (
            re.search(r"\b(shell|bash|subprocess)\b", scope)
            and re.search(r"\b(only|solely|pure)\b", scope)
        ):
            return ApplicabilityVerdict(
                expert=expert,
                status="not_applicable",
                reason="Pure shell-consumption command candidate without authorization scope does not invoke authorization boundary semantics.",
            )

    # 3. All other scopes (including race conditions, unknown properties) remain undetermined
    return ApplicabilityVerdict(
        expert=expert,
        status="undetermined",
        reason="Scope and property do not categorically exclude expert mandate; expert remains scheduled.",
    )
