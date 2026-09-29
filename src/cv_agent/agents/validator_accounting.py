"""Audit final material ballots against their original producer observations."""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Sequence
from typing import Any

from cv_agent.agents.evidence_policy import supporting_validator_proofs
from cv_agent.domain.evidence import ValidationSubject
from cv_agent.domain.review import AgentExpertVote, ValidationPlan, ValidationTaskExecution


@dataclass(frozen=True)
class ValidatorObservationAccounting:
    material_votes_sharing_validator_observation: int
    independent_validator_observations: int
    origins: tuple[dict[str, Any], ...]


def account_validator_observations(
    votes: Sequence[AgentExpertVote], executions: Sequence[ValidationTaskExecution],
    subject: ValidationSubject, plan: ValidationPlan | None = None,
) -> ValidatorObservationAccounting:
    """Count already admitted final ballots; references only resolve aliases.

    Each execution holds only its newly invoked steps. Cumulative final traces
    and forwarded dependency observations are copies of those origins. Source,
    scenario and manifest digests identify content, never a producer execution.
    """
    tasks = {task.task_id: task for task in plan.subtasks} if plan is not None else {}
    origins = {}
    for vote in votes:
        if vote.label == "ABSTAIN":
            continue
        own = {index for index, item in enumerate(executions) if item.vote.expert == vote.expert}
        needed = {executions[index].task_id for index in own if executions[index].task_id is not None}
        pending = list(needed) if plan is not None else []
        while pending:
            for dependency in tasks[pending.pop()].dependencies:
                if dependency not in needed:
                    needed.add(dependency)
                    pending.append(dependency)
        visible = [(index, item) for index, item in enumerate(executions)
                   if index in own or (plan is not None and item.task_id in needed)]
        original = [(execution_index, step_index, execution, step.observation)
                    for execution_index, execution in visible
                    for step_index, step in enumerate(execution.vote.trace)]
        proofs = supporting_validator_proofs(vote, [item[3] for item in original], subject)
        eligible = {id(observation) for observation in proofs}
        for execution_index, step_index, execution, observation in original:
            if id(observation) not in eligible:
                continue
            key = (execution_index + 1, step_index + 1)
            record = origins.setdefault(key, {
                "producer_execution_ordinal": key[0], "producer_step_ordinal": key[1],
                "producer_task_id": execution.task_id, "producer_expert": execution.vote.expert,
                "tool": observation.tool, "citation_id": observation.citation_id,
                "evidence_aliases": observation.evidence_ids, "material_experts": set(),
            })
            record["material_experts"].add(vote.expert)
    recorded = tuple({**record, "material_experts": tuple(sorted(record["material_experts"]))}
                     for _, record in sorted(origins.items()))
    sharing = {expert for record in recorded if len(record["material_experts"]) > 1
               for expert in record["material_experts"]}
    return ValidatorObservationAccounting(len(sharing), len(recorded), recorded)
