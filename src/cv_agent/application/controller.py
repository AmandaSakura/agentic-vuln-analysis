"""Finite product task control with explicit data dependencies and input waits."""
from __future__ import annotations

from copy import deepcopy
from collections.abc import Callable, Mapping
from typing import Literal
import traceback

from cv_agent.agents.evidence_policy import validator_observation_completed
from cv_agent.application.diagnostics import observation_diagnosis
from cv_agent.application.identity import canonical_digest
from cv_agent.domain.evidence import ToolObservation
from cv_agent.domain.product_result import Diagnosis
from cv_agent.domain.types import FrozenModel


class ReviewTask(FrozenModel):
    task_id: str
    dependencies: tuple[str, ...] = ()
    required_inputs: tuple[str, ...] = ()
    available: bool = True


class TaskState(FrozenModel):
    state: Literal["READY", "WAITING_INPUT", "BLOCKED", "FINISHED", "FAILED"]
    protocol_complete: bool = False
    validator_completed: bool = False
    observation: ToolObservation | None = None
    diagnosis: Diagnosis | None = None


class TaskController:
    def __init__(self, tasks: tuple[ReviewTask, ...], handlers: Mapping[str, Callable], *,
                 invalid_action_limit: int = 2):
        if type(invalid_action_limit) is not int or invalid_action_limit < 1:
            raise ValueError("Invalid action limit must be a positive finite integer")
        seen = set()
        for task in tasks:
            if task.task_id in seen or not set(task.dependencies) <= seen:
                raise ValueError("Tasks require unique IDs and earlier real data dependencies")
            seen.add(task.task_id)
        self.tasks = tasks
        self.handlers = dict(handlers)
        self.invalid_action_limit = invalid_action_limit
        self._states = {task.task_id: TaskState(state="READY") for task in tasks}
        self._inputs: dict[str, dict] = {task.task_id: {} for task in tasks}
        self._invalid = {task.task_id: 0 for task in tasks}
        self.events: list[dict] = []

    def _diagnosis(self, task, reason, required=(), *, environment=False):
        return Diagnosis(stage="preflight" if environment else "validation", reason_code=reason,
            message="Restore the declared capability." if environment else "Supply explicitly approved missing input.",
            owner="environment" if environment else "user",
            retry_policy="after_environment_change" if environment else "after_input", required_input=required,
            affected_candidate_ids=(task.task_id,), experiment_failure_class="F4" if environment else "F1")

    def supply(self, task_id: str, values: Mapping) -> None:
        current = self._states[task_id]
        required = set(current.diagnosis.required_input if current.diagnosis else ())
        supplied = dict(values)
        canonical_digest("approved-task-input-v1", supplied)  # Reject non-JSON/nonfinite inputs.
        if current.state != "WAITING_INPUT" or not supplied or set(supplied) - required:
            self._invalid[task_id] += 1
            self.events.append({"event": "input_rejected", "task_id": task_id,
                                "reason_code": "unrequested_input", "attempt": self._invalid[task_id]})
            if self._invalid[task_id] >= self.invalid_action_limit:
                self._states[task_id] = TaskState(state="FAILED", diagnosis=Diagnosis(
                    stage="input", reason_code="invalid_input_limit", message="The fixed invalid-input limit was reached.",
                    owner="user", retry_policy="never", affected_candidate_ids=(task_id,),
                    experiment_failure_class="F2"))
            return
        self._inputs[task_id].update(deepcopy(supplied))
        remaining = required - self._inputs[task_id].keys()
        self.events.append({"event": "input_supplied", "task_id": task_id, "fields": sorted(supplied)})
        self._states[task_id] = (TaskState(state="READY") if not remaining else
            current.model_copy(update={"diagnosis": current.diagnosis.model_copy(update={"required_input": tuple(sorted(remaining))})}))

    def advance(self) -> dict[str, TaskState]:
        # One topological pass, at most one new handler invocation per task.
        for task in self.tasks:
            current = self._states[task.task_id]
            if (current.state == "BLOCKED" and current.diagnosis is not None
                    and current.diagnosis.reason_code == "data_dependency_incomplete"
                    and all(self._states[dep].validator_completed for dep in task.dependencies)):
                current = TaskState(state="READY")
                self._states[task.task_id] = current
            if current.state != "READY":
                continue
            if not task.available:
                self._states[task.task_id] = TaskState(state="BLOCKED", diagnosis=self._diagnosis(
                    task, "required_capability_missing", environment=True))
                continue
            if any(not self._states[dep].validator_completed for dep in task.dependencies):
                self._states[task.task_id] = TaskState(state="BLOCKED", diagnosis=Diagnosis(
                    stage="validation", reason_code="data_dependency_incomplete",
                    message="A genuine data dependency has not completed validation.", owner="runtime",
                    retry_policy="manual", required_input=task.dependencies, affected_candidate_ids=(task.task_id,)))
                continue
            missing = tuple(key for key in task.required_inputs if key not in self._inputs[task.task_id])
            if missing:
                self._states[task.task_id] = TaskState(state="WAITING_INPUT", diagnosis=self._diagnosis(
                    task, "required_input_missing", missing))
                continue
            self.events.append({"event": "task_start", "task_id": task.task_id})
            try:
                observation = self.handlers[task.task_id](deepcopy(self._inputs[task.task_id]))
                if not isinstance(observation, ToolObservation):
                    raise TypeError("Task handler must produce a typed observation")
                # Check before Pydantic's JSON mode can normalize NaN to null.
                canonical_digest("tool-observation-json-v1", observation.model_dump(mode="python"))
                diagnosis = observation_diagnosis(observation, task.task_id)
                completed = validator_observation_completed(observation)
            except Exception as error:
                self.events.append({"event": "task_internal_error", "task_id": task.task_id,
                    "error_type": type(error).__name__, "private_traceback": traceback.format_exc()})
                self._states[task.task_id] = TaskState(state="FAILED", diagnosis=Diagnosis(
                    stage="runtime", reason_code="task_internal_error", message=f"Owned task failed: {type(error).__name__}.",
                    owner="runtime", retry_policy="manual", affected_candidate_ids=(task.task_id,)))
            else:
                state = ("FINISHED" if completed else "WAITING_INPUT" if diagnosis and
                         diagnosis.reason_code == "required_input_missing" else "BLOCKED")
                self._states[task.task_id] = TaskState(state=state, protocol_complete=observation.status == "ok",
                    validator_completed=completed, observation=observation, diagnosis=diagnosis)
            self.events.append({"event": "task_result", "task_id": task.task_id,
                                "state": self._states[task.task_id].state})
        return dict(self._states)
