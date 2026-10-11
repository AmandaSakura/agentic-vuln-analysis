"""R13: representative lawful eight-task topologies retain the frozen bound."""
from __future__ import annotations

import pytest

from cv_agent.agents.workflow import AgenticPipeline, GRAPH_TRANSITION_LIMIT
from cv_agent.harness import FULL_SYSTEM_HARNESS
from test_planner_dependencies import run_plan


ROLE_PATTERNS = {
    "interleaved": ("scan", "taint", "authz", "scan", "taint", "authz", "scan", "taint"),
    "reverse": ("authz", "taint", "scan", "authz", "taint", "scan", "authz", "taint"),
    "one_role": ("scan",) * 8,
    "taint_only": ("taint",) * 8,
    "authz_only": ("authz",) * 8,
    "two_roles": ("scan", "taint") * 4,
    "late_scan": ("authz", "authz", "taint", "taint", "scan", "scan", "scan", "scan"),
}


def _tasks(roles, topology):
    result = []
    for position, role in enumerate(roles):
        if topology == "independent" or position == 0:
            dependencies = []
        elif topology == "chain":
            dependencies = [f"n{position - 1}"]
        elif topology == "fan_out":
            dependencies = ["n0"]
        elif topology == "all_prior":
            dependencies = [f"n{i}" for i in range(position)]
        else:
            dependencies = [f"n{max(0, position - 2)}"]
            if position % 2 == 0:
                dependencies.append(f"n{position - 1}")
        result.append((f"n{position}", role, dependencies))
    return result


@pytest.mark.parametrize("system", ["E4", "E5"])
@pytest.mark.parametrize("topology", ["independent", "chain", "fan_out", "all_prior", "diamond"])
@pytest.mark.parametrize("roles", ROLE_PATTERNS.values(), ids=ROLE_PATTERNS.keys())
def test_eight_task_topology_finishes_without_enlarging_graph_limit(monkeypatch, record_property, system, topology, roles):
    transitions = []
    for method in ("_retrieve", "_plan", "_run_scan", "_run_taint", "_run_authz", "_try_fast", "_adjudicate"):
        original = getattr(AgenticPipeline, method)
        def observed(self, state, *, _original=original, _method=method):
            transitions.append(_method)
            return _original(self, state)
        monkeypatch.setattr(AgenticPipeline, method, observed)
    tasks = _tasks(roles, topology)
    verdict, models = run_plan(tasks, system=system)
    assert GRAPH_TRANSITION_LIMIT == 16
    assert FULL_SYSTEM_HARNESS.planner_max_subtasks == 8
    executed = {item.task_id: item for item in verdict.task_executions if item.task_id is not None}
    assert set(executed) == {task_id for task_id, _, _ in tasks}
    assert all(item.validator_completed is True for item in executed.values())
    ordered = [item.task_id for item in verdict.task_executions]
    for task_id, _, dependencies in tasks:
        assert all(ordered.index(dependency) < ordered.index(task_id) for dependency in dependencies)
    assert len({vote.expert for vote in verdict.votes}) == len(verdict.votes) == 3
    assert not verdict.blocked_tasks
    assert verdict.label == "ABSTAIN" and verdict.path == "slow"
    assert verdict.model_calls == sum(len(model.requests) for model in models.values())
    assert verdict.model_calls == 2 * (1 + len(verdict.task_executions))
    assert transitions.count("_retrieve") == transitions.count("_plan") == transitions.count("_adjudicate") == 1
    assert transitions.count("_try_fast") <= (1 if system == "E5" else 0)
    assert len(transitions) == 3 + len(verdict.task_executions) + transitions.count("_try_fast")
    assert len(transitions) <= GRAPH_TRANSITION_LIMIT - 1
    record_property("task_nodes", len(verdict.task_executions))
    record_property("graph_node_executions", len(transitions))
    record_property("try_fast_nodes", transitions.count("_try_fast"))
