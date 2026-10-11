import pytest
from langgraph.errors import GraphRecursionError

from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.harness import FULL_SYSTEM_HARNESS
from test_planner_dependencies import run_plan


def test_maximum_legal_eight_task_plan_has_an_explicit_measured_bound(monkeypatch):
    from langgraph.graph.state import CompiledStateGraph
    invoke = CompiledStateGraph.invoke
    configs = []
    def capture(self, *args, **kwargs):
        configs.append(kwargs.get("config", {}))
        return invoke(self, *args, **kwargs)
    monkeypatch.setattr(CompiledStateGraph, "invoke", capture)
    count = []
    original = AgenticPipeline._run_named_expert
    def observed(self, state, name):
        count.append(name)
        return original(self, state, name)
    monkeypatch.setattr(AgenticPipeline, "_run_named_expert", observed)
    roles = ("scan", "taint", "authz", "scan", "taint", "authz", "scan", "taint")
    tasks = [(f"t{i}", role, [f"t{i-1}"] if i else []) for i, role in enumerate(roles)]
    verdict, models = run_plan(tasks)
    assert len(verdict.task_executions) == FULL_SYSTEM_HARNESS.planner_max_subtasks == 8
    assert len(count) == 8
    assert configs[0].get("recursion_limit") == 16
    assert verdict.label == "ABSTAIN"
    assert verdict.model_calls == sum(len(model.requests) for model in models.values())


def test_injected_no_progress_graph_stops_within_business_limit(monkeypatch):
    count = []
    def no_progress(self, state):
        count.append(1)
        if len(count) > 32:
            raise AssertionError("graph exceeded the frozen business limit")
        return {}
    monkeypatch.setattr(AgenticPipeline, "_run_scan", no_progress)
    monkeypatch.setattr(AgenticPipeline, "_route_next", lambda self, state: "scan")
    with pytest.raises(GraphRecursionError):
        run_plan([("a", "scan", [])], system="E4")
    assert len(count) <= 16
