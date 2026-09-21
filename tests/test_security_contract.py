"""Semantic boundaries, including negative examples from the project review."""
import json

import pytest

from cv_agent.agent_tools import ToolExecutionScope, ToolRegistry
from cv_agent.agent_types import ModelToolCall
from cv_agent.python_ast import parse_python_source
from cv_agent.retrieval import RepositoryIndex
from cv_agent.validation_tools import full_agent_tools


def make_index(files):
    return RepositoryIndex(span.document for path, source in files.items()
                           for span in parse_python_source("contract", path, source))


def entry(index, name="entry"):
    return next(path for path in index.documents if f"::{name}@" in path)


def invoke(index, tool, arguments, *, candidate_path=None, **options):
    registry = ToolRegistry(full_agent_tools(index, **options), max_output_bytes=100000)
    return registry.invoke(ModelToolCall(call_id="contract", name=tool, arguments=arguments),
                           allowed=(tool,), citation_id="contract:1",
                           scope=ToolExecutionScope(frozenset(index.documents), 100000,
                                                    candidate_path=candidate_path or entry(index)))


@pytest.mark.parametrize("body", [
    'return "safe"\n    eval(request.args["x"])',
    'raise ValueError("stop")\n    eval(request.args["x"])',
    'if True:\n        return "safe"\n    eval(request.args["x"])',
    'while False:\n        eval(request.args["x"])\n    return "safe"',
    'subprocess.run(["/bin/echo", request.args["x"]], shell=False)',
    'subprocess.run(args=["/bin/echo", request.args["x"]])',
])
def test_safe_or_unreachable_flow_is_not_a_witness(body):
    index = make_index({"entry.py": "def entry(request):\n    " + body + "\n"})
    observation = invoke(index, "trace_dataflow", {"source_path": entry(index)})
    assert observation.validation_status.value == "UNRESOLVED"
    assert json.loads(observation.content)["trace"] == []


def test_reachable_flow_remains_visible_without_becoming_exploit_confirmation():
    index = make_index({"entry.py": 'def entry(request):\n    return eval(request.args["x"])\n'})
    observation = invoke(index, "trace_dataflow", {"source_path": entry(index)})
    payload = json.loads(observation.content)
    assert observation.validation_status.value == "UNRESOLVED"
    assert payload["flow_status"] == "MAY_REACH"
    assert any(sink["tainted"] for step in payload["trace"] for sink in step["sinks"])
    probe = invoke(index, "probe_python_eval", {"source_path": entry(index)})
    assert probe.validation_status.value == "CONFIRMED"


def test_dictionary_update_does_not_confirm_authorization_failure():
    index = make_index({"entry.py": 'def entry(request):\n    cache = {}\n    cache.update({"last_seen": 1})\n'})
    observation = invoke(index, "compare_route_and_service_guard", {"route_path": entry(index)})
    assert observation.validation_status.value == "UNRESOLVED"


def test_constant_refactor_is_only_a_source_difference():
    index = make_index({"entry.py": 'def entry(request):\n    return eval("1 + 1")\n'})
    fixed = make_index({"entry.py": 'def entry(request):\n    return 2\n'})
    observation = invoke(index, "compare_vulnerable_and_fixed", {"path": entry(index)},
                         fixed_index=fixed, paired_paths={entry(index): entry(fixed)})
    assert observation.validation_status.value == "UNRESOLVED"
    assert json.loads(observation.content)["fixed_sink_count"] == 0


@pytest.mark.parametrize("binding", [
    "eval = lambda value: value", "eval = str", "if True:\n    eval = str",
    "from external import *",
])
def test_module_binding_cannot_be_assumed_to_be_builtin_eval(binding):
    index = make_index({"entry.py": binding + '\ndef entry(request):\n    return eval(request.args["x"])\n'})
    observation = invoke(index, "probe_python_eval", {"source_path": entry(index)})
    assert observation.validation_status.value == "UNRESOLVED"


@pytest.mark.parametrize("import_line,call", [
    ("from external import calculate", "calculate"),
    ("from external import calculate as compute", "compute"),
    ("import external", "external.calculate"),
])
def test_external_import_does_not_link_to_unrelated_local_name(import_line, call):
    index = make_index({
        "entry.py": import_line + f'\ndef entry(request):\n    return {call}(request.args["x"])\n',
        "unrelated.py": "def calculate(value):\n    return eval(value)\n",
    })
    assert index.graph_neighbors(entry(index), direction="forward") == ()
    observation = invoke(index, "probe_python_eval", {"source_path": entry(index)})
    assert observation.validation_status.value == "UNRESOLVED"


def test_resolved_import_alias_still_reaches_actual_callee():
    index = make_index({
        "entry.py": 'from service import calculate as compute\ndef entry(request):\n    return compute(request.args["x"])\n',
        "service.py": "def calculate(value):\n    return eval(value)\n",
    })
    assert index.graph_neighbors(entry(index), direction="forward") == (entry(index, "calculate"),)
    observation = invoke(index, "probe_python_eval", {"source_path": entry(index)})
    assert observation.validation_status.value == "CONFIRMED"
    trace = invoke(index, "trace_dataflow", {"source_path": entry(index)})
    assert json.loads(trace.content)["flow_status"] == "MAY_REACH"


@pytest.mark.parametrize("binding", [
    "from service import calculate\ncalculate = str",
    "from service import calculate\nif True:\n    calculate = str",
])
def test_rebound_import_does_not_execute_the_old_import_in_probe(binding):
    index = make_index({
        "entry.py": binding + '\ndef entry(request):\n    return calculate(request.args["x"])\n',
        "service.py": "def calculate(value):\n    return eval(value)\n",
    })
    observation = invoke(index, "probe_python_eval", {"source_path": entry(index)})
    assert observation.validation_status.value == "UNRESOLVED"


def test_dataflow_cannot_start_at_another_retrieved_entry():
    index = make_index({"entry.py": 'def entry(request):\n    return "safe"\n\ndef helper(request):\n    return eval(request.args["x"])\n'})
    observation = invoke(index, "trace_dataflow", {"source_path": entry(index, "helper")})
    assert observation.status == "blocked"


def test_detector_pair_ids_are_neutral():
    from pathlib import Path
    config = json.loads((Path(__file__).parents[1] / "configs/langchain_pair_eval.json").read_text())
    for case in config["detector_cases"]:
        assert not any(word in case["case_id"].lower() for word in ("vulnerable", "fixed", "safe", "cve"))
