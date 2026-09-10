import json
from types import SimpleNamespace

import pytest

from cv_agent.agent_tools import ToolExecutionScope, ToolRegistry
from cv_agent.agent_types import ModelToolCall
from cv_agent.python_ast import parse_python_source
from cv_agent.validation_tools import full_agent_tools
from cv_agent.retrieval import RepositoryIndex


def probe(files, *, admitted=None, max_hops=4):
    docs = [span.document for path, source in files.items()
            for span in parse_python_source("probe-tests", path, source)]
    entry = next(doc for doc in docs if doc.path.startswith("entry.py::entry@"))
    registry = ToolRegistry(full_agent_tools(RepositoryIndex(docs)), max_output_bytes=1_000_000)
    observation = registry.invoke(
        ModelToolCall(call_id="probe", name="probe_python_eval",
                      arguments={"source_path": entry.path, "max_hops": max_hops}),
        allowed=("probe_python_eval",),
        scope=ToolExecutionScope(frozenset(doc.path for doc in docs if admitted is None or admitted(doc)), 8192),
    )
    return observation, json.loads(observation.content)


@pytest.mark.parametrize("call,expected", [
    ("calculate(value, 'audit')", "CONFIRMED"),
    ("calculate(expression=value, audit_tag='audit')", "CONFIRMED"),
    ("calculate(audit_tag='audit', expression=value)", "CONFIRMED"),
    ("calculate('1 + 1', value)", "UNRESOLVED"),
    ("calculate(audit_tag=value, expression='1 + 1')", "UNRESOLVED"),
])
def test_concrete_probe_checks_actual_arguments_in_cross_file_call(call, expected):
    observation, result = probe({
        "entry.py": f"from service import calculate\n\ndef entry(request):\n    value = request.args['expression']\n    return {call}\n",
        "service.py": "def calculate(expression: str, audit_tag: str):\n    return eval(expression)\n",
    })
    assert result["status"] == observation.validation_status.value == expected
    assert result["method"] == "bounded-concrete-input-probe"


@pytest.mark.parametrize("body,expected", [
    ("return eval(request.args['x'])", "CONFIRMED"),
    ("value = request.args['x']\n    value = '1 + 1'\n    return eval(value)", "UNRESOLVED"),
    ("return 0\n    eval(request.args['x'])", "UNRESOLVED"),
    ("if False:\n        eval(request.args['x'])\n    return 0", "UNRESOLVED"),
    ("value = request.args['x']\n    if value == 'constant':\n        return 0\n    return eval(value)", "CONFIRMED"),
    ("return eval('(481516 + 2342)')", "UNRESOLVED"),
])
def test_probe_matches_cpython_argument_observations_for_trusted_fixtures(body, expected):
    source = "def entry(request):\n    " + body + "\n"
    _, result = probe({"entry.py": source})
    assert result["status"] == expected
    for attempt in result["attempts"]:
        observed = []
        # These are fixed project-owned test strings. No repository code or model
        # output is executed by this reference check or by the production probe.
        namespace = {"eval": lambda value: observed.append(value)}
        exec(source, namespace)
        namespace["entry"](SimpleNamespace(args={"x": attempt["input"]}))
        assert (attempt["input"] in observed) == (attempt["outcome"] == "input reached eval")


@pytest.mark.parametrize("body", [
    "return eval(normalize(request.args['x']))",
    "for item in request.args['x']:\n        pass\n    return eval(request.args['x'])",
    "return eval(request.args['x'], {})",
    "return open('/etc/passwd').read()",
    "raise ValueError()\n    eval(request.args['x'])",
    "return eval(*[request.args['x']])",
])
def test_unsupported_code_does_not_manufacture_confirmation_or_safety(body):
    _, result = probe({"entry.py": "def entry(request):\n    " + body + "\n"})
    assert result["status"] == "UNRESOLVED"
    assert all(attempt["outcome"] == "unresolved" for attempt in result["attempts"])


def test_unknown_transform_and_constant_return_are_not_treated_as_taint_passthrough():
    _, result = probe({
        "entry.py": "from service import normalize\n\ndef entry(request):\n    return eval(normalize(request.args['x']))\n",
        "service.py": "def normalize(value):\n    return '1 + 1'\n",
    })
    assert result["status"] == "UNRESOLVED"
    assert all(attempt["outcome"] == "no witness" for attempt in result["attempts"])


@pytest.mark.parametrize("max_hops,admitted", [
    (0, None), (4, lambda doc: doc.path.startswith("entry.py")),
])
def test_probe_cannot_cross_call_depth_or_admitted_paths(max_hops, admitted):
    _, result = probe({
        "entry.py": "from service import calculate\n\ndef entry(request):\n    return calculate(request.args['x'])\n",
        "service.py": "def calculate(value):\n    return eval(value)\n",
    }, max_hops=max_hops, admitted=admitted)
    assert result["status"] == "UNRESOLVED"


def test_source_named_eval_is_not_treated_as_builtin_eval():
    _, result = probe({
        "entry.py": "from service import eval\n\ndef entry(request):\n    return eval(request.args['x'])\n",
        "service.py": "def eval(value):\n    return 0\n",
    })
    assert result["status"] == "UNRESOLVED"


@pytest.mark.parametrize("source", [
    "def entry(request):\n    result = eval(request.args['x'])\n    eval = 0\n    return result\n",
    "from service import safe as eval\n\ndef entry(request):\n    return eval(request.args['x'])\n",
    "from service import eval\n\ndef entry(request):\n    return eval(request.args['x'])\n",
])
def test_local_shadowing_aliases_and_recursive_eval_do_not_fake_builtin_witness(source):
    _, result = probe({
        "entry.py": source,
        "service.py": "def safe(value):\n    return 0\n\ndef eval(value):\n    return eval(value)\n",
    })
    assert result["status"] == "UNRESOLVED"
