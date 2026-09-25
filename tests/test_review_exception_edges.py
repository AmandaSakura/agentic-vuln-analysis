"""Regressions for implicit statement errors and precise flow/scope boundaries."""
import json

import pytest

from cv_agent.agents.evidence_policy import _candidate_static_findings
from test_review_followup import vote
from test_review_state_and_scope import flow, observations


@pytest.mark.parametrize("statement", [
    "import optional_parser",
    "from optional_parser import parse",
    "left, right = (1,)",
    "[left, right] = 1",
    "assert False",
    "del missing_name",
    "missing_name += 1",
])
@pytest.mark.parametrize("value, tainted", [("request.args['x']", True), ("'0'", False)])
def test_nonexpression_errors_reach_handler(statement, value, tainted):
    result = flow(f'''def entry(request):
    try:
        {statement}
    except:
        eval({value})
''')
    assert len(result["sinks"]) == 1
    assert result["sinks"][0]["tainted"] is tainted


def test_constant_assignment_does_not_invent_exception_edge():
    result = flow('''def entry(request):
    try:
        value = '0'
    except:
        eval(request.args['x'])
''')
    assert result["sinks"] == ()


@pytest.mark.parametrize("path", ["entry.py", "entry.py::entry@40-43"])
@pytest.mark.parametrize("command", [
    "subprocess.run(['echo', build_cmd('ok')])",
    "subprocess.run('echo ' + shlex.quote(build_cmd('ok')), shell=True)",
])
def test_missing_candidate_line_never_uses_other_sink_lines(path, command):
    trace, subject = observations(f'''def entry(request):
    builtins.eval(request.args['x'])
    {command}
''', "dynamic-evaluation", path)
    static = trace[0].observation
    assert json.loads(static.content)["findings"]
    assert _candidate_static_findings(static, subject) == []
    # This is an unresolved hypothesis about the scanned builtins.eval candidate;
    # shell evidence from another operation neither proves nor refutes it.
    trace = [step for step in trace if step.observation.tool != "trace_dataflow"]
    vote(trace, subject, "VULNERABLE")


@pytest.mark.parametrize("handler, expected", [("value = '0'", False), ("pass", True)])
def test_bare_handler_consumes_original_exception_state(handler, expected):
    result = flow(f'''def entry(request):
    value = '0'
    try:
        value = request.args['x']
        raise RuntimeError()
    except:
        {handler}
    finally:
        eval(value)
''')
    assert result["sinks"][0]["tainted"] is expected


@pytest.mark.parametrize("handler, expected", [("value = '0'", False), ("raise", True)])
def test_handler_only_propagates_new_or_reraised_exceptions(handler, expected):
    result = flow(f'''def entry(request):
    value = '0'
    try:
        try:
            value = request.args['x']
            raise RuntimeError()
        except:
            {handler}
    except:
        eval(value)
''')
    if expected:
        assert result["sinks"][0]["tainted"] is True
    else:
        assert result["sinks"] == ()


def test_else_exception_is_not_caught_by_same_try_handler():
    result = flow('''def entry(request):
    value = '0'
    try:
        pass
    except:
        value = '0'
    else:
        value = request.args['x']
        raise RuntimeError()
    finally:
        eval(value)
''')
    assert result["sinks"][0]["tainted"] is True


@pytest.mark.parametrize("target, iterable, expected", [
    ("value", "['0', '1']", False),
    ("value", "request.args['items']", True),
    ("(value, other)", "[('0', '1')]", False),
])
@pytest.mark.parametrize("tail", ["", "\n        continue"])
def test_for_target_is_rebound_on_every_iteration(target, iterable, expected, tail):
    result = flow(f'''def entry(request):
    for {target} in {iterable}:
        eval(value)
        value = request.args['x']{tail}
''')
    assert len(result["sinks"]) == 1
    assert result["sinks"][0]["tainted"] is expected


def test_for_rebinding_does_not_clear_other_carried_variables_or_final_value():
    result = flow('''def entry(request):
    carry = '0'
    for value in ['0', '1']:
        eval(carry)
        carry = request.args['x']
        value = request.args['x']
    eval(value)
''')
    assert len(result["sinks"]) == 2
    assert all(sink["tainted"] for sink in result["sinks"])


@pytest.mark.parametrize("statement", ["left, right = (1, 2)", "assert True"])
def test_known_nonthrowing_statements_do_not_reach_handler(statement):
    result = flow(f'''def entry(request):
    try:
        {statement}
    except:
        eval(request.args['x'])
''')
    assert result["sinks"] == ()


def test_import_failure_with_typed_handler_is_visible_through_trace_tool():
    trace, _ = observations('''def entry(request):
    try:
        import optional_parser
    except ImportError:
        eval(request.args['x'])
''', "dynamic-evaluation", inspect=False)
    assert json.loads(trace[1].observation.content)["flow_status"] == "MAY_REACH"
