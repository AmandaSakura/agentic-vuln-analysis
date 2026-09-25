"""Candidate scope, exceptional flow, and bounded fixed-point regressions."""
import json
import sys

import pytest

from cv_agent.agents.scanner import StaticScanner
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import ReActStep
from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.analysis import python_flow
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.validation.commands import command_construction
from cv_agent.tools.validation.dataflow import trace_dataflow
from cv_agent.tools.validation.models import CommandConstructionInput, PathInput, TraceDataflowInput
from cv_agent.tools.validation.patterns import SANITIZER_RULES, SINK_RULES, SOURCE_RULES, pattern_tool, static_check
from test_review_followup import vote


def observations(source, rule, path="entry.py", inspect=True):
    doc = CodeDocument(repository_id="r", path=path, text=source, language="python", adapter_tier="ast", defines=("entry",), calls=("get_cmd", "build_cmd"))
    helper = CodeDocument(repository_id="r", path="helper.py", text="def get_cmd(value):\n    return value\n", language="python", defines=("get_cmd", "build_cmd"))
    index = RepositoryIndex([doc, helper])
    candidate = next(c for c in StaticScanner().scan("r", [doc]) if c.metadata["rule"] == rule)
    subject = candidate_subject(index, candidate)
    scope = ToolExecutionScope(candidate_path=doc.path, admitted_paths=frozenset([doc.path, helper.path]), subject=subject, max_observation_tokens=12000)
    results = [
        static_check(index, PathInput(path=doc.path), scope),
        trace_dataflow(index, TraceDataflowInput(source_path=doc.path), scope),
        pattern_tool(index, "find_sanitizers", SANITIZER_RULES)(PathInput(path=doc.path), scope),
    ]
    if inspect:
        results.append(command_construction(index, CommandConstructionInput(source_path=doc.path), scope))
    steps = []
    for i, result in enumerate(results, 1):
        result = result.model_copy(update={"citation_id": f"tool:{i}"})
        steps.append(ReActStep(step=i, model_id="test", tool_call=ModelToolCall(call_id=f"c{i}", name=result.tool, arguments={}), observation=result))
    return steps, subject


def test_no_shell_established_and_unrelated_sanitizer_cannot_support_safe():
    trace, subject = observations('''def entry(value):
    int(1)
    subprocess.run(['python', '-c', get_cmd(value)])
''', "command-execution")
    assert json.loads(trace[-1].observation.content)["command_construction_status"] == "NOT_ESTABLISHED"
    assert json.loads(trace[2].observation.content)["findings"]
    with pytest.raises(ValueError, match="inspect_command_construction"):
        vote(trace, subject, "SAFE")


@pytest.mark.parametrize("path", ["entry.py", "entry.py::entry@40-43"])
@pytest.mark.parametrize("inspect", [False, True])
@pytest.mark.parametrize("rule", ["dynamic-evaluation", "command-execution"])
def test_command_gate_applies_only_to_corresponding_candidate(path, inspect, rule):
    trace, subject = observations('''def entry(request):
    eval(request.args['x'])
    subprocess.run(['echo', build_cmd('ok')])
''', rule, path, inspect)
    assert json.loads(trace[1].observation.content)["flow_status"] == "MAY_REACH"
    if inspect:
        assert json.loads(trace[-1].observation.content)["command_construction_status"] == "NOT_ESTABLISHED"
    if rule == "dynamic-evaluation":
        vote(trace, subject, "VULNERABLE")
    else:
        with pytest.raises(ValueError, match="inspect_command_construction"):
            vote(trace, subject, "VULNERABLE")


def flow(source):
    doc = CodeDocument(repository_id="r", path="entry.py", text=source, language="python")
    return python_flow.python_document_flow(doc, initial_tainted=(), sink_category="code-execution", source_rules=SOURCE_RULES, sink_rules=SINK_RULES, sanitizer_rules=SANITIZER_RULES)


@pytest.mark.parametrize("trigger", ["value = int(value)", "value = 'ok'\n        raise ValueError()"])
@pytest.mark.parametrize("restore, expected", [("backup", True), ("'ok'", False)])
def test_except_receives_state_at_exception(trigger, restore, expected):
    result = flow(f'''def entry(request):
    value = request.args['x']
    try:
        backup = value
        {trigger}
    except ValueError:
        value = {restore}
    eval(value)
''')
    assert result["sinks"][0]["tainted"] is expected


def test_else_does_not_run_after_except_and_clear_restored_taint():
    result = flow('''def entry(request):
    value = request.args['x']
    try:
        backup = value
        value = int(value)
    except ValueError:
        value = backup
    else:
        value = 'ok'
    eval(value)
''')
    assert result["sinks"][0]["tainted"] is True


@pytest.mark.parametrize("termination", ["raise ValueError()", "int(value)"])
def test_exception_state_survives_nested_finally(termination):
    result = flow(f'''def entry(request):
    value = request.args['x']
    try:
        try:
            backup = value
            {termination}
        finally:
            value = 'ok'
    except ValueError:
        value = backup
    eval(value)
''')
    assert result["sinks"][0]["tainted"] is True


@pytest.mark.parametrize("iterable", ["[1]", "request.args['items']"])
def test_nested_loops_do_not_repeat_identical_analysis_states(iterable):
    depth = 12
    lines = ["def entry(request):"]
    for level in range(depth):
        lines.append("    " * (level + 1) + "value = 'ok'")
        lines.append("    " * (level + 1) + f"for _ in {iterable}:")
    lines.append("    " * (depth + 1) + "value = request.args['x']")
    lines.append("    eval(value)")
    visits = 0

    def count_visits(frame, event, arg):
        nonlocal visits
        if event == "call" and frame.f_code.co_filename == python_flow.__file__ and frame.f_code.co_name == "visit":
            visits += 1

    previous = sys.getprofile()
    sys.setprofile(count_visits)
    try:
        result = flow("\n".join(lines))
    finally:
        sys.setprofile(previous)
    assert result["sinks"][0]["tainted"] is True
    assert visits <= 4 * depth * depth, f"Repeated block evaluations: {visits}"


def test_finally_clears_exception_state_before_outer_handler():
    result = flow('''def entry(request):
    value = request.args['x']
    try:
        try:
            raise ValueError()
        finally:
            value = 'ok'
    except ValueError:
        eval(value)
''')
    assert result["sinks"][0]["tainted"] is False


def test_sanitized_command_does_not_refute_separate_eval_candidate():
    trace, subject = observations('''def entry(request):
    eval(request.args['x'])
    subprocess.run('echo ' + shlex.quote(build_cmd('ok')), shell=True)
''', "dynamic-evaluation")
    assert json.loads(trace[-1].observation.content)["command_construction_status"] == "SANITIZED"
    vote(trace, subject, "VULNERABLE")
