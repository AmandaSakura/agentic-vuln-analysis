"""Exceptional boundaries and affirmative candidate evidence from follow-up review."""
import json

import pytest

from cv_agent.agents.evidence_policy import validate_conclusion
from cv_agent.agents.scanner import StaticScanner
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import ReActStep
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation.registry import validation_tools
from test_review_state_and_scope import flow


def command_trace(source, *, inputs=()):
    document = CodeDocument(repository_id="r", path="entry.py", language="python",
                            adapter_tier="ast", text=source)
    index = RepositoryIndex([document])
    candidate = next(c for c in StaticScanner().scan("r", [document])
                     if c.metadata["rule"] == "command-execution")
    candidate = candidate.model_copy(update={"input_parameters": inputs})
    subject = candidate_subject(index, candidate)
    scope = ToolExecutionScope(candidate_path=document.path, subject=subject,
                               admitted_paths=frozenset([document.path]), max_observation_tokens=20000)
    registry = ToolRegistry(validation_tools(index), max_output_bytes=40000)
    calls = [
        ("run_static_check", {"path": document.path}),
        ("trace_dataflow", {"source_path": document.path, "sink_category": "command-execution"}),
        ("find_sanitizers", {"path": document.path}),
        ("inspect_command_construction", {"source_path": document.path}),
    ]
    trace = []
    for i, (name, arguments) in enumerate(calls, 1):
        call = ModelToolCall(call_id=f"call:{i}", name=name, arguments=arguments)
        observation = registry.invoke(call, allowed=[name], scope=scope)
        assert observation.status == "ok", observation.content
        observation = observation.model_copy(update={"citation_id": f"tool:{i}"})
        trace.append(ReActStep(step=i, model_id="test", tool_call=call, observation=observation))
    return trace, subject


def assess(trace, subject, label):
    ids = tuple(step.observation.citation_id for step in trace)
    output = AgentExpertConclusion(expert="scan", label=label, confidence=0.8,
                                  rationale="Assess the candidate using the inspected source and flow.",
                                  evidence_ids=ids, supporting_observation_ids=ids,
                                  validation_status="UNRESOLVED")
    validate_conclusion(output, trace, frozenset(ids), subject=subject)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("termination", ["pass", "return", "break", "continue"])
@pytest.mark.parametrize("tainted", [False, True])
def test_context_exit_errors_carry_every_pending_body_state(asynchronous, termination, tainted):
    prefix = "async " if asynchronous else ""
    value = "request.args['x']" if tainted else "'0'"
    result = flow(f'''{prefix}def entry(request, manager):
    value = request.args['x']
    try:
        value = '0'
        for _ in [1]:
            {prefix}with manager:
                value = {value}
                {termination}
        value = '0'
    except ValueError:
        eval(value)
''')
    assert result["sinks"] and result["sinks"][0]["tainted"] is tainted


@pytest.mark.parametrize("loop", ["while cond():", "for _ in iterable:", "async for _ in iterable:"])
@pytest.mark.parametrize("tainted", [False, True])
def test_loop_header_errors_use_loop_carried_state(loop, tainted):
    prefix = "async " if loop.startswith("async") else ""
    value = "request.args['x']" if tainted else "'0'"
    result = flow(f'''{prefix}def entry(request, cond, iterable):
    value = request.args['x']
    try:
        value = '0'
        {loop}
            value = '0'
            value = {value}
        value = '0'
    except ValueError:
        eval(value)
''')
    assert result["sinks"] and result["sinks"][0]["tainted"] is tainted


def test_while_condition_sink_is_revisited_after_the_body():
    result = flow('''def entry(request):
    value = '0'
    while eval(value):
        value = request.args['x']
''')
    assert result["sinks"][0]["tainted"]


# C1/C3: argv controls declare primitive text inputs explicitly. Framework
# property access has no purity summary; the original shape stays a negative
# control below rather than silently serving as a numeric-proof premise.
@pytest.mark.parametrize("expression", ["request.args['x']", "str(int(request.args['x']))", "shlex.quote(request.args['x'])"])
def test_unknown_request_access_cannot_supply_command_proof(expression):
    trace, subject = command_trace(f"def entry(request):\n    subprocess.run(['python', '-c', {expression}])\n")
    assert json.loads(trace[-1].observation.content)["issues"]
    for label in ("SAFE", "VULNERABLE"):
        with pytest.raises(ValueError):
            assess(trace, subject, label)


@pytest.mark.parametrize("argument,safe", [
    ("str(int(input_x))", True),
    ("input_x", False),
    ("shlex.quote(input_x)", False),
])
def test_numeric_non_shell_argv_can_support_safety(argument, safe):
    trace, subject = command_trace(f'''def entry(input_x, request):
    int(1)
    subprocess.run(['python', '-c', {argument}])
''', inputs=('input_x',))
    if safe:
        assess(trace, subject, "SAFE")
    else:
        with pytest.raises(ValueError):
            assess(trace, subject, "SAFE")


@pytest.mark.parametrize("parameters,extra", [
    ("request, int", ""),
    ("request, str", ""),
    ("request", ", executable=input_program"),
    ("request", ", env=input_environment"),
    ("request", ", shell=input_shell"),
])
def test_numeric_argv_does_not_ignore_shadowing_or_execution_overrides(parameters, extra):
    trace, subject = command_trace(f'''def entry(input_environment, input_program, input_shell, input_x, {parameters}):
    subprocess.run(['python', '-c', str(int(input_x))]{extra})
''', inputs=('input_environment', 'input_program', 'input_shell', 'input_x'))
    with pytest.raises(ValueError):
        assess(trace, subject, "SAFE")


def test_numeric_argv_fact_requires_all_dynamic_arguments_to_be_numeric():
    trace, subject = command_trace('''def entry(input_code, input_x, request):
    subprocess.run(['python', '-c', input_code, str(int(input_x))])
''', inputs=('input_code', 'input_x'))
    with pytest.raises(ValueError):
        assess(trace, subject, "SAFE")


def test_numeric_argv_tracks_assigned_result_at_the_candidate():
    trace, subject = command_trace('''def entry(input_x, request):
    count = int(input_x)
    code = str(count)
    subprocess.run(['python', '-c', code])
''', inputs=('input_x',))
    assess(trace, subject, "SAFE")


@pytest.mark.parametrize("raw_first", [False, True])
def test_one_numeric_sink_does_not_protect_another_sink_on_the_same_line(raw_first):
    calls = ["subprocess.run(['python', '-c', str(int(input_n))])",
             "subprocess.run(['python', '-c', input_code])"]
    if raw_first:
        calls.reverse()
    trace, subject = command_trace("def entry(input_code, input_n, request):\n    " + "; ".join(calls) + "\n", inputs=('input_code', 'input_n'))
    with pytest.raises(ValueError):
        assess(trace, subject, "SAFE")
    assess(trace, subject, "VULNERABLE")


@pytest.mark.parametrize("tail,safe", [(",-1,None", True), (",-1,None,None,None,None,None,None,True", False)])
def test_numeric_argv_respects_positional_popen_options(tail, safe):
    trace, subject = command_trace(f'''def entry(input_n, request):
    subprocess.Popen(['python', '-c', str(int(input_n))]{tail})
''', inputs=('input_n',))
    if safe:
        assess(trace, subject, "SAFE")
    else:
        with pytest.raises(ValueError):
            assess(trace, subject, "SAFE")


@pytest.mark.parametrize("whole_argv", [False, True])
@pytest.mark.parametrize("safe", [False, True])
def test_numeric_argv_joins_literal_alternatives_without_ignoring_raw_ones(whole_argv, safe):
    alternative = "'0'" if safe else "input_code"
    if whole_argv:
        assignment = ("args = ['python', '-c', str(int(input_n))] if flag "
                      f"else ['python', '-c', {alternative}]")
        argument = "args"
    else:
        assignment = f"code = str(int(input_n)) if flag else {alternative}"
        argument = "['python', '-c', code]"
    trace, subject = command_trace(f"def entry(input_code, input_n, request, flag):\n    {assignment}\n    subprocess.run({argument})\n", inputs=('input_code', 'input_n', 'flag'))
    if safe:
        assess(trace, subject, "SAFE")
    else:
        with pytest.raises(ValueError):
            assess(trace, subject, "SAFE")
        assess(trace, subject, "VULNERABLE")


@pytest.mark.parametrize("unsupported", [False, True])
def test_later_unsupported_statement_does_not_erase_unsafe_witness(unsupported):
    suffix = "    try:\n        pass\n    finally:\n        pass\n" if unsupported else ""
    trace, subject = command_trace("def entry(value):\n    os.system(value)\n" + suffix, inputs=("value",))
    inspection = json.loads(trace[-1].observation.content)
    assert inspection["sink_facts"][0]["status"] == "UNSANITIZED"
    assess(trace, subject, "VULNERABLE")
    with pytest.raises(ValueError):
        assess(trace, subject, "SAFE")


@pytest.mark.parametrize("docstring", [False, True])
@pytest.mark.parametrize("sanitized", [False, True])
def test_numeric_helper_docstring_preserves_return_flow(docstring, sanitized):
    from cv_agent.tools.validation.models import PathInput
    from cv_agent.tools.validation.patterns import SANITIZER_RULES, pattern_tool
    from test_review_evidence_precedence import step

    caller = CodeDocument(repository_id="r", path="entry.py", language="python", adapter_tier="ast",
                          text="def entry(value):\n    return eval(parse_number(value))\n",
                          defines=("entry",), calls=("parse_number",))
    body = '    """Convert user text to numeric text."""\n' if docstring else ""
    body += "    return str(int(value))\n" if sanitized else "    int(value)\n    return value\n"
    helper = CodeDocument(repository_id="r", path="helper.py", language="python", adapter_tier="ast",
                          text="def parse_number(value):\n" + body, defines=("parse_number",))
    index = RepositoryIndex([caller, helper])
    subject = candidate_subject(index, StaticScanner().scan("r", [caller])[0])
    scope = ToolExecutionScope(candidate_path=caller.path, subject=subject,
                               admitted_paths=frozenset([caller.path, helper.path]), max_observation_tokens=10000)
    observation = pattern_tool(index, "find_sanitizers", SANITIZER_RULES)(PathInput(path=helper.path), scope)
    assert json.loads(observation.content)["findings"]
    # C1/C5: pattern return-flow facts are retained, not upgraded to eval safety.
    assert bool(json.loads(observation.content)["candidate_sanitizer_flows"]) is sanitized
    with pytest.raises(ValueError, match="matching cited proof"):
        assess([step(observation, 1)], subject, "SAFE")
