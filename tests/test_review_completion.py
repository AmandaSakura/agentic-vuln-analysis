"""Behavioral regressions for incomplete commands and candidate flow selection."""
import json

import pytest

from cv_agent.agents.scanner import StaticScanner
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation.registry import validation_tools
from test_review_evidence_precedence import step
from test_review_followup import vote
from test_review_state_and_scope import flow, observations


@pytest.mark.parametrize("supported, tainted", [(False, True), (True, True), (True, False)])
def test_loop_command_evidence_requires_complete_interpretation(supported, tainted):
    assignment = "cmd = value" if tainted else "cmd = 'echo next'"
    tail = f"        {assignment}" if supported else f"        try:\n            {assignment}\n        finally:\n            pass"
    trace, subject = observations(f'''def entry(value):
    cmd = 'echo ok'
    for _ in [1, 2]:
        os.system(cmd)
{tail}
''', "command-execution")
    inspection = json.loads(trace[-1].observation.content)
    if not supported:
        assert inspection["command_construction_status"] == "AMBIGUOUS"
        assert inspection["issues"] == ["unsupported statement: Try"]
        assert inspection["sink_facts"][0]["status"] == "SANITIZED"
        with pytest.raises(ValueError):
            vote(trace, subject, "SAFE")
    elif tainted:
        assert inspection["command_construction_status"] == "UNSANITIZED"
        vote(trace, subject, "VULNERABLE")
        with pytest.raises(ValueError):
            vote(trace, subject, "SAFE")
    else:
        assert inspection["command_construction_status"] == "SANITIZED"
        vote(trace, subject, "SAFE")


@pytest.mark.parametrize("path", ["entry.py", "entry.py::entry@40-43"])
@pytest.mark.parametrize("command_first", [False, True])
@pytest.mark.parametrize("tainted", [False, True])
def test_non_shell_candidate_gets_its_own_flow(path, command_first, tainted):
    argument = "request.args['x']" if tainted else "'print(1)'"
    statements = ["    eval(request.args['code'])", f"    subprocess.run(['python', '-c', {argument}])"]
    if command_first:
        statements.reverse()
    trace, subject = observations("def entry(request):\n" + "\n".join(statements) + "\n", "command-execution", path)
    data = json.loads(trace[1].observation.content)
    assert data["flow_status"] == "MAY_REACH"
    assert json.loads(trace[-1].observation.content)["command_construction_status"] == "NOT_ESTABLISHED"
    if tainted:
        line = 2 if command_first else 3
        assert any(sink["category"] == "command-execution" and sink["line"] == line and sink["tainted"]
                   for step in data["trace"] if step["path"] == path for sink in step["sinks"])
        vote(trace, subject, "VULNERABLE")
    else:
        with pytest.raises(ValueError, match="inspect_command_construction"):
            vote(trace, subject, "VULNERABLE")


@pytest.mark.parametrize("category", ["command-execution", "code-execution"])
@pytest.mark.parametrize("tainted", [False, True])
def test_explicit_flow_category_distinguishes_candidates_on_one_line(category, tainted):
    argument = "request.args['x']" if tainted else "'print(1)'"
    doc = CodeDocument(repository_id="r", path="entry.py", language="python", adapter_tier="ast",
                       text=f"def entry(request):\n    eval(request.args['code']); subprocess.run(['python', '-c', {argument}])\n")
    index = RepositoryIndex([doc])
    candidate = next(c for c in StaticScanner().scan("r", [doc]) if c.metadata["rule"] == "command-execution")
    subject = candidate_subject(index, candidate)
    scope = ToolExecutionScope(candidate_path=doc.path, admitted_paths=frozenset([doc.path]),
                               subject=subject, max_observation_tokens=12000)
    registry = ToolRegistry(validation_tools(index), max_output_bytes=20000)
    calls = [
        ("run_static_check", {"path": doc.path}),
        ("trace_dataflow", {"source_path": doc.path, "sink_category": category}),
        ("inspect_command_construction", {"source_path": doc.path}),
    ]
    trace = []
    for i, (name, arguments) in enumerate(calls, 1):
        result = registry.invoke(ModelToolCall(call_id=f"call:{i}", name=name, arguments=arguments),
                                 allowed=[name], scope=scope)
        assert result.status == "ok", result.content
        trace.append(step(result, i))
    data = json.loads(trace[1].observation.content)
    if category == "command-execution" and tainted:
        assert data["flow_status"] == "MAY_REACH"
        assert all(sink["category"] == category for entry in data["trace"] for sink in entry["sinks"])
        vote(trace, subject, "VULNERABLE")
    else:
        assert data["flow_status"] == ("MAY_REACH" if category == "code-execution" else "NOT_ESTABLISHED")
        with pytest.raises(ValueError):
            vote(trace, subject, "VULNERABLE")


@pytest.mark.parametrize("manager", ["contextlib.suppress(ValueError), failing()", "contextlib.suppress(ValueError), manager, failing()"])
@pytest.mark.parametrize("value, tainted", [("request.args['x']", True), ("'0'", False)])
def test_later_context_entry_failure_can_be_suppressed(manager, value, tainted):
    result = flow(f'''def entry(request):
    value = {value}
    try:
        with {manager}:
            return
    finally:
        pass
    eval(value)
''')
    assert len(result["sinks"]) == 1
    assert result["sinks"][0]["tainted"] is tainted


def test_single_context_cannot_suppress_its_own_entry_failure():
    result = flow('''def entry(request):
    with failing():
        return
    eval(request.args['x'])
''')
    assert not result["sinks"]
