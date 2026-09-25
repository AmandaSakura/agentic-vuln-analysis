"""Regression coverage for the four follow-up semantic review findings."""
import json
import subprocess
import sys

import pytest

from cv_agent.agents.react import validate_conclusion
from cv_agent.code_adapters.javascript import parse_typescript_source
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import ReActStep, ValidationSubject
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import repository_source_digest
from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.validation.commands import command_construction
from cv_agent.tools.validation.models import CommandConstructionInput, PathInput
from cv_agent.tools.validation.patterns import SINK_RULES, _matching_lines, static_check


@pytest.mark.parametrize("loop", ["for _ in [1]:", "while flag:"])
@pytest.mark.parametrize("assignment, expected", [("request.args['x']", "MAY_REACH"), ("'ok'", "NOT_ESTABLISHED")])
def test_loop_reset_continue_terminates_and_preserves_exit_taint(loop, assignment, expected):
    source = f'''def entry(request, flag):
    value = 'ok'
    {loop}
        value = 'ok'
        if flag:
            value = {assignment}
            continue
    eval(value)
'''
    # A separate process bounds the original infinite analysis without hanging pytest.
    script = f'''
import json
from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.validation.dataflow import trace_dataflow
from cv_agent.tools.validation.models import TraceDataflowInput
doc = CodeDocument(repository_id="r", path="entry.py", text={source!r}, language="python", defines=("entry",))
result = trace_dataflow(RepositoryIndex([doc]), TraceDataflowInput(source_path=doc.path), ToolExecutionScope(candidate_path=doc.path, admitted_paths=frozenset([doc.path]), max_observation_tokens=4000))
print(json.loads(result.content)["flow_status"])
'''
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


@pytest.mark.parametrize("expression, count", [
    ("eval(req.query.x)", 1),
    ('"eval(req.query.x)"', 0),
    ("/eval\\(req.query.x\\)/", 0),
])
def test_tsx_adapter_preserves_code_and_masks_literals(expression, count):
    parsed = parse_typescript_source("r", "View.tsx", f"function View(req) {{ return <div><span>hello</span>{{{expression}}}</div>; }}")
    assert not parsed.has_error
    assert parsed.spans
    for span in parsed.spans:
        assert span.document.language == "typescript"
        assert len(_matching_lines(span.document, SINK_RULES)) == count


def inspect_and_trace(caller_text, helper_text):
    caller = CodeDocument(repository_id="r", path="entry.py", text=caller_text, language="python", defines=("entry",), calls=("build_cmd",))
    helper = CodeDocument(repository_id="r", path="helper.py", text=helper_text, language="python", defines=("build_cmd",))
    index = RepositoryIndex([caller, helper])
    subject = ValidationSubject(candidate_id="c", repository_id="r", entry_path=caller.path, source_digest=repository_source_digest(index))
    scope = ToolExecutionScope(candidate_path=caller.path, admitted_paths=frozenset([caller.path, helper.path]), subject=subject, max_observation_tokens=10000)
    inspection = command_construction(index, CommandConstructionInput(source_path=caller.path), scope).model_copy(update={"citation_id": "tool:cmd"})
    static = static_check(index, PathInput(path=caller.path), scope).model_copy(update={"citation_id": "tool:static"})
    trace = [ReActStep(step=i, model_id="test", tool_call=ModelToolCall(call_id=obs.citation_id, name=obs.tool, arguments={}), observation=obs) for i, obs in enumerate((static, inspection), 1)]
    return json.loads(inspection.content), trace, subject


def vote(trace, subject, label):
    ids = tuple(step.observation.citation_id for step in trace)
    conclusion = AgentExpertConclusion(expert="scan", label=label, confidence=0.8, rationale="Assess caller and admitted helper command construction.", validation_status="UNRESOLVED", evidence_ids=ids, supporting_observation_ids=ids)
    validate_conclusion(conclusion, trace, frozenset(ids), subject=subject)


@pytest.mark.parametrize("unsupported", [True, False])
def test_helper_failure_cannot_support_safe_vote(unsupported):
    helper = '''def build_cmd(value):
    try:
        os.system(value)
    except Exception:
        pass
''' if unsupported else '''def build_cmd(value):
    return "echo " + shlex.quote(value)
'''
    caller = '''def entry(value):
    build_cmd(value)
    os.system("echo " + shlex.quote(value))
'''
    data, trace, subject = inspect_and_trace(caller, helper)
    if unsupported:
        assert data["command_construction_status"] == "AMBIGUOUS"
        assert data["issues"] == ["helper: unsupported statement: Try"]
        with pytest.raises(ValueError):
            vote(trace, subject, "SAFE")
    else:
        assert data["command_construction_status"] == "SANITIZED"
        vote(trace, subject, "SAFE")


@pytest.mark.parametrize("call", [
    "subprocess.check_call(build_cmd(value), shell=True)",
    "subprocess.check_output(build_cmd(value), shell=True)",
    "subprocess.check_output(args=build_cmd(value), shell=True)",
    "subprocess.getoutput(build_cmd(value))",
    "subprocess.getoutput(cmd=build_cmd(value))",
    "subprocess.getstatusoutput(build_cmd(value))",
    "subprocess.getstatusoutput(cmd=build_cmd(value))",
    "os.popen(build_cmd(value))",
    "os.popen(cmd=build_cmd(value))",
    "os.system(command=build_cmd(value))",
])
@pytest.mark.parametrize("quoted", [False, True])
def test_extended_sinks_helper_inspection_and_vote(call, quoted):
    helper = 'def build_cmd(value):\n    return "echo " + ' + ("shlex.quote(value)" if quoted else "value") + "\n"
    data, trace, subject = inspect_and_trace(f"def entry(value):\n    {call}\n", helper)
    assert data["helpers"], "The command analysis must include the actual admitted helper"
    assert data["command_construction_status"] == ("SANITIZED" if quoted else "UNSANITIZED")
    assert len(data["sink_facts"]) == 1
    vote(trace, subject, "SAFE" if quoted else "VULNERABLE")


@pytest.mark.parametrize("api", ["subprocess.check_call", "subprocess.check_output"])
@pytest.mark.parametrize("shell, expected", [("False", "NOT_ESTABLISHED"), ("flag", "AMBIGUOUS")])
def test_extended_subprocess_sinks_respect_shell_mode(api, shell, expected):
    caller = f"def entry(value, flag):\n    {api}(['echo', build_cmd(value)], shell={shell})\n"
    data, trace, subject = inspect_and_trace(caller, "def build_cmd(value):\n    return value\n")
    assert data["command_construction_status"] == expected
    with pytest.raises(ValueError, match="inspect_command_construction"):
        vote(trace, subject, "VULNERABLE")
