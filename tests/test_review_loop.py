"""Behavioral tests found by the review-agent skill review loop."""
import json

import pytest

from test_review_state_and_scope import flow, observations
from test_review_followup import vote


@pytest.mark.parametrize("declaration", [
    "def unused(arg=1/0):\n            pass",
    "@missing_decorator\n        def unused():\n            pass",
    "def unused(arg: 1/0):\n            pass",
    "class Unused:\n            value = 1/0",
])
def test_definition_evaluation_errors_reach_handler(declaration):
    result = flow(f'''def entry(request):
    try:
        {declaration}
    except:
        eval(request.args['x'])
''')
    assert result["sinks"] and result["sinks"][0]["tainted"]


def test_unused_plain_function_body_does_not_execute_or_raise():
    result = flow('''def entry(request):
    try:
        def unused():
            eval(request.args['x'])
            raise RuntimeError()
    except:
        eval(request.args['x'])
''')
    assert not result["sinks"]


@pytest.mark.parametrize("iterable,expected", [("[]", None), ("[1]", False), ("[1,2]", True)])
def test_literal_loop_does_not_invent_extra_iterations(iterable, expected):
    result = flow(f'''def entry(request):
    value = '0'
    for _ in {iterable}:
        eval(value)
        value = request.args['x']
''')
    if expected is None:
        assert not result["sinks"]
    else:
        assert result["sinks"][0]["tainted"] is expected


@pytest.mark.parametrize("termination,expected", [("break", True), ("continue", True), ("return", None)])
def test_literal_loop_preserves_real_exit_kind(termination, expected):
    result = flow(f'''def entry(request):
    for _ in [1]:
        value = request.args['x']
        {termination}
    eval(value)
''')
    if expected is None:
        assert not result["sinks"]
    else:
        assert result["sinks"][0]["tainted"] is expected


def test_aliased_command_keeps_construction_counterevidence_despite_empty_scan():
    trace, subject = observations('''def entry(value):
    from os import system
    system('echo ' + shlex.quote(value))
''', "command-execution")
    trace = [s for s in trace if s.observation.tool in {"run_static_check", "inspect_command_construction"}]
    assert json.loads(trace[0].observation.content)["findings"] == []
    assert json.loads(trace[1].observation.content)["command_construction_status"] == "SANITIZED"
    with pytest.raises(ValueError, match="counter-evidence"):
        vote(trace, subject, "VULNERABLE")
    vote(trace, subject, "SAFE")


def test_qualified_numeric_helper_is_not_ambiguous_with_other_module(tmp_path):
    from cv_agent.code_adapters import load_code_repository
    from cv_agent.agents.scanner import StaticScanner
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.tools.identity import candidate_subject
    from cv_agent.tools.registry import ToolExecutionScope
    from cv_agent.tools.validation.models import PathInput
    from cv_agent.tools.validation.patterns import SANITIZER_RULES, pattern_tool
    from test_review_evidence_precedence import step

    (tmp_path / "entry.py").write_text(
        "from a import parse_number as parse_a\n"
        "from b import parse_number as parse_b\n"
        "def entry(value):\n"
        "    unused = parse_b('0')\n"
        "    return eval(parse_a(value))\n"
    )
    (tmp_path / "a.py").write_text("def parse_number(value):\n    return str(int(value))\n")
    (tmp_path / "b.py").write_text("def parse_number(value):\n    return value\n")
    repo = load_code_repository("r", tmp_path)
    caller = repo.locate("entry.py", 3).document
    helper = repo.locate("a.py", 1).document
    index = RepositoryIndex(repo.documents)
    candidate = next(c for c in StaticScanner().scan("r", [caller]) if c.metadata["rule"] == "dynamic-evaluation")
    subject = candidate_subject(index, candidate)
    scope = ToolExecutionScope(candidate_path=caller.path, subject=subject, admitted_paths=frozenset(d.path for d in repo.documents), max_observation_tokens=10000)
    observation = pattern_tool(index, "find_sanitizers", SANITIZER_RULES)(PathInput(path=helper.path), scope)
    assert json.loads(observation.content)["candidate_sanitizer_flows"]
    vote([step(observation, 1)], subject, "SAFE")


def test_unqualified_numeric_helper_remains_unresolved_with_two_definitions():
    from cv_agent.domain.types import CodeDocument
    from cv_agent.domain.evidence import ValidationSubject
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.tools.identity import repository_source_digest
    from cv_agent.tools.registry import ToolExecutionScope
    from cv_agent.tools.validation.models import PathInput
    from cv_agent.tools.validation.patterns import SANITIZER_RULES, pattern_tool
    from test_review_evidence_precedence import step

    caller = CodeDocument(repository_id="r", path="entry.py", language="python", text="def entry(value):\n    return eval(parse_number(value))\n", defines=("entry",), calls=("parse_number",))
    safe = CodeDocument(repository_id="r", path="a.py", language="python", text="def parse_number(value):\n    return str(int(value))\n", defines=("parse_number", "a.parse_number"))
    raw = CodeDocument(repository_id="r", path="b.py", language="python", text="def parse_number(value):\n    return value\n", defines=("parse_number", "b.parse_number"))
    index = RepositoryIndex([caller, safe, raw])
    subject = ValidationSubject(candidate_id="c", repository_id="r", entry_path=caller.path, entry_line=2, source_digest=repository_source_digest(index))
    scope = ToolExecutionScope(candidate_path=caller.path, subject=subject, admitted_paths=frozenset([caller.path, safe.path, raw.path]), max_observation_tokens=10000)
    observation = pattern_tool(index, "find_sanitizers", SANITIZER_RULES)(PathInput(path=safe.path), scope)
    assert json.loads(observation.content)["candidate_sanitizer_flows"] == []
    with pytest.raises(ValueError, match="affirmative counter-evidence"):
        vote([step(observation, 1)], subject, "SAFE")
