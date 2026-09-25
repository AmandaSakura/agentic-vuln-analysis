"""Independent proofs, shell counter-evidence, and linked helper sanitizers."""
import json

import pytest

from cv_agent.agents.react import validate_conclusion
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import ReActStep, ToolObservation, ValidationStatus
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.identity import repository_source_digest
from cv_agent.tools.validation.models import PathInput
from cv_agent.tools.validation.patterns import SANITIZER_RULES, pattern_tool
from test_review_state_and_scope import observations, flow
from test_review_followup import vote


def step(observation, i):
    observation = observation.model_copy(update={"citation_id": f"tool:extra:{i}"})
    return ReActStep(step=i, model_id="test", tool_call=ModelToolCall(call_id=f"call:{i}", name=observation.tool, arguments={}), observation=observation)


@pytest.mark.parametrize("label,status", [("VULNERABLE", ValidationStatus.CONFIRMED), ("SAFE", ValidationStatus.REFUTED)])
@pytest.mark.parametrize("proof", ["matching", "wrong-candidate", "wrong-source", "truncated", "uncited"])
def test_deterministic_proof_overrides_incomplete_command_analysis(label, status, proof):
    trace, subject = observations('''def entry(value):
    subprocess.run(['python', '-c', build_cmd(value)])
''', "command-execution")
    assert json.loads(trace[-1].observation.content)["command_construction_status"] == "NOT_ESTABLISHED"
    proof_subject = subject
    if proof == "wrong-candidate":
        proof_subject = subject.model_copy(update={"candidate_id": "other"})
    if proof == "wrong-source":
        proof_subject = subject.model_copy(update={"source_digest": "stale"})
    fixture = step(ToolObservation(tool="run_fixture", status="ok", content=json.dumps({"status": status}), validation_status=status, subject=proof_subject, metadata={"observation_truncated": proof == "truncated"}), 5)
    trace.append(fixture)
    ids = tuple(s.observation.citation_id for s in trace if proof != "uncited" or s is not fixture)
    conclusion = AgentExpertConclusion(expert="scan", label=label, confidence=0.9, rationale="Candidate-bound fixture result.", validation_status=status, evidence_ids=ids, supporting_observation_ids=ids)
    if proof == "matching":
        validate_conclusion(conclusion, trace, frozenset(ids), subject=subject)
    else:
        with pytest.raises(ValueError):
            validate_conclusion(conclusion, trace, frozenset(ids), subject=subject)


def test_sanitized_command_remains_counterevidence_without_static_check():
    trace, subject = observations('''def entry(value):
    os.system('echo ' + shlex.quote(value))
''', "command-execution")
    trace = [s for s in trace if s.observation.tool == "inspect_command_construction"]
    assert subject.entry_line == 2
    assert json.loads(trace[0].observation.content)["command_construction_status"] == "SANITIZED"
    with pytest.raises(ValueError, match="counter-evidence"):
        vote(trace, subject, "VULNERABLE")
    vote(trace, subject, "SAFE")


@pytest.mark.parametrize("statement", [
    "for a, b in [(1,)]:\n            pass",
    "value = {[]: 0}",
    "value = {[]}",
    "value = [*1]",
])
def test_implicit_iteration_and_container_failures_reach_handler(statement):
    result = flow(f'''def entry(request):
    try:
        {statement}
    except:
        eval(request.args['x'])
''')
    assert result["sinks"] and result["sinks"][0]["tainted"]


@pytest.mark.parametrize("statement", ["for a, b in [(1, 2)]:\n            pass", "value = {'key': 0}", "value = {(1, 2)}"])
def test_literal_container_and_unpack_controls_do_not_invent_errors(statement):
    result = flow(f'''def entry(request):
    try:
        {statement}
    except:
        eval(request.args['x'])
''')
    assert not result["sinks"]


@pytest.mark.parametrize("handler", ["BaseException", "(ValueError, BaseException)"])
@pytest.mark.parametrize("shadowed", [False, True])
def test_baseexception_consumes_errors_only_when_builtin(handler, shadowed):
    params = "request, BaseException" if shadowed else "request"
    result = flow(f'''def entry({params}):
    value = '0'
    try:
        value = request.args['x']
        raise RuntimeError()
    except {handler}:
        value = '0'
    finally:
        eval(value)
''')
    assert result["sinks"][0]["tainted"] is shadowed


@pytest.mark.parametrize("helper_body, caller_expr, linked, accept", [
    ("return str(int(value))", "parse_number(value)", True, True),
    ("int(value)\n    return value", "parse_number(value)", True, False),
    ("return str(int(value))", "value", True, False),
    ("return str(int(value))", "parse_number(value)", False, False),
    ("return str(int(value))", "parse_number(value) + value", True, False),
    ("int = replacement\n    return str(int(value))", "parse_number(value)", True, False),
])
def test_helper_sanitizer_requires_return_flow_into_candidate(helper_body, caller_expr, linked, accept):
    caller = CodeDocument(repository_id="r", path="entry.py", language="python", text=f"def entry(value):\n    eval({caller_expr})\n", defines=("entry",), calls=("parse_number",) if linked else ())
    helper = CodeDocument(repository_id="r", path="helper.py::parse_number@10-15", language="python", text=f"def parse_number(value):\n    {helper_body}\n", defines=("parse_number",))
    index = RepositoryIndex([caller, helper])
    from cv_agent.domain.evidence import ValidationSubject
    subject = ValidationSubject(candidate_id="c", repository_id="r", entry_path=caller.path, entry_line=2, source_digest=repository_source_digest(index), input_parameters=("value",))
    scope = ToolExecutionScope(candidate_path=caller.path, admitted_paths=frozenset([caller.path, helper.path]), subject=subject, max_observation_tokens=10000)
    observation = pattern_tool(index, "find_sanitizers", SANITIZER_RULES)(PathInput(path=helper.path), scope)
    assert json.loads(observation.content)["findings"]
    trace = [step(observation, 1)]
    if accept:
        vote(trace, subject, "SAFE")
        with pytest.raises(ValueError):
            vote(trace, subject.model_copy(update={"source_digest": "changed"}), "SAFE")
    else:
        with pytest.raises(ValueError, match="affirmative counter-evidence"):
            vote(trace, subject, "SAFE")


@pytest.mark.parametrize("statement", [
    "value = [0 for _ in 1]",
    "value = f'{1:invalid}'",
    "with 1:\n            pass",
])
def test_handler_is_not_pruned_for_unproven_expression_or_context_semantics(statement):
    result = flow(f'''def entry(request):
    try:
        {statement}
    except:
        eval(request.args['x'])
''')
    assert result["sinks"] and result["sinks"][0]["tainted"]
