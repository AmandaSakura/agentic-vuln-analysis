import json
from types import SimpleNamespace

import pytest

from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.domain.chat import ModelToolCall
from cv_agent.code_adapters.python import parse_python_source
from cv_agent.tools.validation import full_agent_tools
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


def test_candidate_bound_probe_cannot_bypass_entry_guards_via_retrieved_helper():
    files={
        'entry.py': "from service import helper\n\ndef entry(request):\n    if False:\n        return helper(request)\n    return 0\n",
        'service.py': "def helper(request):\n    return eval(request.args['x'])\n",
    }
    docs=[span.document for path,source in files.items() for span in parse_python_source('test',path,source)]
    entry=next(doc for doc in docs if doc.path.startswith('entry.py::entry@'))
    helper=next(doc for doc in docs if doc.path.startswith('service.py::helper@'))
    registry=ToolRegistry(full_agent_tools(RepositoryIndex(docs)),max_output_bytes=100000)
    scope=ToolExecutionScope(frozenset(doc.path for doc in docs),8192,candidate_path=entry.path)
    def invoke(path):
        return registry.invoke(ModelToolCall(call_id='probe',name='probe_python_eval',
            arguments={'source_path':path}),allowed=['probe_python_eval'],scope=scope)
    bypass=invoke(helper.path)
    assert bypass.status=='blocked'
    assert bypass.validation_status is None
    actual=invoke(entry.path)
    assert actual.validation_status.value=='UNRESOLVED'
    assert 'no witness' in actual.content


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


@pytest.mark.parametrize("tail", ["yield 1", "yield from ()", "if False:\n        yield 1"])
def test_calling_generator_does_not_execute_its_body(tail):
    source = "def entry(request):\n    eval(request.args['x'])\n    " + tail + "\n"
    _, result = probe({"entry.py": source})
    observed = []
    namespace = {"eval": lambda value: observed.append(value)}
    exec(source, namespace)  # Fixed project-owned fixture, never repository code.
    namespace["entry"](SimpleNamespace(args={"x": "1 + 1"}))
    assert observed == []
    assert result["status"] == "UNRESOLVED"


def test_unconsumed_helper_generator_does_not_produce_witness():
    _, result = probe({
        "entry.py": "from service import calculate\n\ndef entry(request):\n    return calculate(request.args['x'])\n",
        "service.py": "def calculate(value):\n    eval(value)\n    yield 1\n",
    })
    assert result["status"] == "UNRESOLVED"


def test_generator_argument_is_evaluated_before_generator_is_created():
    _, result = probe({
        "entry.py": "from service import calculate\n\ndef entry(request):\n    return calculate(eval(request.args['x']))\n",
        "service.py": "def calculate(value):\n    yield value\n",
    })
    assert result["status"] == "CONFIRMED"


def test_unreachable_nested_generator_does_not_make_outer_function_lazy():
    _, result = probe({"entry.py": "def entry(request):\n    eval(request.args['x'])\n    def nested():\n        yield 1\n"})
    assert result["status"] == "CONFIRMED"


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


def _bound_probe(source, *, property_id='dynamic-evaluation', line=1, booleans=None, inputs=('request',)):
    from cv_agent.domain.evidence import ValidationSubject
    from cv_agent.domain.types import CodeDocument
    from cv_agent.tools.identity import repository_source_digest
    from cv_agent.tools.validation.probes import concrete_eval_probe
    from cv_agent.tools.validation.models import SourceFlowInput

    docs = [span.document for span in parse_python_source('r', 'entry.py', source)]
    doc = next(doc for doc in docs if 'entry' in doc.defines and '::entry@' in doc.path)
    index = RepositoryIndex(docs)
    subject = ValidationSubject(candidate_id='c', repository_id='r', entry_path=doc.path,
                                entry_line=line, source_digest=repository_source_digest(index),
                                property_id=property_id, input_parameters=inputs, entry_boolean_arguments=booleans or {})
    scope = ToolExecutionScope(frozenset(item.path for item in docs), 8192, candidate_path=doc.path, subject=subject)
    return concrete_eval_probe(index, SourceFlowInput(source_path=doc.path), scope), subject


@pytest.mark.parametrize('property_id,line', [(None, 1), ('command-execution', 1), ('dynamic-evaluation', 4)])
def test_eval_witness_cannot_prove_another_property_or_call(property_id, line):
    observation, subject = _bound_probe(
        "def entry(request):\n    eval(request.args['x'])\n    if False:\n        os.system('echo ok')\n",
        property_id=property_id, line=line,
    )
    assert observation.validation_status.value == 'CONFIRMED'  # preserve the actual local witness
    assert observation.subject is None
    from cv_agent.agents.evidence_policy import validate_conclusion
    from cv_agent.domain.evidence import ReActStep
    from cv_agent.domain.review import AgentExpertConclusion
    observation = observation.model_copy(update={'citation_id': 'probe'})
    step = ReActStep(step=1, model_id='offline', observation=observation,
                    tool_call=ModelToolCall(call_id='probe', name=observation.tool, arguments={}))
    for status in ('CONFIRMED', 'UNRESOLVED'):
        with pytest.raises(ValueError):
            validate_conclusion(AgentExpertConclusion(
                expert='scan', label='VULNERABLE', validation_status=status, confidence=.9,
                evidence_ids=('probe',), supporting_observation_ids=('probe',), rationale='Local witness only.',
            ), [step], frozenset(), subject=subject)


@pytest.mark.parametrize('enabled,expected', [(False, 'UNRESOLVED'), (True, 'CONFIRMED')])
def test_eval_witness_honors_candidate_boolean_scenario(enabled, expected):
    observation, subject = _bound_probe(
        "def entry(request, enabled=True):\n    if enabled:\n        eval(request.args['x'])\n",
        booleans={'enabled': enabled},
    )
    assert observation.validation_status.value == expected
    assert observation.subject == subject


@pytest.mark.parametrize('offset', [0, 39])
@pytest.mark.parametrize('line', [1, 2])
def test_eval_witness_remains_candidate_bound_for_its_actual_scope(line, offset):
    observation, subject = _bound_probe('# padding\n' * offset + "def entry(request):\n    eval(request.args['x'])\n", line=line + offset)
    assert observation.validation_status.value == 'CONFIRMED'
    assert observation.subject == subject


@pytest.mark.parametrize('line', [0, 200])
def test_eval_probe_rejects_candidate_outside_indexed_slice(line):
    # A global line preceding a slice and a line beyond its end both reject.
    observation, _ = _bound_probe('# prefix\n' + "def entry(request):\n    eval(request.args['x'])\n",
                                  line=line + 1)
    assert observation.status == 'blocked'


@pytest.mark.parametrize('inputs,expected', [
    (('request',), 'CONFIRMED'),
    (('other',), 'UNRESOLVED'),
    ((), 'UNRESOLVED'),
    (('missing',), 'UNRESOLVED'),
    (('request', 'missing'), 'UNRESOLVED'),
])
@pytest.mark.parametrize('via_helper', [False, True])
def test_eval_candidate_witness_requires_its_declared_input_source(inputs, expected, via_helper):
    helper = "def identity(value):\n    return value\n\n" if via_helper else ''
    argument = "identity(request.args['x'])" if via_helper else "request.args['x']"
    observation, subject = _bound_probe(
        helper + f"def entry(request, other=False):\n    return eval({argument})\n",
        line=4 if via_helper else 1, inputs=inputs,
    )
    assert observation.validation_status.value == expected, observation.content
    from cv_agent.agents.evidence_policy import validate_conclusion
    from cv_agent.domain.evidence import ReActStep
    from cv_agent.domain.review import AgentExpertConclusion
    observation = observation.model_copy(update={'citation_id': 'probe'})
    step = ReActStep(step=1, model_id='offline', observation=observation,
                    tool_call=ModelToolCall(call_id='probe', name=observation.tool, arguments={}))
    conclusion = AgentExpertConclusion(
        expert='scan', label='VULNERABLE', validation_status='CONFIRMED', confidence=.9,
        evidence_ids=('probe',), supporting_observation_ids=('probe',), rationale='Input witness.',
    )
    if expected == 'CONFIRMED':
        validate_conclusion(conclusion, [step], frozenset(), subject=subject)
    else:
        with pytest.raises(ValueError):
            validate_conclusion(conclusion, [step], frozenset(), subject=subject)


@pytest.mark.parametrize('name', ['request', 'req'])
@pytest.mark.parametrize('body,booleans,expected', [
    ("return eval(INPUT.args['x'])", {}, 'CONFIRMED'),
    ("value = INPUT.args['x']\n    value = '1 + 1'\n    return eval(value)", {}, 'UNRESOLVED'),
    ("if enabled:\n        return eval(INPUT.args['x'])", {'enabled': False}, 'UNRESOLVED'),
    ("if enabled:\n        return eval(INPUT.args['x'])", {'enabled': True}, 'CONFIRMED'),
])
def test_eval_declared_source_still_requires_actual_flow_and_scenario(name, body, booleans, expected):
    observation, subject = _bound_probe(
        f'def entry({name}, enabled=True):\n    ' + body.replace('INPUT', name) + '\n',
        inputs=(name,), booleans=booleans,
    )
    assert observation.validation_status.value == expected, observation.content
    result = json.loads(observation.content)
    assert result['input_parameters'] == [name]
    assert result['entry_boolean_arguments'] == booleans
    assert observation.subject == subject
