"""Regressions for suppressed exceptions and candidate-scoped command evidence."""
import json

import pytest

from test_review_state_and_scope import flow, observations
from test_review_followup import vote


def test_suppressed_exception_keeps_normal_continuation():
    result = flow('''def entry(request):
    value = request.args['x']
    try:
        with contextlib.suppress(ValueError):
            raise ValueError()
        eval(value)
    finally:
        pass
''')
    assert any(sink['tainted'] for sink in result['sinks'])


@pytest.mark.parametrize('exit_statement', ['return', 'break', 'continue'])
def test_context_manager_does_not_suppress_control_flow(exit_statement):
    result = flow(f'''def entry(request):
    for _ in [1]:
        with manager:
            {exit_statement}
        eval(request.args['x'])
''')
    assert not result['sinks']


@pytest.mark.parametrize('types', ['(missing_type, BaseException)', '(BaseException, missing_type)', '(42, BaseException)'])
def test_invalid_handler_tuple_preserves_exception_state(types):
    result = flow(f'''def entry(request):
    value = request.args['x']
    try:
        raise ValueError()
    except {types}:
        value = '0'
    finally:
        eval(value)
''')
    assert result['sinks'][0]['tainted']


def test_non_shell_code_execution_keeps_matching_taint_evidence():
    trace, subject = observations('''def entry(request):
    subprocess.run(['python', '-c', request.args['x']])
''', 'command-execution')
    assert json.loads(trace[-1].observation.content)['command_construction_status'] == 'NOT_ESTABLISHED'
    vote(trace, subject, 'VULNERABLE')


def test_command_safety_uses_candidate_sink_not_aggregate():
    trace, subject = observations('''def entry(value):
    os.system('echo ' + shlex.quote(value))
    os.system(value)
''', 'command-execution')
    assert json.loads(trace[-1].observation.content)['command_construction_status'] == 'UNSANITIZED'
    vote(trace, subject, 'SAFE')
    with pytest.raises(ValueError, match='counter-evidence'):
        vote(trace, subject, 'VULNERABLE')


def test_unknown_handler_before_catch_all_keeps_type_evaluation_error():
    result = flow('''def entry(request):
    value = request.args['x']
    try:
        raise ValueError()
    except missing_type:
        value = '0'
    except BaseException:
        value = '0'
    finally:
        eval(value)
''')
    assert result['sinks'][0]['tainted']


def test_exception_target_shadows_builtin_exception_type():
    result = flow('''def entry(request):
    try:
        raise ValueError()
    except ValueError as BaseException:
        pass
    value = request.args['x']
    try:
        raise ValueError()
    except BaseException:
        value = '0'
    finally:
        eval(value)
''')
    assert result['sinks'][0]['tainted']


@pytest.mark.parametrize('mutation', ['line', 'path', 'truncated'])
def test_unrelated_or_truncated_taint_cannot_override_command_gate(mutation):
    trace, subject = observations('''def entry(request):
    subprocess.run(['python', '-c', request.args['x']])
''', 'command-execution')
    observation = trace[1].observation
    content = json.loads(observation.content)
    metadata = dict(observation.metadata)
    if mutation == 'line':
        for entry in content['trace']:
            for sink in entry.get('sinks', []):
                sink['line'] += 10
    elif mutation == 'path':
        for entry in content['trace']:
            entry['path'] = 'other.py'
    else:
        metadata['observation_truncated'] = True
    trace[1] = trace[1].model_copy(update={'observation': observation.model_copy(update={'content': json.dumps(content), 'metadata': metadata})})
    with pytest.raises(ValueError, match='inspect_command_construction'):
        vote(trace, subject, 'VULNERABLE')


def test_sanitized_candidate_needs_no_unrelated_sanitizer_finding():
    trace, subject = observations('''def entry(value):
    os.system('echo ' + shlex.quote(value))
    os.system(value)
''', 'command-execution', path='entry.py::entry@40-43')
    trace = [step for step in trace if step.observation.tool == 'inspect_command_construction']
    vote(trace, subject, 'SAFE')
    with pytest.raises(ValueError, match='affirmative counter-evidence'):
        vote(trace, subject.model_copy(update={'entry_line': 42}), 'SAFE')
