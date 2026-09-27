"""Command evidence must preserve unsafe witnesses and account for process input."""
import json

import pytest

from test_review_exit_and_evidence import assess, command_trace


@pytest.mark.parametrize("source", [
    "os.system(value); subprocess.run('echo ok', shell=flag)",
    "subprocess.run('echo ok', shell=flag); os.system(value)",
    "os.system(value if flag else 'echo $HOME')",
    "os.system('echo $HOME' if flag else value)",
])
def test_unsafe_command_witness_survives_other_ambiguous_paths(source):
    trace, subject = command_trace(f"def entry(value, flag):\n    {source}\n", inputs=("value", "flag"))
    assess(trace, subject, "VULNERABLE")
    with pytest.raises(ValueError):
        assess(trace, subject, "SAFE")


@pytest.mark.parametrize("source", [
    "os.system('echo $HOME')",
    "os.system('echo ok' if flag else 'echo $HOME')",
    "os.system('echo ok'); subprocess.run('echo ok', shell=flag)",
])
def test_ambiguity_without_an_unsafe_witness_supports_neither_label(source):
    trace, subject = command_trace(f"def entry(flag):\n    {source}\n")
    for label in ("SAFE", "VULNERABLE"):
        with pytest.raises(ValueError):
            assess(trace, subject, label)


@pytest.mark.parametrize("callee,options,safe", [
    ("run", ", input=code, text=True", False),
    ("run", ", stdin=stream", False),
    ("Popen", ", -1, None, stream", False),
    ("run", "", True),
    ("run", ", input=None, stdin=None", True),
    ("Popen", ", -1, None, None", True),
    ("run", ", stdout=output", True),
])
def test_numeric_argv_does_not_sanitize_executable_standard_input(callee, options, safe):
    # C1/C3: test process-input semantics independently of unmodeled getters.
    trace, subject = command_trace(f'''def entry(value, code, stream, output):
    subprocess.{callee}(['python', '-c', 'import sys; exec(sys.stdin.read())', str(int(value))]{options})
''', inputs=("value", "code", "stream", "output"))
    if safe:
        assess(trace, subject, "SAFE")
    else:
        with pytest.raises(ValueError):
            assess(trace, subject, "SAFE")
    fact = json.loads(trace[-1].observation.content)["sink_facts"][0]
    assert bool(fact.get("numeric_argv")) is safe


@pytest.mark.parametrize('module', ['posixpath', 'ntpath'])
@pytest.mark.parametrize('operation', ['basename', 'dirname', 'normpath'])
@pytest.mark.parametrize('quoted', [False, True])
def test_lexical_path_conversion_reaches_real_command_admission(module, operation, quoted):
    expression = f'{module}.{operation}(value)'
    if quoted:
        expression = f'shlex.quote({expression})'
    trace, subject = command_trace(
        f'def entry(value):\n    import {module}\n    import shlex\n'
        f'    os.system("echo " + {expression})\n', inputs=('value',))
    # String-type summaries permit a later quote to establish protection.
    # They do not establish that a chosen attack string survives the transform.
    if quoted:
        assess(trace, subject, 'SAFE')
    else:
        with pytest.raises(ValueError):
            assess(trace, subject, 'SAFE')
    with pytest.raises(ValueError):
        assess(trace, subject, 'VULNERABLE')


def test_absolute_path_join_discards_earlier_untrusted_component():
    trace, subject = command_trace('def entry(value):\n    import posixpath\n'
        '    os.system("echo " + posixpath.join(value, "/fixed"))\n', inputs=('value',))
    assess(trace, subject, 'SAFE')
    with pytest.raises(ValueError):
        assess(trace, subject, 'VULNERABLE')


@pytest.mark.parametrize('expression', ['posixpath.basename(obj)', 'os.path.basename(value)'])
def test_path_summary_does_not_assume_pathlike_hooks_or_target_platform(expression):
    trace, subject = command_trace('def entry(value, obj):\n    import posixpath\n'
        f'    os.system("echo " + shlex.quote({expression}))\n', inputs=('value',))
    for label in ('SAFE', 'VULNERABLE'):
        with pytest.raises(ValueError):
            assess(trace, subject, label)


@pytest.mark.parametrize('statement', [
    'command = posixpath.basename(shlex.quote(value))',
    'posixpath = obj\n    command = shlex.quote(posixpath.basename(value))',
])
def test_path_transform_cannot_reuse_earlier_quote_or_shadowed_module(statement):
    trace, subject = command_trace('def entry(value, obj):\n    import posixpath\n'
        f'    {statement}\n    os.system("echo " + command)\n', inputs=('value',))
    for label in ('SAFE', 'VULNERABLE'):
        with pytest.raises(ValueError):
            assess(trace, subject, label)


@pytest.mark.parametrize('condition', ['os.path.exists(value)', 'not os.path.exists(value)'])
def test_filesystem_predicate_all_safe_paths_support_safety(condition):
    trace, subject = command_trace(f'''def entry(value):
    if {condition}:
        command = "echo " + shlex.quote(value)
    else:
        command = "echo absent"
    os.system(command)
''', inputs=('value',))
    assess(trace, subject, 'SAFE')
    with pytest.raises(ValueError):
        assess(trace, subject, 'VULNERABLE')


def test_filesystem_predicate_does_not_invent_a_dangerous_path_witness():
    trace, subject = command_trace('''def entry(value):
    if os.path.exists(value):
        os.system(value)
    else:
        os.system("echo absent")
''', inputs=('value',))
    for label in ('SAFE', 'VULNERABLE'):
        with pytest.raises(ValueError):
            assess(trace, subject, label)
    facts = json.loads(trace[-1].observation.content)['sink_facts']
    assert facts and any(f.get('environment_requirements') for f in facts)


def test_distinct_filesystem_reads_are_not_assumed_stable():
    trace, subject = command_trace('''def entry(value):
    command = shlex.quote(value)
    if os.path.exists(value):
        command = value
    if os.path.exists(value):
        command = shlex.quote(value)
    os.system("echo " + command)
''', inputs=('value',))
    for label in ('SAFE', 'VULNERABLE'):
        with pytest.raises(ValueError):
            assess(trace, subject, label)
    facts = json.loads(trace[-1].observation.content)['sink_facts']
    assert len(facts) == 4


def test_saved_filesystem_result_keeps_its_boolean_identity():
    trace, subject = command_trace('''def entry(value):
    found = os.path.exists(value)
    command = shlex.quote(value)
    if found:
        command = value
    if found:
        command = shlex.quote(value)
    os.system("echo " + command)
''', inputs=('value',))
    assess(trace, subject, 'SAFE')
    assert len(json.loads(trace[-1].observation.content)['sink_facts']) == 2


def test_independent_danger_is_not_erased_by_later_filesystem_condition():
    trace, subject = command_trace('''def entry(value):
    os.system(value)
    if os.path.exists(value):
        os.system("echo " + shlex.quote(value))
''', inputs=('value',))
    assess(trace, subject, 'VULNERABLE')
    with pytest.raises(ValueError):
        assess(trace, subject, 'SAFE')


def test_filesystem_summary_rejects_untyped_pathlike_argument():
    trace, subject = command_trace('''def entry(value, obj):
    if os.path.exists(obj):
        os.system("echo " + shlex.quote(value))
''', inputs=('value',))
    for label in ('SAFE', 'VULNERABLE'):
        with pytest.raises(ValueError):
            assess(trace, subject, label)
    assert 'builtin string path' in json.loads(trace[-1].observation.content)['issues'][0]
