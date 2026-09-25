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
    trace, subject = command_trace(f"def entry(value, flag):\n    {source}\n", inputs=("value",))
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
    ("run", ", input=request.args['code'], text=True", False),
    ("run", ", stdin=request.args['stream']", False),
    ("Popen", ", -1, None, request.args['stream']", False),
    ("run", "", True),
    ("run", ", input=None, stdin=None", True),
    ("Popen", ", -1, None, None", True),
    ("run", ", stdout=request.args['output']", True),
])
def test_numeric_argv_does_not_sanitize_executable_standard_input(callee, options, safe):
    trace, subject = command_trace(f'''def entry(request):
    subprocess.{callee}(['python', '-c', 'import sys; exec(sys.stdin.read())', str(int(request.args['n']))]{options})
''')
    if safe:
        assess(trace, subject, "SAFE")
    else:
        with pytest.raises(ValueError):
            assess(trace, subject, "SAFE")
    fact = json.loads(trace[-1].observation.content)["sink_facts"][0]
    assert bool(fact.get("numeric_argv")) is safe
