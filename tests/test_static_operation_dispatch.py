"""V2 must distinguish nested arguments from additional registered operations."""
import json
import subprocess
import sys

import pytest


def review(tmp_path, text):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'entry.py').write_text(text)
    output = tmp_path / 'result'
    process = subprocess.run([sys.executable, '-m', 'cv_agent', 'review', str(source),
        '--output', str(output), '--profile', 'product_triage_v2'], capture_output=True, text=True)
    return process, json.loads((output / 'result.json').read_text())


@pytest.mark.parametrize('text', [
    'def inspect(value):\n    return eval(str(value))\n',
    'def inspect(value):\n    return eval(compile(value, "<owned>", "eval"))\n',
    'import subprocess\ndef inspect(item):\n    subprocess.run([str(item)], shell=False)\n',
    'import subprocess as sp\ndef inspect(item):\n    sp.run([str(item)], shell=False)\n',
    'from subprocess import run as launch\ndef inspect(item):\n    launch([str(item)], shell=False)\n',
])
def test_one_registered_operation_with_nested_arguments_is_attempted_without_claiming_proof(tmp_path, text):
    process, result = review(tmp_path, text)
    assert process.returncode == 0, process.stdout + process.stderr
    assert result['run_state'] == 'COMPLETED'
    assert result['counts']['candidate_total'] == result['counts']['analysis_completed'] == 1
    assert result['counts']['analysis_blocked'] == 0
    assert result['findings'][0]['property_state'] == 'UNKNOWN'
    assert result['accounting']['target_executions'] == result['accounting']['model_requests'] == 0


@pytest.mark.parametrize('text,count', [
    ('def inspect():\n    eval("1"); eval("2")\n', 2),
    ('def inspect():\n    eval(eval("1"))\n', 2),
    ('import os\ndef inspect():\n    os.system("true"); os.system("true")\n', 2),
    ('import os\ndef inspect():\n    os.system("true"); eval("1")\n', 2),
    ('from builtins import eval as evaluate\ndef inspect():\n    evaluate("1"); eval("2")\n', 2),
])
def test_multiple_registered_operations_on_same_line_stay_blocked(tmp_path, text, count):
    process, result = review(tmp_path, text)
    assert process.returncode == 2
    assert result['run_state'] == 'PARTIAL'
    assert result['counts']['analysis_blocked'] == result['counts']['candidate_total'] == count
    assert all(finding['property_state'] == 'UNKNOWN' for finding in result['findings'])
    assert result['accounting']['target_executions'] == result['accounting']['model_requests'] == 0


@pytest.mark.parametrize('mode,state', [('0o772', 'SUPPORTED'), ('0o750', 'REFUTED')])
def test_permission_positive_controls_remain_strong(tmp_path, mode, state):
    process, result = review(tmp_path, f'import os\ndef inspect(path):\n    os.chmod(path, {mode})\n')
    assert process.returncode == 0
    assert result['findings'][0]['property_state'] == state
    assert result['counts']['analysis_completed'] == 1
