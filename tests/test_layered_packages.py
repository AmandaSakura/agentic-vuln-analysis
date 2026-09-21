"""Package moves preserve observable parsing and original public object identities."""
import dataclasses
import importlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

PYTHON = '''from service import run\nimport external.client\n\ndef entry(request):\n    external.client.run(request)\n    return run(request)\n\ndef run(value):\n    return value\n'''
JAVA = '''package demo;\nimport java.sql.Statement;\nclass Handler {\n  public void handle(Statement stmt, String input) throws Exception {\n    stmt.executeQuery(input);\n  }\n}\n'''


def simplify(value):
    if hasattr(value, 'model_dump'):
        return value.model_dump(mode='json')
    if dataclasses.is_dataclass(value):
        return {f.name: simplify(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, (list, tuple)):
        return [simplify(v) for v in value]
    return value


def test_parser_coordinates_and_qualified_symbols_match_original():
    from cv_agent.code_adapters.python import parse_python_source
    from cv_agent.code_adapters.java import parse_java_source
    expected = json.loads((Path(__file__).parent / 'fixtures/parser_baseline.json').read_text())
    assert simplify(parse_python_source('repo', 'src/backend/base/api.py', PYTHON, module_path='api.py')) == expected['python']
    assert simplify(parse_java_source('repo', 'demo/Handler.java', JAVA)) == expected['java']


@pytest.mark.parametrize('module,name', [
    ('domain.types', 'Candidate'),
    ('agents.workflow', 'AgenticPipeline'),
    ('agents.react', 'ReActEngine'),
    ('code_adapters.python', 'parse_python_source'),
    ('code_adapters.java', 'parse_java_source'),
    ('baselines.workflow', 'AgentPipeline'),
    ('runtime.model', 'OpenAICompatibleChatModel'),
    ('evaluation.metrics', 'metrics'),
])
def test_implementations_have_one_canonical_owner(module, name):
    owner = importlib.import_module('cv_agent.' + module)
    assert getattr(owner, name).__module__ == owner.__name__


def test_agent_imports_do_not_load_deterministic_baseline(tmp_path):
    code = '''
import sys
import cv_agent.agents.workflow
import cv_agent.evaluation.datasets.owasp_live
assert not any(name.startswith('cv_agent.baselines') for name in sys.modules)
from cv_agent import Candidate, AgentPipeline
assert Candidate.__module__ == 'cv_agent.domain.types'
assert AgentPipeline.__module__ == 'cv_agent.baselines.workflow'
'''
    subprocess.run([sys.executable, '-c', code], cwd=tmp_path, check=True)


def test_live_admission_fingerprints_the_checkout_after_relocation():
    from cv_agent.runtime import admission
    root = Path(__file__).resolve().parents[1]
    assert admission.PROJECT_ROOT == root
    relative = {path.relative_to(root).as_posix() for path in admission.fingerprint_files(root)}
    assert 'src/cv_agent/agents/workflow.py' in relative
    assert 'src/cv_agent/tools/analysis/commands.py' in relative
    assert 'tests/test_layered_packages.py' in relative


def test_canonical_quorum_module_preserves_full_and_fast_behavior(tmp_path):
    result = subprocess.run([sys.executable, '-m', 'cv_agent.evaluation.quorum_probe'],
                            cwd=tmp_path, check=True, capture_output=True, text=True)
    payload = json.loads(result.stdout)
    assert payload['claim_eligible'] is False
    assert payload['dataset_role'] == 'development'
    assert {(row['case'], row['system']): (row['verdict']['label'], row['verdict']['path'])
            for row in payload['results']} == {
        ('C01', 'E4'): ('VULNERABLE', 'slow'),
        ('C01', 'E5'): ('VULNERABLE', 'fast'),
        ('C02', 'E4'): ('ABSTAIN', 'slow'),
        ('C02', 'E5'): ('ABSTAIN', 'slow'),
    }
