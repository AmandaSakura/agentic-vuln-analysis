"""Guard ownership boundaries so implementation does not drift back into facades."""
import ast
import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT/'src/cv_agent'


def _module(path):
    parts = path.relative_to(ROOT/'src').with_suffix('').parts
    return '.'.join(parts[:-1] if parts[-1] == '__init__' else parts)


def test_implementations_do_not_depend_on_script_modules():
    sources = {path: ast.parse(path.read_text()) for path in PACKAGE.rglob('*.py')}
    violations = []
    for path, tree in sources.items():
        module = _module(path)
        package = module if path.name == '__init__.py' else module.rsplit('.', 1)[0]
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                target = importlib.util.resolve_name('.'*node.level + (node.module or ''), package) if node.level else node.module
                if target == 'scripts' or (target and target.startswith(('scripts.', 'run_', 'prepare_', 'reproduce_'))):
                    violations.append((module, node.lineno, target))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == 'scripts' or alias.name.startswith(('scripts.', 'run_')):
                        violations.append((module, node.lineno, alias.name))
    assert violations == []


def test_public_root_exports_are_the_canonical_objects():
    import cv_agent

    expected = {
        'AgentPipeline': 'baselines.workflow', 'PipelineConfig': 'baselines.workflow',
        'Candidate': 'domain.types', 'CodeDocument': 'domain.types',
        'SystemVersion': 'domain.types', 'Verdict': 'domain.types',
        'QuorumPolicy': 'agents.voting', 'SingleExpertPolicy': 'agents.voting',
        'RepositoryIndex': 'retrieval',
    }
    assert set(cv_agent.__all__) == set(expected)
    for name, module in expected.items():
        assert getattr(cv_agent, name) is getattr(importlib.import_module('cv_agent.' + module), name)
    with pytest.raises(AttributeError):
        getattr(cv_agent, 'nonexistent_api')
