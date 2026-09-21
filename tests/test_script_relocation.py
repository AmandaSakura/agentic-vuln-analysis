"""Stable launch commands with import-safe, directly testable package implementations."""
import ast
import importlib
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).parents[1]
WORKERS = {"jinja_attr_probe", "langchain_template_probe"}


def test_implementations_import_without_loading_experiment_settings(tmp_path):
    code = """
import importlib
from pathlib import Path
import os
import sys
root = Path(sys.argv[1])
sys.path.insert(0, str(root / 'src'))
original_read = Path.read_text
original_getitem = os._Environ.__getitem__
def guarded_read(path, *args, **kwargs):
    if 'configs' in path.parts or path.name.startswith('.env'):
        raise AssertionError('import loaded experiment settings: ' + str(path))
    return original_read(path, *args, **kwargs)
def guarded_getitem(environment, name):
    if any(word in name.upper() for word in ('API_KEY', 'TOKEN', 'SECRET', 'CREDENTIAL')):
        raise AssertionError('import accessed credentials: ' + name)
    return original_getitem(environment, name)
Path.read_text = guarded_read
os._Environ.__getitem__ = guarded_getitem
before = list(sys.path)
implementations = sorted((root / 'src/cv_agent/evaluation').glob('*/*.py'))
modules = [path for path in implementations if path.parent.name in {'runners', 'preparation', 'diagnostics'}
           and path.name != '__init__.py']
assert len(modules) == 47
for path in modules:
    importlib.import_module('.'.join(path.relative_to(root / 'src').with_suffix('').parts))
assert sys.path == before
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(ROOT)], cwd=tmp_path,
        env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1"},
        text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("group, stem, function, expected", [
    ("runners", "run_development_benchmark", "run", [((), {"pilot": False})]),
    ("runners", "run_development_pilot", "run", [((), {"pilot": True})]),
    ("runners", "run_development_fast_check", "run", [((), {"pilot": True, "fast_check": True})]),
    ("runners", "run_development_graph_check", "run", [((), {"pilot": True, "graph_check": True})]),
    ("runners", "run_development_lexical_check", "run", [((), {"pilot": True, "lexical_check": True})]),
    ("runners", "run_development_positive_check", "run", [((), {"pilot": True, "positive_check": True})]),
    ("runners", "run_real_source_smoke_native", "main", [(("configs/experiments/real_source_smoke_native.json",), {})]),
    ("runners", "run_python_heldout_pair_gate", "run", [((), {})]),
    ("runners", "run_python_heldout_pair_matrix", "run", [((), {})]),
    ("runners", "run_python_heldout_pilot", "run", [((ROOT / "configs/experiments/python_heldout_pilot.json",), {})]),
    ("runners", "run_python_repository_pilot", "run", [((ROOT / "configs/experiments/python_repository_pilot.json",), {})]),
    ("diagnostics", "audit_python_discovery", "audit", [
        ((ROOT / "configs/experiments/python_repository_pilot.json",), {}),
        ((ROOT / "configs/experiments/python_nltk_development_pilot.json",), {}),
    ]),
    ("diagnostics", "review_ten_trial_results", "run", [((), {})]),
])
def test_package_main_guards_preserve_original_arguments(group, stem, function, expected, monkeypatch):
    implementation = importlib.import_module(f"cv_agent.evaluation.{group}.{stem}")
    calls = []
    monkeypatch.setattr(implementation, function, lambda *args, **kwargs: calls.append((args, kwargs)))

    path = Path(implementation.__file__)
    tree = ast.parse(path.read_text())
    guard = next(node for node in tree.body if isinstance(node, ast.If)
                 and isinstance(node.test, ast.Compare)
                 and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__")
    namespace = {**vars(implementation), "__name__": "__main__"}
    exec(compile(ast.Module(body=[guard], type_ignores=[]), str(path), "exec"), namespace)

    assert calls == expected


def test_micro_default_configuration_is_loaded_only_on_request(tmp_path, monkeypatch):
    from cv_agent.evaluation.runners import run_micro_benchmark as micro
    from cv_agent.evaluation.runners import run_development_benchmark as development

    (tmp_path / "configs/models").mkdir(parents=True)
    model_path = tmp_path / "configs/models/micro_benchmark.json"
    model_path.write_text('{"model": "first-offline"}')
    assert micro.load_default_model_config(tmp_path) == {"model": "first-offline"}
    model_path.write_text('{"model": "second-offline"}')
    monkeypatch.setattr(development, "project_root", tmp_path)
    observed = []
    monkeypatch.setattr(development, "_run_candidate", lambda *args, **kwargs: observed.append(kwargs))

    development.run_candidate(None, None, None, None, None)
    development.run_candidate(None, None, None, None, None, model_config={"model": "explicit"})

    assert [item["model_config"] for item in observed] == [
        {"model": "second-offline"}, {"model": "explicit"},
    ]


def test_only_isolated_subject_workers_keep_script_implementations():
    paths = sorted((ROOT / "scripts").rglob("*.py"))
    assert {path.stem for path in paths} == WORKERS
    for path in paths:
        tree = ast.parse(path.read_text())
        assert any(isinstance(node, ast.FunctionDef) for node in tree.body)
        assert all(not (isinstance(node, ast.ImportFrom) and (node.module or "").startswith("cv_agent"))
                   for node in ast.walk(tree))


def test_reproduction_workers_remain_standalone_files():
    from cv_agent.evaluation.runners import reproduce_jinja_attr_pair as jinja
    from cv_agent.evaluation.runners import reproduce_langchain_template_pair as langchain

    assert jinja.PROBE_SCRIPT == ROOT / "scripts/probes/jinja_attr_probe.py"
    assert langchain.PROBE_SCRIPT == ROOT / "scripts/probes/langchain_template_probe.py"
    assert jinja.PROBE_SCRIPT.is_file() and langchain.PROBE_SCRIPT.is_file()


def test_shell_commands_have_valid_syntax():
    paths = sorted((ROOT/'scripts').glob('*.sh'))
    assert {path.name for path in paths} == {
        'heldout_gate.sh', 'heldout_matrix.sh', 'deepseek.sh', 'fetch_benchmarks.sh',
    }
    for path in paths:
        shell = '/bin/sh' if path.read_text().startswith('#!/bin/sh') else '/bin/bash'
        subprocess.run([shell, '-n', str(path)], check=True)


def test_advisory_entrypoints_have_no_obsolete_compatibility_imports():
    for name in ('gate', 'matrix'):
        path = ROOT/f'src/cv_agent/evaluation/runners/run_python_heldout_pair_{name}.py'
        tree = ast.parse(path.read_text())
        loaded = {node.id for node in ast.walk(tree)
                  if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module != '__future__':
                assert {alias.asname or alias.name for alias in node.names} <= loaded, path
            elif isinstance(node, ast.Import):
                assert {alias.asname or alias.name.split('.')[0] for alias in node.names} <= loaded, path
        assert {node.name for node in tree.body if isinstance(node, ast.FunctionDef)} == {'load_config', 'run'}
