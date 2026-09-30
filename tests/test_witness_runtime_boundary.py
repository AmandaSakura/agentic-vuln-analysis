"""Core witness imports never depend on the experiment/evaluation package."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest


SOURCE = Path(__file__).resolve().parents[1] / "src/cv_agent"
CORE = ("agents", "tools", "runtime")
RETIRED = (
    "bounded_execution_witness.py", "witness_contract.py", "witness_values.py",
    "witness_branches.py", "witness_preexec.py", "witness_scenario_runtime.py",
    "isolation_read_policy.py", "process_resource_accounting.py",
    "isolation_read_diagnostics.py",
)


def _evaluation_imports(source: str) -> list[tuple[int, str]]:
    violations = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "cv_agent.evaluation" or alias.name.startswith("cv_agent.evaluation."):
                    violations.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if (module == "cv_agent.evaluation" or module.startswith("cv_agent.evaluation.")
                    or node.level and (module == "evaluation" or module.startswith("evaluation."))):
                violations.append((node.lineno, module))
            elif module == "cv_agent":
                for alias in node.names:
                    if alias.name == "evaluation":
                        violations.append((node.lineno, "cv_agent.evaluation"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if "cv_agent.evaluation" in node.value or "evaluation.diagnostics" in node.value:
                violations.append((node.lineno, node.value))
    return violations


def test_core_agent_tools_runtime_have_no_evaluation_imports_or_dynamic_paths():
    failures = {}
    for package in CORE:
        for path in sorted((SOURCE / package).rglob("*.py")):
            violations = _evaluation_imports(path.read_text())
            if violations:
                failures[str(path.relative_to(SOURCE))] = violations
    assert failures == {}
    for retired in RETIRED:
        assert not (SOURCE / "evaluation/diagnostics" / retired).exists()


@pytest.mark.parametrize("source", (
    "import cv_agent.evaluation.diagnostics.tracer\n",
    "def nested():\n    from cv_agent.evaluation.diagnostics import old\n",
    "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from cv_agent.evaluation import old\n",
    "import importlib\nimportlib.import_module('cv_agent.evaluation.diagnostics.old')\n",
    "from ..evaluation.diagnostics import old\n",
))
def test_boundary_scan_detects_nested_type_checking_relative_and_dynamic_imports(source):
    assert _evaluation_imports(source)
