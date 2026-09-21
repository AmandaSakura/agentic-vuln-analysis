import importlib
import sys
from pathlib import Path

import pytest




def test_jinja_reproduction_requires_prepared_environment(monkeypatch, tmp_path):
    mod = importlib.import_module('cv_agent.evaluation.runners.reproduce_jinja_attr_pair')
    monkeypatch.setattr(mod, "PYTHON_ENV_BIN", tmp_path / "bin/python")
    with pytest.raises(FileNotFoundError, match="Virtualenv"):
        mod.reproduce_pair(tmp_path / "out")


def test_jinja_real_pair_if_prepared(tmp_path):
    mod = importlib.import_module('cv_agent.evaluation.runners.reproduce_jinja_attr_pair')
    if not mod.PYTHON_ENV_BIN.exists() or not mod.VULN_CHECKOUT.exists() or not mod.FIXED_CHECKOUT.exists():
        pytest.skip("Jinja pair checkouts are not prepared")
    result = mod.reproduce_pair(tmp_path / "out")
    assert result["summary"]["verified_differential_security"] is True
