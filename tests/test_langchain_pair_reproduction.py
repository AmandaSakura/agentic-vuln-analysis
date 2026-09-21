import importlib.util
from pathlib import Path
import sys
import pytest

SCRIPTS_DIR = Path(__file__).parents[1] / "scripts"
spec = importlib.util.spec_from_file_location(
    "reproduce_langchain_template_pair",
    SCRIPTS_DIR / "reproduce_langchain_template_pair.py",
)
reproduce_mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = reproduce_mod
spec.loader.exec_module(reproduce_mod)

VULN_CHECKOUT = reproduce_mod.VULN_CHECKOUT
FIXED_CHECKOUT = reproduce_mod.FIXED_CHECKOUT
PYTHON_ENV_BIN = reproduce_mod.PYTHON_ENV_BIN
run_single_probe = reproduce_mod.run_single_probe
reproduce_pair = reproduce_mod.reproduce_pair


@pytest.mark.parametrize("failure", ["benign_output", "wrong_rejection"])
def test_pair_rejects_invalid_control_or_unrelated_value_error(tmp_path, monkeypatch, failure):
    vulnerable = tmp_path / "a"
    fixed = tmp_path / "b"
    vulnerable.mkdir()
    fixed.mkdir()
    monkeypatch.setattr(reproduce_mod, "VULN_CHECKOUT", vulnerable)
    monkeypatch.setattr(reproduce_mod, "FIXED_CHECKOUT", fixed)
    monkeypatch.setattr(reproduce_mod, "PYTHON_ENV_BIN", Path(sys.executable))
    monkeypatch.setattr(reproduce_mod, "get_git_commit",
                        lambda path: reproduce_mod.VULN_COMMIT if path == vulnerable else reproduce_mod.FIX_COMMIT)
    monkeypatch.setattr(reproduce_mod, "get_installed_packages", lambda path: {})
    monkeypatch.setattr(reproduce_mod, "require_clean_checkout", lambda path: None, raising=False)
    def probe(checkout, scenario):
        if scenario == "benign":
            parsed = dict(status="BENIGN_OK", success=failure != "benign_output",
                          output="WRONG" if failure == "benign_output" else "Hello World")
        elif checkout == vulnerable:
            parsed = dict(status="EXPLOITED", leaked_secret=True, leaked_dunder=True)
        else:
            parsed = dict(status="BLOCKED", error_type="ValueError",
                          error_message="unrelated failure" if failure == "wrong_rejection" else
                          f"Invalid variable name '{'marker.secret' if scenario == 'attribute_access' else 'marker.__class__.__name__'}' in f-string template")
        return dict(parsed=parsed, raw={})
    monkeypatch.setattr(reproduce_mod, "run_single_probe", probe)
    assert reproduce_pair(tmp_path / "result")["summary"]["verified_differential_security"] is False


def test_pair_requires_clean_checkout_before_running_probe(tmp_path, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(reproduce_mod.subprocess, 'run', lambda *args, **kwargs:
                        SimpleNamespace(stdout=' M libs/core/changed.py\n'))
    with pytest.raises(ValueError, match='clean checkout'):
        reproduce_mod.require_clean_checkout(tmp_path)


def test_child_probe_has_a_fixed_timeout(monkeypatch, tmp_path):
    import subprocess
    def timeout(command, **kwargs):
        assert kwargs['timeout'] == 30
        raise subprocess.TimeoutExpired(command, 30)
    monkeypatch.setattr(reproduce_mod.subprocess, 'run', timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        run_single_probe(tmp_path, 'benign')


@pytest.mark.skipif(
    not (PYTHON_ENV_BIN.exists() and VULN_CHECKOUT.is_dir() and FIXED_CHECKOUT.is_dir()),
    reason="Diagnostic langchain checkouts or python env missing",
)
def test_langchain_isolated_probe_differential_outcomes():
    # Benign control must succeed on both
    vuln_benign = run_single_probe(VULN_CHECKOUT, "benign")
    fixed_benign = run_single_probe(FIXED_CHECKOUT, "benign")
    assert vuln_benign["parsed"]["status"] == "BENIGN_OK"
    assert fixed_benign["parsed"]["status"] == "BENIGN_OK"

    # Attribute access: exploited on vulnerable, blocked on fixed
    vuln_attr = run_single_probe(VULN_CHECKOUT, "attribute_access")
    fixed_attr = run_single_probe(FIXED_CHECKOUT, "attribute_access")
    assert vuln_attr["parsed"]["status"] == "EXPLOITED"
    assert vuln_attr["parsed"]["leaked_secret"] is True
    assert fixed_attr["parsed"]["status"] == "BLOCKED"
    assert fixed_attr["parsed"]["error_type"] == "ValueError"

    # Dunder access: exploited on vulnerable, blocked on fixed
    vuln_dunder = run_single_probe(VULN_CHECKOUT, "dunder_access")
    fixed_dunder = run_single_probe(FIXED_CHECKOUT, "dunder_access")
    assert vuln_dunder["parsed"]["status"] == "EXPLOITED"
    assert vuln_dunder["parsed"]["leaked_dunder"] is True
    assert fixed_dunder["parsed"]["status"] == "BLOCKED"
    assert fixed_dunder["parsed"]["error_type"] == "ValueError"


@pytest.mark.skipif(
    not (PYTHON_ENV_BIN.exists() and VULN_CHECKOUT.is_dir() and FIXED_CHECKOUT.is_dir()),
    reason="Diagnostic langchain checkouts or python env missing",
)
def test_reproduce_pair_creates_valid_artifacts(tmp_path: Path):
    result = reproduce_pair(output_dir=tmp_path)
    assert result["summary"]["verified_differential_security"] is True
    assert result["summary"]["benign_control_preserved"] is True
    assert (tmp_path / "metadata.json").is_file()
    assert (tmp_path / "results.json").is_file()
    assert (tmp_path / "raw_subprocesses.json").is_file()
