import importlib
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def copy_config_tree(tmp_path):
    (tmp_path / "configs").mkdir()
    (tmp_path / "validation").mkdir()
    for name in ("python_pair_gate.json", "python_pair_matrix.json"):
        (tmp_path / "configs" / name).write_text((ROOT / "configs" / name).read_text())
    (tmp_path / "validation/python_pair_labels_v1.json").write_text(
        (ROOT / "validation/python_pair_labels_v1.json").read_text()
    )


def test_gate_attempt_updates_pointer_before_pytest(monkeypatch, tmp_path):
    copy_config_tree(tmp_path)
    mod = importlib.import_module("run_python_pair_gate")
    monkeypatch.setattr(mod, "require_passing_tests", lambda: (_ for _ in ()).throw(RuntimeError("blocked")))
    run_dir = tmp_path / "artifacts/python_pair_gate/new"
    with pytest.raises(RuntimeError, match="blocked"):
        mod.run(root=tmp_path, output=run_dir)
    pointer = json.loads((tmp_path / "artifacts/python_pair_gate.json").read_text())
    assert pointer == {"run_directory": "artifacts/python_pair_gate/new"}


def test_matrix_stops_before_model_calls_without_gate(monkeypatch, tmp_path):
    copy_config_tree(tmp_path)
    mod = importlib.import_module("run_python_pair_matrix")
    calls = []
    monkeypatch.setattr(mod, "run_candidate", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError, match="gate"):
        mod.run(root=tmp_path, output=tmp_path / "artifacts/python_pair_matrix/new")
    assert calls == []
