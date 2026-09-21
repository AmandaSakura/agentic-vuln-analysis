import json
from pathlib import Path

import pytest

from cv_agent.python_pair_config import PythonPairExperimentConfig, PythonPairLabels


ROOT = Path(__file__).parents[1]


def test_pair_configs_are_fixed_size_and_labels_are_evaluator_only():
    gate = PythonPairExperimentConfig.model_validate_json(
        (ROOT / "configs/python_pair_gate.json").read_text()
    )
    matrix = PythonPairExperimentConfig.model_validate_json(
        (ROOT / "configs/python_pair_matrix.json").read_text()
    )
    labels = PythonPairLabels.model_validate_json(
        (ROOT / gate.label_file).read_text()
    )
    assert gate.dataset_role == "paired_development_gate"
    assert matrix.dataset_role == "paired_development_matrix"
    assert len(gate.pairs) * 2 * len(gate.systems) == 10
    assert len(matrix.pairs) * 2 * len(matrix.systems) == 20
    detector_json = json.dumps(gate.model_dump(mode="json")) + json.dumps(matrix.model_dump(mode="json"))
    assert "required_validation_status" not in detector_json
    assert "required_fixture_status" not in detector_json
    assert set(labels.labels) == {
        "langchain_template_vulnerable",
        "langchain_template_fixed",
        "jinja_attr_vulnerable",
        "jinja_attr_fixed",
    }


def test_config_rejects_expansion_duplicate_systems_and_path_escape():
    value = json.loads((ROOT / "configs/python_pair_gate.json").read_text())
    value["pairs"].append(value["pairs"][0])
    with pytest.raises(ValueError, match="exactly ten"):
        PythonPairExperimentConfig.model_validate(value)
    value = json.loads((ROOT / "configs/python_pair_gate.json").read_text())
    value["systems"] = ["E1", "E1", "E3", "E4", "E5"]
    with pytest.raises(ValueError, match="E1 through E5"):
        PythonPairExperimentConfig.model_validate(value)
    value = json.loads((ROOT / "configs/python_pair_gate.json").read_text())
    value["pairs"][0]["cases"][0]["checkout"] = "../outside"
    with pytest.raises(ValueError, match="relative"):
        PythonPairExperimentConfig.model_validate(value)
