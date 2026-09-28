"""The corrected diagnostic declaration cannot rewrite the v4 experiment protocol."""

import hashlib
import importlib
import json
from pathlib import Path

from cv_agent.evaluation.datasets.composition import AdvisoryDataset, load_advisory_config


ROOT = Path(__file__).resolve().parents[1]
V4_PATH = "configs/datasets/advisory_pairs_v4.json"
V5_PATH = "configs/datasets/advisory_pairs_v5.json"
V4_SHA256 = "6b26bb871650211f5087174e663c4f870ea61fc1a38cb4e9d6c81627f9847896"


def _differences(before, after, path=()):
    if isinstance(before, dict) and isinstance(after, dict):
        assert before.keys() == after.keys(), f"dataset keys changed at {path}"
        return [difference for key in before
                for difference in _differences(before[key], after[key], (*path, key))]
    if isinstance(before, list) and isinstance(after, list):
        assert len(before) == len(after), f"dataset length changed at {path}"
        return [difference for index, (left, right) in enumerate(zip(before, after, strict=True))
                for difference in _differences(left, right, (*path, index))]
    if type(before) is type(after) and before == after:
        return []
    return [(path, before, after)]


def _hp003(config):
    return next(pair for pair in config.pairs if pair.entry_id == "entry-00389")


def test_v5_changes_exactly_one_declared_value_and_preserves_v4_bytes():
    v4_bytes = (ROOT / V4_PATH).read_bytes()
    v5_bytes = (ROOT / V5_PATH).read_bytes()
    assert hashlib.sha256(v4_bytes).hexdigest() == V4_SHA256
    assert _differences(json.loads(v4_bytes), json.loads(v5_bytes)) == [
        (("pairs", 2, "entry_value_assumptions", "self._nworkers"), None, 1),
    ]
    # These are strict production dataset models; metadata stays in the sidecar.
    before = AdvisoryDataset.model_validate_json(v4_bytes)
    after = AdvisoryDataset.model_validate_json(v5_bytes)
    assert before.claim_eligible is after.claim_eligible is False
    assert _hp003(before).entry_value_assumptions["self._nworkers"] is None
    assert _hp003(after).entry_value_assumptions["self._nworkers"] == 1


def test_existing_experiments_remain_v4_and_new_diagnostics_can_select_v5():
    runners = (
        ("run_python_heldout_pair_gate", "advisory_gate_v4.json"),
        ("run_python_heldout_pair_matrix", "advisory_matrix_v4.json"),
        ("run_hp003_diagnosis_pilot", "advisory_hp003_diagnosis_v4.json"),
    )
    for module_name, profile_name in runners:
        module = importlib.import_module(f"cv_agent.evaluation.runners.{module_name}")
        profile = f"configs/profiles/{profile_name}"
        default = load_advisory_config(ROOT, profile)
        explicit_v4 = load_advisory_config(ROOT, profile, dataset_path=V4_PATH)
        assert module.load_config(ROOT) == default == explicit_v4
        assert _hp003(default).entry_value_assumptions["self._nworkers"] is None
    diagnostic = load_advisory_config(
        ROOT, "configs/profiles/advisory_hp003_diagnosis_v4.json", dataset_path=V5_PATH,
    )
    assert _hp003(diagnostic).entry_value_assumptions["self._nworkers"] == 1
    assert diagnostic.claim_eligible is False
