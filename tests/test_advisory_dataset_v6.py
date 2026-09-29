"""Near-transfer data append cannot alter prior experiments or supply scenes."""
import hashlib
import json
from pathlib import Path

from cv_agent.evaluation.datasets.composition import AdvisoryDataset

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_SHA256 = {'configs/history/python_heldout_pairs.json': 'a5ceb1e426f06c6ca61064be9535c8d22ec70dac452652d94f54b6b696d5e5a6', 'configs/history/python_heldout_pairs_v2.json': '90c30f0290f21d892c7380a07f46b63626171814a86cd0bb2d78941eecb4d461', 'configs/history/python_heldout_pairs_v3.json': '11c70024404277f2e78f1b8fde6fcb87faf4c1f67f775dabe5a5c85b8133040f', 'configs/history/python_heldout_pairs_v4.json': '7fc0287228723f4eb3645162f458975f816cfcf9e02022a48ec889287c80543e', 'configs/datasets/advisory_pairs_v4.json': '6b26bb871650211f5087174e663c4f870ea61fc1a38cb4e9d6c81627f9847896', 'configs/datasets/advisory_pairs_v5.json': '21a646958130e250ea1946b05dded36754d41f2ecc9128ac6e16ee96a8c3cfcc'}


def test_v6_appends_only_no_scene_cli_pair_and_preserves_prior_bytes():
    for name, digest in HISTORICAL_SHA256.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
    before = json.loads((ROOT / "configs/datasets/advisory_pairs_v5.json").read_text())
    raw = (ROOT / "configs/datasets/advisory_pairs_v6.json").read_text()
    after = json.loads(raw)
    assert after.keys() == before.keys()
    assert {k: v for k, v in after.items() if k != "pairs"} == {k: v for k, v in before.items() if k != "pairs"}
    assert after["pairs"][:-1] == before["pairs"]
    assert len(after["pairs"]) == len(before["pairs"]) + 1
    dataset = AdvisoryDataset.model_validate_json(raw)
    assert dataset.claim_eligible is False
    pair = dataset.pairs[-1]
    assert pair.entry_id == "entry-00390"
    assert pair.entry_point["file"] == "mlflow/models/cli.py" and pair.entry_point["line"] == 24
    assert pair.critical_operation["file"] == "mlflow/utils/environment.py" and pair.critical_operation["line"] == 1014
    assert pair.input_parameters == ()
    assert pair.entry_boolean_arguments == pair.entry_condition_assumptions == pair.entry_value_assumptions == {}
    assert [case.case_id for case in pair.cases] == ["hp004_a", "hp004_b"]
    assert all(case.file_path == pair.entry_point["file"] and case.line_hint == 24 for case in pair.cases)
    assert [case.commit for case in pair.cases] == [case.commit for case in dataset.pairs[-2].cases]
    assert "enable_mlserver=True" not in pair.vulnerability_title + pair.analysis_scope
