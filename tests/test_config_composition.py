"""New reusable declarations resolve to the frozen v4 protocol exactly."""
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]


def _parts(profile):
    from cv_agent.evaluation.datasets.composition import AdvisoryDataset, AdvisoryRunProfile
    dataset = AdvisoryDataset.model_validate_json((ROOT/'configs/datasets/advisory_pairs_v4.json').read_text())
    selection = AdvisoryRunProfile.model_validate_json((ROOT/f'configs/profiles/advisory_{profile}_v4.json').read_text())
    return dataset, selection


@pytest.mark.parametrize('profile,frozen,count', [
    ('gate','python_heldout_pair_gate_v4.json',10),
    ('matrix','python_heldout_pairs_v4.json',30),
])
def test_composed_protocol_equals_frozen_config(profile, frozen, count):
    from cv_agent.evaluation.datasets.composition import compose_advisory_config
    from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairExperimentConfig, planned_heldout_cells
    dataset, selection = _parts(profile)
    expected = PythonHeldoutPairExperimentConfig.model_validate_json((ROOT/'configs/history'/frozen).read_text())
    actual = compose_advisory_config(dataset, selection)
    assert actual.model_dump(mode='json', by_alias=True) == expected.model_dump(mode='json', by_alias=True)
    assert planned_heldout_cells(actual) == planned_heldout_cells(expected)
    assert len(planned_heldout_cells(actual)) == count
    mlflow = next(pair for pair in actual.pairs if pair.pair_id.startswith('hp003'))
    langflow = next(pair for pair in actual.pairs if pair.pair_id.startswith('hp002'))
    assert mlflow.input_parameters == ('model_uri',)
    assert mlflow.entry_boolean_arguments == {'enable_mlserver': True}
    assert langflow.python_import_root == 'src/backend/base'
    assert actual.claim_eligible is False


def test_profile_cannot_override_dataset_or_weaken_validation():
    from cv_agent.evaluation.datasets.composition import AdvisoryRunProfile, compose_advisory_config
    dataset, selection = _parts('matrix')
    payload = selection.model_dump(mode='json', by_alias=True)
    with pytest.raises(ValidationError, match='Extra inputs'):
        AdvisoryRunProfile.model_validate({**payload, 'pairs': []})
    with pytest.raises(ValidationError, match='Selected held-out cells'):
        compose_advisory_config(dataset, AdvisoryRunProfile.model_validate({
            **payload, 'selected_cells': [{'case_id':'hp999_a','system':'E1'}],
        }))
    with pytest.raises(ValidationError, match='model_config'):
        AdvisoryRunProfile.model_validate({**payload, 'model_config': None})


@pytest.mark.parametrize('name,frozen', [
    ('gate', 'python_heldout_pair_gate_v4.json'),
    ('matrix', 'python_heldout_pairs_v4.json'),
])
def test_current_runner_reads_composed_files_without_historical_fallback(tmp_path, name, frozen):
    import importlib
    import shutil
    from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairExperimentConfig
    runner = importlib.import_module(f'cv_agent.evaluation.runners.run_python_heldout_pair_{name}')
    for group in ('datasets', 'profiles'):
        shutil.copytree(ROOT / 'configs' / group, tmp_path / 'configs' / group)
    expected = PythonHeldoutPairExperimentConfig.model_validate_json(
        (ROOT / 'configs/history' / frozen).read_text())
    assert runner.load_config(tmp_path) == expected
    dataset_path = tmp_path / 'configs/datasets/advisory_pairs_v4.json'
    dataset = json.loads(dataset_path.read_text())
    mlflow = next(pair for pair in dataset['pairs'] if pair['pair_id'].startswith('hp003'))
    mlflow['entry_boolean_arguments']['enable_mlserver'] = False
    dataset_path.write_text(json.dumps(dataset))
    actual_mlflow = next(pair for pair in runner.load_config(tmp_path).pairs
                         if pair.pair_id.startswith('hp003'))
    assert actual_mlflow.entry_boolean_arguments == {'enable_mlserver': False}
    profile = tmp_path / f'configs/profiles/advisory_{name}_v4.json' 
    payload = json.loads(profile.read_text())
    payload['limits']['max_requests'] += 1
    profile.write_text(json.dumps(payload))
    assert runner.load_config(tmp_path).limits.max_requests == expected.limits.max_requests + 1
    # An archived copy must never mask a missing current profile.
    (tmp_path / 'configs/history').mkdir()
    shutil.copy2(ROOT / 'configs/history' / frozen, tmp_path / 'configs/history' / frozen)
    profile.unlink()
    with pytest.raises(FileNotFoundError):
        runner.load_config(tmp_path)
    profile.write_text(json.dumps({**payload, 'pairs': []}))
    with pytest.raises(ValidationError, match='Extra inputs'):
        runner.load_config(tmp_path)
