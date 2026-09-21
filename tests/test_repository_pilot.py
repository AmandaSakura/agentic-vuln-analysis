import importlib
import json
from pathlib import Path

import pytest

from cv_agent.provenance import GitIdentity
from cv_agent.repository_pilot import RepositoryPilotConfig, validate_heldout_membership


def config_dict():
    return {'dataset_role': 'development_pilot', 'model_config_path': 'model.json',
            'systems': ['E3', 'E5'], 'candidate_limit_per_subject': 1,
            'max_requests': 30, 'max_seconds': 60,
            'subjects': [{'repository_id': 'subject-01',
                          'repository_url': 'https://github.com/example/project',
                          'commit': 'a'*40, 'checkout': 'checkout', 'source_prefix': '.'}]}


def runner(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / 'scripts'))
    return importlib.import_module('run_python_repository_pilot')


@pytest.mark.parametrize('change', [
    {'candidate_limit_per_subject': 6}, {'systems': ['E3', 'E3']},
    {'evaluator_labels': 'secret'}, {'systems': []}, {'candidate_limit_per_subject': 0},
])
def test_pilot_cannot_expand_past_ten_cells_or_accept_label_inputs(change):
    with pytest.raises(ValueError):
        RepositoryPilotConfig.model_validate({**config_dict(), **change})


def test_heldout_membership_rejects_development_and_other_commits():
    config = RepositoryPilotConfig.model_validate(config_dict())
    frozen = {'subjects': [{'repository_url': config.subjects[0].repository_url, 'commit': 'a'*40}]}
    validate_heldout_membership(config, frozen)
    with pytest.raises(ValueError, match='frozen independent'):
        validate_heldout_membership(config, {'subjects': []})
    with pytest.raises(ValueError, match='frozen independent'):
        validate_heldout_membership(config, {'subjects': [{**frozen['subjects'][0], 'commit': 'b'*40}]})


def setup_pilot(tmp_path):
    checkout = tmp_path / 'checkout'
    checkout.mkdir()
    (checkout / 'handler.py').write_text('def entry(value):\n    return eval(value)\n')
    path = tmp_path / 'pilot.json'
    path.write_text(json.dumps(config_dict()))
    (tmp_path / 'model.json').write_text('{}')
    return path


def test_runner_records_all_candidates_before_analysis_and_stops_on_failure(monkeypatch, tmp_path):
    mod = runner(monkeypatch)
    config_path = setup_pilot(tmp_path)
    output = tmp_path / 'output'
    events = []
    monkeypatch.setattr(mod, 'require_passing_tests', lambda: events.append('full_gate'))
    monkeypatch.setattr(mod, 'git_identity', lambda path: GitIdentity(revision='a'*40, dirty=False))
    monkeypatch.setattr(mod, 'snapshot_sources', lambda path: {})

    def fail(index, candidate, system, journal, budget, **kwargs):
        assert events == ['full_gate']
        assert (output / 'inventory.json').is_file()
        assert len(json.loads((output / 'results.json').read_text())) == 2
        assert 'a'*40 not in candidate.model_dump_json()
        assert str(tmp_path) not in candidate.model_dump_json()
        events.append('trial')
        return {'case_id': candidate.case_id, 'system': system.value, 'status': 'failed',
                'predicted_label': None, 'error': 'scripted transport failure'}

    monkeypatch.setattr(mod, 'run_candidate', fail)
    assert mod.run(config_path, root=tmp_path, output=output) == output
    rows = json.loads((output / 'results.json').read_text())
    assert [row['status'] for row in rows] == ['failed', 'not_run']
    assert events == ['full_gate', 'trial']
    assert json.loads((output / 'usage.json').read_text())['requests'] == 0
    with pytest.raises(FileExistsError):
        mod.run(config_path, root=tmp_path, output=output)


def test_runner_can_complete_a_bounded_scripted_pair(monkeypatch, tmp_path):
    mod = runner(monkeypatch)
    config_path = setup_pilot(tmp_path)
    monkeypatch.setattr(mod, 'require_passing_tests', lambda: None)
    monkeypatch.setattr(mod, 'git_identity', lambda path: GitIdentity(revision='a'*40, dirty=False))
    monkeypatch.setattr(mod, 'snapshot_sources', lambda path: {})
    called = []

    def complete(index, candidate, system, journal, budget, **kwargs):
        called.append(system.value)
        return {'case_id': candidate.case_id, 'system': system.value,
                'status': 'completed', 'predicted_label': 'VULNERABLE'}

    monkeypatch.setattr(mod, 'run_candidate', complete)
    output = mod.run(config_path, root=tmp_path, output=tmp_path/'output')
    assert called == ['E3', 'E5']
    assert all(row['status'] == 'completed' for row in json.loads((output/'results.json').read_text()))


def test_modified_source_cannot_be_used_as_the_frozen_snapshot(monkeypatch, tmp_path):
    mod = runner(monkeypatch)
    setup_pilot(tmp_path)
    monkeypatch.setattr(mod, 'git_identity', lambda path: GitIdentity(revision='a'*40, dirty=False))
    _, runtime = mod.prepare(RepositoryPilotConfig.model_validate(config_dict()), tmp_path)
    root, discovery, _ = runtime['subject-01']
    (root / 'handler.py').write_text('def entry(value):\n    return value\n')
    with pytest.raises(ValueError, match='changed after discovery'):
        mod.verify_source_snapshot(root, discovery.report)
