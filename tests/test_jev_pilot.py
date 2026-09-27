import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from cv_agent.evaluation.runners import run_jev_routing_pilot as pilot
from cv_agent.harness import AgentSystemVersion
from test_agentic_workflow import _index_and_candidate


ROOT = Path(__file__).resolve().parents[1]


def setup_pilot(tmp_path, monkeypatch):
    for relative in ('configs/experiments/jev_routing_v2_pilot.json', 'configs/profiles/advisory_matrix_v4.json',
                     'configs/datasets/advisory_pairs_v4.json'):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    monkeypatch.setenv('JEV_API_KEY', 'offline-key')
    monkeypatch.setattr(pilot, 'require_passing_tests', lambda: None)
    monkeypatch.setattr(pilot, 'snapshot_sources', lambda *args: {})
    monkeypatch.setattr(pilot, 'load_experiment_model', lambda *args: ({'model': 'offline'}, 'offline-expert-key'))
    index, candidate = _index_and_candidate()
    def prepare(root, config):
        assert [(cell.case_id, cell.system.value) for cell in config.selected_cells] == [('hp001_a', 'E4'), ('hp001_b', 'E4')]
        return [('pair', role, index, candidate.model_copy(update={'case_id': case}), (), AgentSystemVersion.E4_GRAPH_MULTI)
                for case, role in [('hp001_a', 'vulnerable'), ('hp001_b', 'fixed')]], {}, {}
    monkeypatch.setattr(pilot, 'build_tasks', prepare)


def test_pilot_runs_separate_six_cell_comparison_and_keeps_credentials_out(tmp_path, monkeypatch):
    setup_pilot(tmp_path, monkeypatch)
    calls = []
    def execute(index, candidate, system, journal, budget, **kwargs):
        calls.append((candidate.case_id, system, kwargs))
        return dict(case_id=candidate.case_id, system=kwargs['report_system'], status='abstained',
                    predicted_label='ABSTAIN', verdict=None, model_calls=0, tool_calls=0, latency_sec=0)
    monkeypatch.setattr(pilot, 'run_candidate', execute)
    output = pilot.run(tmp_path)
    assert [kwargs['report_system'] for _, _, kwargs in calls] == ['E4_JEV', 'E3', 'E4'] * 2
    assert [kwargs['routing_config'] is not None for _, _, kwargs in calls] == [True, False, False] * 2
    summary = json.loads((output / 'summary.json').read_text())
    assert summary['claim_eligible'] is False
    assert summary['dataset_role'] == 'development'
    assert summary['systems']['E4_JEV']['abstained'] == 2
    assert summary['systems']['E4_JEV']['total'] == 2
    assert 'offline-key' not in (output / 'metadata.json').read_text()
    assert 'offline-expert-key' not in (output / 'metadata.json').read_text()


def test_failed_pilot_stops_and_retains_unrun_denominators(tmp_path, monkeypatch):
    setup_pilot(tmp_path, monkeypatch)
    calls = []
    def execute(index, candidate, system, journal, budget, **kwargs):
        calls.append(kwargs['report_system'])
        return dict(status='failed', error='offline transport failure', model_calls=1,
                    tool_calls=0, latency_sec=0, predicted_label=None, verdict=None)
    monkeypatch.setattr(pilot, 'run_candidate', execute)
    output = tmp_path / 'run'
    with pytest.raises(RuntimeError, match='offline transport failure'): pilot.run(tmp_path, output)
    assert calls == ['E4_JEV']
    rows = json.loads((output / 'results.json').read_text())
    assert len(rows) == 6
    assert [row['status'] for row in rows] == ['failed'] + ['not_run'] * 5


def test_pilot_requires_key_before_preparing_or_running_models(tmp_path, monkeypatch):
    setup_pilot(tmp_path, monkeypatch)
    monkeypatch.delenv('JEV_API_KEY')
    with pytest.raises(ValueError, match='JEV_API_KEY'): pilot.run(tmp_path)
    assert not (tmp_path / 'artifacts').exists()


def test_launcher_loads_only_temporary_credentials_and_calls_fixed_entrypoint(tmp_path):
    (tmp_path / 'scripts').mkdir()
    shutil.copyfile(ROOT / 'scripts/jev_pilot.sh', tmp_path / 'scripts/jev_pilot.sh')
    (tmp_path / '.env.experiments').write_text('JEV_API_KEY=temporary-test-key\n')
    (tmp_path / 'bin').mkdir()
    uv = tmp_path / 'bin/uv'
    uv.write_text('#!/bin/bash\nset -eu\n[[ "$JEV_API_KEY" == temporary-test-key ]]\nprintf "%s\\n" "$@"\n')
    uv.chmod(0o755)
    result = subprocess.run(['bash', str(tmp_path / 'scripts/jev_pilot.sh')], cwd='/',
        env={'PATH': str(tmp_path / 'bin') + ':' + os.environ['PATH']}, text=True, capture_output=True, check=True)
    assert result.stdout.splitlines() == ['run', '--no-sync', 'python', '-m', 'cv_agent.evaluation.runners.run_jev_routing_pilot']


@pytest.mark.parametrize('fail_first', [False, True])
def test_hp003_active_comparison_shares_inputs_and_preserves_four_cells(tmp_path, monkeypatch, fail_first):
    setup_pilot(tmp_path, monkeypatch)
    config_path = 'configs/experiments/hp003_jev_active.json'
    shutil.copyfile(ROOT / config_path, tmp_path / config_path)
    index, candidate = _index_and_candidate()
    registered = (object(),)

    def prepare(root, config):
        assert [(cell.case_id, cell.system.value) for cell in config.selected_cells] == [
            ('hp003_a', 'E4'), ('hp003_b', 'E4')]
        return [('pair', role, index, candidate.model_copy(update={'case_id': case}),
                 registered, AgentSystemVersion.E4_GRAPH_MULTI)
                for case, role in [('hp003_a', 'vulnerable'), ('hp003_b', 'fixed')]], {}, {}

    calls = []

    def execute(actual_index, actual_candidate, system, journal, budget, **kwargs):
        calls.append((actual_candidate, kwargs))
        assert actual_index is index
        assert kwargs['registered_tools'] is registered
        assert system == AgentSystemVersion.E4_GRAPH_MULTI
        routing = kwargs['routing_config']
        if kwargs['report_system'] == 'E4_JEV':
            assert routing.mode == 'active'
        else:
            assert routing is None
        return dict(status='failed' if fail_first else 'abstained',
                    error='offline transport failure' if fail_first else None,
                    predicted_label=None if fail_first else 'ABSTAIN', verdict=None,
                    model_calls=0, tool_calls=0, latency_sec=0)

    monkeypatch.setattr(pilot, 'build_tasks', prepare)
    monkeypatch.setattr(pilot, 'run_candidate', execute)
    output = tmp_path / 'active-run'
    if fail_first:
        with pytest.raises(RuntimeError, match='offline transport failure'):
            pilot.run(tmp_path, output, config_path=config_path)
        assert len(calls) == 1
    else:
        pilot.run(tmp_path, output, config_path=config_path)
        assert [(item.case_id, kwargs['report_system']) for item, kwargs in calls] == [
            ('hp003_a', 'E4_JEV'), ('hp003_a', 'E4'),
            ('hp003_b', 'E4_JEV'), ('hp003_b', 'E4')]
        assert calls[0][0] is calls[1][0]
        assert calls[2][0] is calls[3][0]
    rows = json.loads((output / 'results.json').read_text())
    assert len(rows) == 4
    assert [row['status'] for row in rows] == (
        ['failed', 'not_run', 'not_run', 'not_run'] if fail_first else ['abstained'] * 4)
    summary = json.loads((output / 'summary.json').read_text())
    assert set(summary['systems']) == {'E4_JEV', 'E4'}
    assert set(summary['paired']) == {'E4_vs_E4_JEV'}
    metadata = json.loads((output / 'metadata.json').read_text())
    assert metadata['config']['routing']['mode'] == 'active'
    assert 'offline-key' not in (output / 'metadata.json').read_text()
