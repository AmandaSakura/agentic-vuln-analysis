"""The explicit verification CLI and differential retain positive-only status."""

import copy
import json
import subprocess
import sys

import pytest

from cv_agent.evaluation.diagnostics.compare_bounded_witness_diagnostics import compare_diagnostics
from test_bounded_execution_witness import NONCE
from test_bounded_witness_pair_comparison import _record
from test_bounded_witness_verification import _bound


def _verified_record(digest):
    record = _record(digest)
    record['verification_mode'] = True
    record['read_policy_sha256'] = 'same-policy'
    record['resource_profile'] = {'name': 'heavy_target'}
    record['result']['status'] = 'CONFIRMED'
    record['result']['raw_status'] = 'EXPANDED_OBSERVED'
    record['result']['details'].update(diagnostic_only=False, verification_mode=True,
                                    isolation_read_grants=[])
    return record


def test_pair_comparison_accepts_explicit_positive_only_verification():
    first = _verified_record('a')
    second = _verified_record('b')
    second['result'].update(status='UNRESOLVED', raw_status='LITERAL_OBSERVED')
    result = compare_diagnostics(first, second)
    assert result['same_concrete_input'] is True
    assert result['same_read_policy'] is True
    assert result['same_resource_profile'] is True
    assert result['first']['raw_status'] == 'EXPANDED_OBSERVED'
    assert result['second']['raw_status'] == 'LITERAL_OBSERVED'


@pytest.mark.parametrize('field', ['read_policy_sha256', 'resource_profile'])
def test_verification_pair_rejects_policy_or_resource_differences(field):
    second = copy.deepcopy(_verified_record('b'))
    second[field] = 'changed'
    with pytest.raises(ValueError, match='verification policies differ'):
        compare_diagnostics(_verified_record('a'), second)


def test_verification_pair_rejects_observation_only_partner():
    with pytest.raises(ValueError, match='modes differ'):
        compare_diagnostics(_verified_record('a'), _record('b'))


def test_explicit_cli_runs_probe_and_control_and_preserves_full_observations(tmp_path):
    manifest = _bound(tmp_path)
    manifest_path = tmp_path / 'manifest.json'
    manifest_path.write_text(manifest.model_dump_json())
    output = tmp_path / 'result.json'
    completed = subprocess.run([
        sys.executable, '-m', 'cv_agent.evaluation.diagnostics.run_bounded_witness_diagnostic',
        str(manifest_path), str(tmp_path / 'runtime'), NONCE, str(output),
        '--no-strace', '--verify-obligations',
    ], capture_output=True, text=True, timeout=20)
    assert completed.returncode == 0, completed.stderr
    record = json.loads(output.read_text())
    assert record['verification_mode'] is True
    assert record['result']['status'] == 'CONFIRMED', record
    assert record['result']['details']['control_event']['preexec_verification']['ok'] is True
    assert record['result']['details']['control_replay']['ok'] is True
    assert record['strace_enabled'] is False
