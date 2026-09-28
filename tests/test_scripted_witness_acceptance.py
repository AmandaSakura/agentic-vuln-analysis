"""Scripted data generation reaches the normal agent evidence gate, offline."""

from cv_agent.evaluation.diagnostics.scripted_witness_acceptance import run_scripted_candidate
from test_bounded_witness_tool import _inputs


NONCE = 'ACCEPTANCE12345678'


def test_fully_generated_manifest_is_concluded_without_repeating_execution(tmp_path):
    index,candidate,context,_ = _inputs(tmp_path/'repo')
    result = run_scripted_candidate(index,candidate,context,
        constructor_parameters={},precondition_files={},nonce=NONCE)
    assert result['verdict']['label'] == 'VULNERABLE', result
    assert result['scripted_model_calls'] == 2
    assert len(result['verdict']['votes'][0]['trace']) == 1


def test_scripted_missing_constructor_is_filled_then_admitted(tmp_path):
    index,candidate,context,_ = _inputs(tmp_path/'repo',missing_constructor=True)
    result = run_scripted_candidate(index,candidate,context,
        constructor_parameters={'token':'fixture-data'},precondition_files={},nonce=NONCE)
    assert result['live_model_requests'] == 0
    assert result['scripted_model_calls'] == 3
    assert result['verdict']['label'] == 'VULNERABLE', result
    trace = result['verdict']['votes'][0]['trace']
    assert trace[0]['tool_call']['arguments']['constructor_parameters'] == {}
    assert trace[1]['tool_call']['arguments']['constructor_parameters'] == {'token':'fixture-data'}
    assert trace[1]['observation']['validation_status'] == 'CONFIRMED'
    assert trace[1]['observation']['fixture_proof']['supported_statuses'] == ['CONFIRMED']


def test_scripted_missing_data_cannot_create_a_witness(tmp_path):
    index,candidate,context,_ = _inputs(tmp_path/'repo',missing_constructor=True)
    result = run_scripted_candidate(index,candidate,context,
        constructor_parameters={},precondition_files={},nonce=NONCE)
    assert result['verdict']['label'] == 'ABSTAIN'
    assert not any(step['observation']['validation_status'] == 'CONFIRMED'
                   for step in result['verdict']['votes'][0]['trace'])


def test_label_metadata_flip_does_not_change_script_calls_or_manifest(tmp_path):
    index,candidate,context,_ = _inputs(tmp_path/'repo',missing_constructor=True)
    first = run_scripted_candidate(index,candidate.model_copy(update={'metadata':{'expected_label':'SAFE'}}),context,
        constructor_parameters={'token':'fixture-data'},precondition_files={},nonce=NONCE)
    second = run_scripted_candidate(index,candidate.model_copy(update={'metadata':{'expected_label':'VULNERABLE'}}),context,
        constructor_parameters={'token':'fixture-data'},precondition_files={},nonce=NONCE)
    assert first['verdict']['label'] == second['verdict']['label'] == 'VULNERABLE'
    left = first['verdict']['votes'][0]['trace']
    right = second['verdict']['votes'][0]['trace']
    assert [step['tool_call'] for step in left] == [step['tool_call'] for step in right]
    assert left[1]['observation']['metadata']['manifest_sha256'] == right[1]['observation']['metadata']['manifest_sha256']
