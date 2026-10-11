"""Offline model-view/consumer regressions; no credential or transport access."""
import importlib.util
import json
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('live_static_pilot_v2',ROOT/'audit/live_static_pilot_20261001/run_v2.py')
pilot=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pilot)


@pytest.fixture
def payload():
    return {'candidate_id':'operation-owned','contract':{},'operation_locator':{},'source_slice':'source',
        'original_observation':{'tool':'validate_permission_mode','status':'ok','content':'{}',
            'citation_id':'producer-owned','evidence_ids':['permission_mode:entry.py::inspect@1-2'],
            'validation_status':'UNRESOLVED'},'available_evidence_refs':['observation-owned']}


def reply(state='UNKNOWN',refs=None):
    return json.dumps({'candidate_id':'operation-owned','property_state':state,
        'evidence_refs':['observation-owned']if refs is None else refs,
        'reasoning':'Bounded original observation only.','limitation':'No application security assessment.'})


def test_model_view_eliminates_the_demonstrated_reference_namespace_ambiguity(payload):
    original=json.loads(json.dumps(payload))
    view=pilot.make_model_view(payload)
    assert payload==original
    assert view['reference_namespace']=='producer-observation-only-v1'
    assert view['available_evidence_refs']==['observation-owned']
    observation=view['observations'][0]
    assert observation['observation_ref']=='observation-owned'
    assert 'citation_id'not in observation['observation_view']
    assert 'evidence_ids'not in observation['observation_view']
    assert observation['observation_view']['validation_status']=='UNRESOLVED'
    assert observation['observation_view']['content']=='{}'
    assert 'permission_mode:entry.py'in payload['original_observation']['evidence_ids'][0]
    assert 'available_evidence_refs' in pilot.SYSTEM and 'Never copy' in pilot.SYSTEM


def test_supplied_tool_fact_id_is_still_rejected_with_a_specific_reason(payload):
    with pytest.raises(pilot.ProposalProtocolError)as caught:
        pilot.validate_proposal(reply(refs=payload['original_observation']['evidence_ids']),payload)
    assert caught.value.reason_code=='wrong_reference_namespace'
    assert caught.value.invalid_refs==tuple(payload['original_observation']['evidence_ids'])


@pytest.mark.parametrize('state',['SUPPORTED','REFUTED','UNKNOWN'])
def test_correct_original_observation_reference_preserves_positive_controls(payload,state):
    proposal=pilot.validate_proposal(reply(state),payload)
    assert proposal.property_state==state
    assert proposal.evidence_refs==['observation-owned']


def test_wrong_candidate_and_missing_strong_reference_remain_rejected(payload):
    wrong=json.loads(reply());wrong['candidate_id']='operation-other'
    with pytest.raises(pilot.ProposalProtocolError,match='candidate_identity_mismatch'):
        pilot.validate_proposal(json.dumps(wrong),payload)
    with pytest.raises(pilot.ProposalProtocolError,match='strong_state_missing_observation_reference'):
        pilot.validate_proposal(reply('SUPPORTED',[]),payload)


def test_malformed_json_has_explicit_error_and_no_fence_fallback(payload):
    with pytest.raises(pilot.ProposalProtocolError,match='reply_not_json'):
        pilot.validate_proposal('```json\n'+reply()+'\n```',payload)
