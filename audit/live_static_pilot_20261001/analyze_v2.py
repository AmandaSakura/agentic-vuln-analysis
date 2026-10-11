"""Final read-only reconciliation; keep the two protocol versions separate."""
import hashlib
import json
from pathlib import Path
from reference_protocol import make_model_view,validate_proposal

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
OLD=ROOT/'artifacts/live_static_pilot_20261001/9930210894134fe29f99da8657c25d3c'
NEW=ROOT/'artifacts/live_static_pilot_v2_20261001/6a087adb63084f3cad384c2f3a0c43e0'

def load(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

previous=load(OLD/'summary.json');current=load(NEW/'summary.json')
assert previous['status']=='STOPPED'and current['status']=='COMPLETED'
assert current['usage']['requests']==3 and current['usage']['reported_total_tokens']==5726
assert current['ledger_audit']['reported_tokens']==5726 and not current['ledger_audit']['issues']
rows=load(NEW/'private-input-manifest.json')
events=[json.loads(line)for line in (NEW/'events.jsonl').read_text().splitlines()]
replies=[event for event in events if event['event']=='model_reply']
for row,event,result in zip(rows,replies,current['results'],strict=True):
    proposal=validate_proposal(event['reply']['content'],row['payload'])
    assert proposal.candidate_id==row['payload']['candidate_id']
    assert proposal.property_state==row['canonical_state']==result['accepted_state']
    assert result['exact_state_match']
    view=make_model_view(row['payload'])
    assert 'canonical_state'not in view
    assert all('citation_id'not in o['observation_view']and'evidence_ids'not in o['observation_view']for o in view['observations'])
assert [r['sample']for r in current['results']]==[3,4,5]
assert [r['proposed']['property_state']for r in current['results']]==['UNKNOWN','SUPPORTED','REFUTED']
combined_requests=previous['usage']['requests']+current['usage']['requests']
combined_tokens=previous['usage']['reported_total_tokens']+current['usage']['reported_total_tokens']
assert combined_requests==5 and combined_tokens==9485
gate=ROOT/'artifacts/pytest_gate/fedab56484ee498494fa84b553b2d533/pytest.log'
assert '2948 passed in 426.61s'in gate.read_text()
receipt={'schema':'live-reference-repair-acceptance-v1','status':'REPAIR_AND_BOUNDED_V2_PILOT_PASS',
    'repair':{'prompt':'Explicitly cite only available_evidence_refs/observation_ref',
        'model_view':'Internal citation_id/evidence_ids omitted from the model projection; full private originals retained',
        'validator':'Exact candidate and reference membership retained; explicit reason codes and rejected proposals logged',
        'new_offline_regressions':7,'old_second_reply_still_rejected':True},
    'gate':{'passed':2948,'seconds':426.61,'actual_experiment_process':True,
        'log':str(gate.relative_to(ROOT)),'sha256':sha(gate),'saved_stamp_used':False},
    'v1':{'status':'STOPPED_REFERENCE_NAMESPACE_MISMATCH','requests':2,'reported_tokens':3759,
        'accepted':1,'protocol_rejected':1,'history_unchanged':True,'run':str(OLD.relative_to(ROOT))},
    'v2':{'status':'COMPLETED','original_samples':[3,4,5],'requests':3,'reported_tokens':5726,
        'accepted':3,'proposed_states':['UNKNOWN','SUPPORTED','REFUTED'],
        'exact_state_matches':3,'reference_errors':0,'wrong_strong_assertions':0,
        'run':str(NEW.relative_to(ROOT))},
    'combined':{'requests':combined_requests,'reported_tokens':combined_tokens,
        'request_cap':5,'reported_token_cap':30000,'within_budget':True},
    'limits':{'same_failed_input_live_retry_performed':False,
        'all_five_under_one_unchanged_protocol_pass':False,
        'controlled_causal_improvement_claim':False,'heldout_claim_eligible':False,
        'independent_project_quality_measured':False,'human_benefit_measured':False,
        'target_executions':0,'production_R17_enabled':False,'G_A_changed':False},
    'source_and_test_fingerprint':load(NEW/'gate-receipt.json')['source_fingerprint'],
    'evidence_sha256':{str((NEW/name).relative_to(ROOT)):sha(NEW/name)for name in
        ('metadata.json','private-input-manifest.json','frozen-prompts.json','events.jsonl','summary.json','gate-receipt.json')},
    'old_evidence_sha256':{str((OLD/name).relative_to(ROOT)):sha(OLD/name)for name in
        ('metadata.json','frozen-prompts.json','private-input-manifest.json','events.jsonl','summary.json','gate-receipt.json')}}
old_diagnosis=load(HERE/'result.json')
assert all(sha(OLD/name)==digest for name,digest in old_diagnosis['evidence_sha256'].items())
(HERE/'result_v2.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'status':receipt['status'],'requests':combined_requests,'reported_tokens':combined_tokens,'v2_accepted':3}))
