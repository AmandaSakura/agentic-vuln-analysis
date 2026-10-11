"""Read-only reconciliation of the stopped pilot; no model/network operation."""
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
RUN=ROOT/'artifacts/live_static_pilot_20261001/9930210894134fe29f99da8657c25d3c'

def load(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    manifest=load(RUN/'private-input-manifest.json')
    summary=load(RUN/'summary.json')
    events=[json.loads(line)for line in (RUN/'events.jsonl').read_text().splitlines()]
    replies=[event for event in events if event['event']=='model_reply']
    rows=[]
    for row,event in zip(manifest,replies):
        proposal=json.loads(event['reply']['content'])
        expected=set(row['payload']['available_evidence_refs'])
        supplied=set(row['payload']['original_observation']['evidence_ids'])
        cited=set(proposal['evidence_refs'])
        rows.append({'request_id':event['request_id'],'candidate_id':proposal['candidate_id'],
            'canonical_state':row['canonical_state'],'proposed_state':proposal['property_state'],
            'candidate_identity_matches':proposal['candidate_id']==row['payload']['candidate_id'],
            'state_matches':proposal['property_state']==row['canonical_state'],
            'allowed_observation_refs':sorted(expected),'cited_refs':sorted(cited),
            'observation_namespace_valid':cited<=expected,
            'out_of_namespace_ids_are_supplied_tool_evidence_ids':bool(cited-expected)and(cited-expected)<=supplied,
            'reported_usage':event['reply']['usage']})
    assert summary['usage']['requests']==len(replies)==2
    assert summary['ledger_audit']['reported_tokens']==summary['usage']['reported_total_tokens']==3759
    assert all(r['candidate_identity_matches']and r['state_matches']for r in rows)
    assert rows[0]['observation_namespace_valid']and not rows[1]['observation_namespace_valid']
    assert rows[1]['out_of_namespace_ids_are_supplied_tool_evidence_ids']
    gate_log=ROOT/'artifacts/pytest_gate/b59fc1446f454259ae3e59d4f25560c5/pytest.log'
    assert '2941 passed in 427.49s'in gate_log.read_text()
    diagnosis={'schema':'live-static-pilot-reconciliation-v1','status':'STOPPED_REFERENCE_NAMESPACE_MISMATCH',
        'run':str(RUN.relative_to(ROOT)),'gate':{'passed':2941,'seconds':427.49,'actual_in_process':True,
            'credential_loaded_before_gate':False,'log':str(gate_log.relative_to(ROOT)),'sha256':sha(gate_log)},
        'requests':2,'provider_replies':2,'reported_tokens':3759,'accepted_candidates':1,
        'parsed_but_protocol_rejected_candidates':1,'unrun_candidates':3,
        'zero_wrong_strong_states_observed_in_two_replies':True,'completed_planned_five_case_trial':False,
        'cases':rows,'diagnosis':'The second response cited a supplied tool-internal source/fact evidence ID instead of an allowed producer observation reference. Its UNKNOWN state was consistent with the canonical static result, but its reference namespace did not satisfy the frozen output protocol.',
        'prompt_limitation':'The wording original evidence reference IDs can be read ambiguously because both namespaces occur in the payload. This is a protocol/prompt usability issue, not demonstrated vulnerability misclassification.',
        'no_posthoc_acceptance_rule_change':True,'remaining_budget_is_not_authorization_to_retry':True,
        'next_offline_work':'Explicitly distinguish available_evidence_refs from tool-internal evidence_ids in a prospective protocol version; retain the original failed run and do not weaken original producer identity checks.',
        'source_or_target_executions':0,'claim_eligible':False,'production_R17_enabled':False,'G_A_changed':False,
        'evidence_sha256':{name:sha(RUN/name)for name in ('metadata.json','frozen-prompts.json','private-input-manifest.json','events.jsonl','summary.json','gate-receipt.json')}}
    (HERE/'result.json').write_text(json.dumps(diagnosis,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'status':diagnosis['status'],'requests':2,'reported_tokens':3759,'accepted_candidates':1}))

if __name__=='__main__':main()
