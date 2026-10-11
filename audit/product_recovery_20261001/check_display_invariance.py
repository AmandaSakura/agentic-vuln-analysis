"""Actual local S/R/U review followed by presentation-only permutation."""
import hashlib
import json
from pathlib import Path
import tempfile

from cv_agent.application.product_boundary import run_bounded_review
from cv_agent.application.service_v2 import render_local_report, project_share
from cv_agent.domain.product_result_v2 import ReviewResultV2


HERE=Path(__file__).resolve().parent
SOURCE='''import os
def first(path):
    os.chmod(path,0o602)
def second(path):
    os.chmod(path,0o600)
def third(path,mode):
    os.chmod(path,mode)
'''


def semantic_facts(result):
    return {'identity':result.identity.model_dump(mode='json'),
        'counts':result.counts.model_dump(mode='json'),
        'facts':{f.candidate_id:{'state':f.property_state,'subject':f.subject.model_dump(mode='json'),
            'record_refs':f.record_refs,'evidence_refs':f.evidence_refs}for f in result.findings}}


def main():
    output=HERE/'display-invariance-run'
    with tempfile.TemporaryDirectory(prefix='cv-agent-owned-display-')as directory:
        source=Path(directory);(source/'entry.py').write_text(SOURCE)
        envelope=run_bounded_review(source,output,options={'summary_bytes':8192})
    assert envelope['run_state']=='COMPLETED'
    result=ReviewResultV2.model_validate(envelope['result'])
    assert {f.property_state for f in result.findings}=={'SUPPORTED','REFUTED','UNKNOWN'}
    original=semantic_facts(result)
    permuted=result.model_copy(update={'findings':tuple(reversed(result.findings))})
    assert [f.candidate_id for f in permuted.findings]!=[f.candidate_id for f in result.findings]
    assert semantic_facts(permuted)==original
    a=render_local_report(result);b=render_local_report(permuted)
    assert a==b
    share=project_share(permuted,1)
    assert share['verification_availability']=='NOT_VERIFIABLE'and share['findings']==[]
    assert semantic_facts(result)==semantic_facts(permuted)==original
    receipt={'schema':'recovery-display-order-check-v1','scope':'Owned 3-function literal positive/negative/unknown control',
        'review_state':envelope['run_state'],'output':str(output),'candidate_count':3,
        'property_states':['SUPPORTED','REFUTED','UNKNOWN'],'actual_input_order_reversed':True,
        'source_engine_view_delivery_identity_unchanged':True,'property_facts_counts_and_refs_unchanged':True,
        'priority_report_byte_identical':True,'report_sha256':hashlib.sha256(a.encode()).hexdigest(),
        'share_one_byte_not_verifiable':True,'local_conclusions_survive_share':True,
        'real_model_requests':0,'target_executions':0,'human_task_measured':False}
    path=HERE/'display-invariance.json';path.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'receipt':str(path),'passed':True}))


if __name__=='__main__':main()
