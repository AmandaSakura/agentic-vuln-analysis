import json
import subprocess
import sys
from pathlib import Path
import pytest


def console(tmp_path, text, *, budget=8192):
    source=tmp_path/'source';source.mkdir(exist_ok=True)
    (source/'entry.py').write_text(text)
    output=tmp_path/f'run-{budget}'
    p=subprocess.run([sys.executable,'-m','cv_agent','review',str(source),'--output',str(output),
        '--profile','product_triage_v2','--summary-bytes',str(budget)],capture_output=True,text=True)
    assert output.joinpath('result.json').is_file(),p.stderr+p.stdout
    return p,output,json.loads(output.joinpath('result.json').read_text())


@pytest.mark.parametrize(('mode','state'),[('0o602','SUPPORTED'),('0o600','REFUTED'),('mode','UNKNOWN')])
def test_v2_public_static_positive_negative_unknown(tmp_path,mode,state):
    p,output,result=console(tmp_path,f"import os\nos.chmod('never-executed', {mode})\n")
    assert p.returncode==0,p.stdout+p.stderr
    assert result['schema_version']=='product-review-v2'
    assert [f['property_state']for f in result['findings']]==[state]
    assert result['accounting']['model_requests']==result['accounting']['target_executions']==0
    assert output.joinpath('.private/material_manifest.json').is_file()


def test_v2_local_proof_survives_small_summary_and_share_has_no_standalone_proof(tmp_path):
    p,out,a=console(tmp_path,"import os\nos.chmod('never',0o602)\n",budget=8192)
    p,out,b=console(tmp_path,"import os\nos.chmod('never',0o602)\n",budget=1)
    assert a['identity']['semantic_engine_digest']==b['identity']['semantic_engine_digest']
    assert a['identity']['delivery_policy_digest']!=b['identity']['delivery_policy_digest']
    assert a['findings'][0]['property_state']==b['findings'][0]['property_state']=='SUPPORTED'
    assert b['counts']['analysis_completed']==1
    assert b['run_state']=='COMPLETED'
    share=json.loads(out.joinpath('share.json').read_text())
    assert share['verification_availability']=='NOT_VERIFIABLE'
    assert not any(f.get('property_state')in{'SUPPORTED','REFUTED'}for f in share['findings'])


def test_v2_same_line_operations_do_not_borrow_proof(tmp_path):
    p,out,r=console(tmp_path,"import os\nlabel='中文'; os.chmod('first',0o600); os.chmod('second',0o602)\n")
    assert p.returncode==0
    assert len(r['findings'])==2
    assert [f['property_state']for f in r['findings']]==['REFUTED','SUPPORTED']
    assert len({f['candidate_id']for f in r['findings']})==2
    assert len({f['operation_locator']['start_col_utf8']for f in r['findings']})==2


def test_v2_verify_rejects_missing_record_and_local_view_rejects_source_drift(tmp_path):
    p,out,r=console(tmp_path,"import os\nos.chmod('never',0o602)\n")
    from cv_agent.application.service_v2 import verify_bundle, view_finding
    assert verify_bundle(out)['valid']
    f=r['findings'][0]; assert 'os.chmod' in view_finding(out,f['candidate_id'],tmp_path/'source')['source']
    (tmp_path/'source/entry.py').write_text("import os\nos.chmod('never',0o600)\n")
    with pytest.raises(ValueError,match='SOURCE_DRIFT'):
        view_finding(out,f['candidate_id'],tmp_path/'source')
    next(out.joinpath('.private/evidence').glob('*.json')).unlink()
    assert not verify_bundle(out)['valid']


def test_v2_does_not_execute_shadowed_callee_and_counts_analysis_completion(tmp_path):
    p,out,r=console(tmp_path,"def check(os):\n    os.chmod('never',0o602)\n")
    assert r['findings'][0]['property_state']=='UNKNOWN'
    assert r['counts']['analysis_completed']==1
    assert r['counts']['resolved_without_conflict']==0
    assert r['findings'][0]['review_action']['required_input']


def test_v2_old_observation_argument_is_rejected(tmp_path):
    s=tmp_path/'source';s.mkdir()
    p=subprocess.run([sys.executable,'-m','cv_agent','review',str(s),'--output',str(tmp_path/'out'),
        '--profile','product_triage_v2','--observation-bytes','1800'],capture_output=True,text=True)
    assert p.returncode==2
    assert 'ambiguous' in p.stdout.lower()
