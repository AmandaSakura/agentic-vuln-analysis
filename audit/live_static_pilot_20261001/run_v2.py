"""Single bounded live evidence-consumption pilot; no target/tool execution by LLM."""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import time
from uuid import uuid4

import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from reference_protocol import SYSTEM,ProposalProtocolError,make_model_view,validate_proposal
from cv_agent.application.service_v2 import verify_bundle
from cv_agent.domain.chat import ChatMessage
from cv_agent.evaluation.metrics import provider_usage
from cv_agent.runtime.admission import require_passing_tests,source_fingerprint
from cv_agent.runtime.journal import Journal,Trial,audit_journal
from cv_agent.runtime.model import OpenAICompatibleChatModel
from cv_agent.runtime.paths import PROJECT_ROOT

HERE=Path(__file__).resolve().parent
ROOT=PROJECT_ROOT

def write(path,value):
    with path.open('w',encoding='utf-8')as stream:
        os.fchmod(stream.fileno(),0o600)
        json.dump(value,stream,ensure_ascii=False,indent=2,allow_nan=False)
        stream.write('\n');stream.flush();os.fsync(stream.fileno())


def read_json(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def credential(path,name):
    # Deliberately called only after the full in-process gate completed.
    for line in path.read_text().splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        if line.startswith('export '):line=line[7:]
        key,separator,value=line.partition('=')
        if separator and key.strip()==name:
            parts=shlex.split(value,comments=True)
            if len(parts)!=1 or not parts[0]:raise ValueError('Configured credential is empty or invalid')
            return parts[0]
    raise ValueError('Configured credential name is absent')


def main():
    protocol=read_json(HERE/'protocol_v2.json');config=read_json(ROOT/protocol['model_config'])
    output=ROOT/'artifacts/live_static_pilot_v2_20261001'/uuid4().hex
    output.mkdir(parents=True,mode=0o700)
    events_path=output/'events.jsonl';events_path.touch(mode=0o600)
    journal=Journal(events_path);results=[];status='PREPARING';phase='static_preparation'
    script_hash=sha(Path(__file__));protocol_hash=sha(HERE/'protocol_v2.json');helper_hash=sha(HERE/'reference_protocol.py')
    metadata={'protocol':protocol,'config':{**config,'max_tokens':protocol['max_output_tokens']},
        'source_fingerprint':source_fingerprint(ROOT),'script_sha256':script_hash,
        'protocol_sha256':protocol_hash,'helper_sha256':helper_hash,'started_at':datetime.now(timezone.utc).isoformat(),
        'claim_eligible':False,'target_executions':0,'model_tools':[],
        'purpose':'Live consumption of bounded static evidence, not exploit or held-out evaluation'}
    write(output/'metadata.json',metadata)
    print('Run directory: '+str(output),flush=True)

    def finish(reason=None):
        events=[json.loads(line)for line in events_path.read_text().splitlines()]
        summary={'status':status,'phase':phase,'stop_reason':reason,'results':results,
            'usage':provider_usage(events),'ledger_audit':audit_journal(events_path),
            'completed_candidates':len(results),'planned_candidates':protocol['max_requests'],
            'target_executions':0,'heldout_claim_eligible':False,'production_R17_enabled':False,
            'G_A_changed':False,'finished_at':datetime.now(timezone.utc).isoformat()}
        write(output/'summary.json',summary)
        return summary

    try:
        previous=ROOT/protocol['previous_run']
        previous_rows=read_json(previous/'private-input-manifest.json')
        old_summary=read_json(previous/'summary.json');old_usage=old_summary['usage']
        assert old_usage['requests']==2 and old_usage['reported_total_tokens']==3759
        assert not old_usage['requests_without_reported_usage']and not old_usage['usage_conflicts']
        rows=[previous_rows[i-1]for i in protocol['original_samples']]
        for row in rows:assert verify_bundle(Path(row['bundle']))['valid']
        assert len(rows)==protocol['max_requests']
        write(output/'private-input-manifest.json',rows)
        messages=[]
        for row in rows:
            messages.append([ChatMessage(role='system',content=SYSTEM),
                ChatMessage(role='user',content=json.dumps(make_model_view(row['payload']),ensure_ascii=False))])
        write(output/'frozen-prompts.json',[[m.model_dump(mode='json')for m in batch]for batch in messages])
        phase='full_pytest_gate';status='GATING';finish()
        gate_started=time.monotonic();require_passing_tests()
        write(output/'gate-receipt.json',{'actual_in_process_gate_passed':True,
            'seconds':time.monotonic()-gate_started,'source_fingerprint':source_fingerprint(ROOT),
            'saved_stamp_used':False,'credential_loaded_before_gate':False})
        phase='model_requests';status='RUNNING'
        key=credential(ROOT/protocol['credential_file'],protocol['credential_name'])
        for ordinal,(row,batch)in enumerate(zip(rows,messages,strict=True)):
            assert sha(Path(__file__))==script_hash and sha(HERE/'protocol_v2.json')==protocol_hash
            assert sha(HERE/'reference_protocol.py')==helper_hash
            usage=provider_usage([json.loads(line)for line in events_path.read_text().splitlines()])
            if usage['requests']>=protocol['max_requests']:raise RuntimeError('Request cap reached')
            if old_usage['requests']+usage['requests']>=protocol['combined_request_cap']:raise RuntimeError('Combined request cap reached')
            if usage['requests_without_reported_usage']or usage['usage_conflicts']:raise RuntimeError('Usage unknown or conflicting')
            reservation=len(json.dumps([m.model_dump(mode='json')for m in batch],ensure_ascii=False).encode())+protocol['max_output_tokens']+protocol['request_framing_reservation']
            if old_usage['reported_total_tokens']+usage['reported_total_tokens']+reservation>protocol['combined_reported_token_cap']:
                raise RuntimeError('Conservative token reservation exceeds remaining trial budget')
            sample=protocol['original_samples'][ordinal]
            trial=Trial('sample-'+str(sample),'single-shot-static-evidence-v2',journal)
            model=OpenAICompatibleChatModel(**{**config,'max_tokens':protocol['max_output_tokens']},
                api_key=key,observer=trial.observe('evidence_reader'))
            journal.write({'event':'reservation','sample':sample,'reserved_token_units':reservation})
            started=time.monotonic();reply=model.complete(batch,())
            if reply.model_id!=config['model']:raise RuntimeError('Returned model ID differs from frozen model')
            if reply.tool_calls:raise ValueError('Unexpected tool request in tools-disabled diagnostic')
            phase='reply_protocol_validation'
            proposal=validate_proposal(reply.content,row['payload'])
            result={'sample':sample,'role':row['role'],'candidate_id':proposal.candidate_id,
                'canonical_state':row['canonical_state'],'proposed':proposal.model_dump(),
                'exact_state_match':proposal.property_state==row['canonical_state'],
                'accepted_state':row['canonical_state'],'model_never_overrides_static_evidence':True,
                'wall_seconds':time.monotonic()-started}
            results.append(result);journal.write({'event':'proposal_assessment',**result})
            usage=provider_usage([json.loads(line)for line in events_path.read_text().splitlines()])
            if usage['requests_without_reported_usage']or usage['usage_conflicts']:raise RuntimeError('Reported usage unavailable')
            if old_usage['reported_total_tokens']+usage['reported_total_tokens']>protocol['combined_reported_token_cap']:raise RuntimeError('Reported token cap exceeded; no further call permitted')
            finish();print('Completed sample '+str(sample)+': '+proposal.property_state,flush=True)
            if not result['exact_state_match']and proposal.property_state in {'SUPPORTED','REFUTED','CONFLICT'}:
                raise RuntimeError('Unsupported strong proposal retained; remaining trial stopped')
            phase='model_requests'
        status='COMPLETED';phase='completed';summary=finish()
        print(json.dumps({'status':status,'usage':summary['usage'],'output':str(output)}),flush=True)
        return 0
    except BaseException as error:
        status='STOPPED';reason=error.reason_code if isinstance(error,ProposalProtocolError)else type(error).__name__
        journal.write({'event':'trial_stopped','phase':phase,'error_type':type(error).__name__,'reason_code':reason,
            'rejected_proposal':error.proposed if isinstance(error,ProposalProtocolError)else None,
            'invalid_refs':list(error.invalid_refs)if isinstance(error,ProposalProtocolError)else []})
        summary=finish(reason)
        print(json.dumps({'status':status,'phase':phase,'error_type':type(error).__name__,
            'usage':summary['usage'],'output':str(output)}),flush=True)
        return 2


if __name__=='__main__':raise SystemExit(main())
