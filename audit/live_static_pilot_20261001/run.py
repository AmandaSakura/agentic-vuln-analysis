"""Single bounded live evidence-consumption pilot; no target/tool execution by LLM."""
from datetime import datetime,timezone
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import tempfile
import time
from uuid import uuid4

from pydantic import BaseModel,ConfigDict,Field
from typing import Literal
from cv_agent.application.product_boundary import run_bounded_review
from cv_agent.application.service_v2 import verify_bundle
from cv_agent.domain.chat import ChatMessage
from cv_agent.evaluation.metrics import provider_usage
from cv_agent.runtime.admission import require_passing_tests,source_fingerprint
from cv_agent.runtime.journal import Journal,Trial,audit_journal
from cv_agent.runtime.model import OpenAICompatibleChatModel
from cv_agent.runtime.paths import PROJECT_ROOT

HERE=Path(__file__).resolve().parent
ROOT=PROJECT_ROOT

SYSTEM='''Read the supplied source slice and original registered static observation.
Determine only whether the observation establishes its declared bounded predicate.
Pattern presence, local coverage, unsupported semantics or unresolved dependencies
cannot establish a strong result. Do not assess whole-application safety,
exploitability or remote reachability. Do not propose attacks, patches or actions.
No tools are available. Return one JSON object only, with exactly these fields:
candidate_id (the supplied exact ID), property_state (SUPPORTED, REFUTED, UNKNOWN,
or CONFLICT), evidence_refs (only supplied original evidence reference IDs),
reasoning (brief factual explanation), limitation (the remaining scope boundary).
Do not guess absent facts. Never treat an unresolved observation as safety.'''


class Proposal(BaseModel):
    model_config=ConfigDict(extra='forbid')
    candidate_id:str
    property_state:Literal['SUPPORTED','REFUTED','UNKNOWN','CONFLICT']
    evidence_refs:list[str]
    reasoning:str=Field(min_length=1)
    limitation:str=Field(min_length=1)


def write(path,value):
    with path.open('w',encoding='utf-8')as stream:
        os.fchmod(stream.fileno(),0o600)
        json.dump(value,stream,ensure_ascii=False,indent=2,allow_nan=False)
        stream.write('\n');stream.flush();os.fsync(stream.fileno())


def read_json(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs_from_bundle(bundle,role):
    assert verify_bundle(bundle)['valid'],'Complete local static package required'
    result=read_json(bundle/'result.json')
    materials=read_json(bundle/'.private/material_manifest.json')['materials']
    sources=read_json(bundle/'.private/sources.json')
    documents={row['path']:row for row in sources['documents']}
    rows=[]
    for finding,material in zip(result['findings'],materials,strict=True):
        descriptor=material['descriptor'];assert descriptor is not None
        candidate=material['candidate']
        payload={'candidate_id':finding['candidate_id'],'contract':finding['contract'],
            'operation_locator':finding['operation_locator'],
            'source_slice':documents[candidate['path']]['text'],
            'original_observation':descriptor['observation'],
            'available_evidence_refs':finding['evidence_refs']}
        rows.append({'payload':payload,'canonical_state':finding['property_state'],
            'role':role,'bundle':str(bundle),'source_digest':result['identity']['source_digest'],
            'semantic_engine_digest':result['identity']['semantic_engine_digest']})
    return rows


def static_bundle(source,output):
    envelope=run_bounded_review(source,output,options={'summary_bytes':8192})
    assert envelope['run_state']=='COMPLETED',envelope['reason_code']
    return output


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
    protocol=read_json(HERE/'protocol.json');config=read_json(ROOT/protocol['model_config'])
    output=ROOT/'artifacts/live_static_pilot_20261001'/uuid4().hex
    output.mkdir(parents=True,mode=0o700)
    events_path=output/'events.jsonl';events_path.touch(mode=0o600)
    journal=Journal(events_path);results=[];status='PREPARING';phase='static_preparation'
    script_hash=sha(Path(__file__));protocol_hash=sha(HERE/'protocol.json')
    metadata={'protocol':protocol,'config':{**config,'max_tokens':protocol['max_output_tokens']},
        'source_fingerprint':source_fingerprint(ROOT),'script_sha256':script_hash,
        'protocol_sha256':protocol_hash,'started_at':datetime.now(timezone.utc).isoformat(),
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
        bundle=static_bundle(ROOT/protocol['source_root'],output/'owned-project-static')
        rows=inputs_from_bundle(bundle,'self_owned_project')
        assert len(rows)==protocol['expected_owned_candidates']
        with tempfile.TemporaryDirectory(prefix='cv-agent-owned-live-controls-')as folder:
            for ordinal,mode in enumerate(protocol['control_modes']):
                source=Path(folder)/f'item-{ordinal}';source.mkdir()
                (source/'entry.py').write_text('import os\ndef inspect(path):\n    os.chmod(path,'+mode+')\n')
                control=static_bundle(source,output/f'control-static-{ordinal}')
                rows.extend(inputs_from_bundle(control,'generated_development_control'))
        assert len(rows)==protocol['max_requests']
        write(output/'private-input-manifest.json',rows)
        messages=[]
        for row in rows:
            messages.append([ChatMessage(role='system',content=SYSTEM),
                ChatMessage(role='user',content=json.dumps(row['payload'],ensure_ascii=False))])
        write(output/'frozen-prompts.json',[[m.model_dump(mode='json')for m in batch]for batch in messages])
        phase='full_pytest_gate';status='GATING';finish()
        gate_started=time.monotonic();require_passing_tests()
        write(output/'gate-receipt.json',{'actual_in_process_gate_passed':True,
            'seconds':time.monotonic()-gate_started,'source_fingerprint':source_fingerprint(ROOT),
            'saved_stamp_used':False,'credential_loaded_before_gate':False})
        phase='model_requests';status='RUNNING'
        key=credential(ROOT/protocol['credential_file'],protocol['credential_name'])
        for ordinal,(row,batch)in enumerate(zip(rows,messages,strict=True)):
            assert sha(Path(__file__))==script_hash and sha(HERE/'protocol.json')==protocol_hash
            usage=provider_usage([json.loads(line)for line in events_path.read_text().splitlines()])
            if usage['requests']>=protocol['max_requests']:raise RuntimeError('Request cap reached')
            if usage['requests_without_reported_usage']or usage['usage_conflicts']:raise RuntimeError('Usage unknown or conflicting')
            reservation=len(json.dumps([m.model_dump(mode='json')for m in batch],ensure_ascii=False).encode())+protocol['max_output_tokens']+protocol['request_framing_reservation']
            if usage['reported_total_tokens']+reservation>protocol['max_reported_tokens']:
                raise RuntimeError('Conservative token reservation exceeds remaining trial budget')
            trial=Trial('sample-'+str(ordinal+1),'single-shot-static-evidence',journal)
            model=OpenAICompatibleChatModel(**{**config,'max_tokens':protocol['max_output_tokens']},
                api_key=key,observer=trial.observe('evidence_reader'))
            journal.write({'event':'reservation','sample':ordinal+1,'reserved_token_units':reservation})
            started=time.monotonic();reply=model.complete(batch,())
            if reply.model_id!=config['model']:raise RuntimeError('Returned model ID differs from frozen model')
            if reply.tool_calls:raise ValueError('Unexpected tool request in tools-disabled diagnostic')
            proposal=Proposal.model_validate(json.loads(reply.content))
            assert proposal.candidate_id==row['payload']['candidate_id']
            assert set(proposal.evidence_refs)<=set(row['payload']['available_evidence_refs'])
            if proposal.property_state in {'SUPPORTED','REFUTED','CONFLICT'}and not proposal.evidence_refs:
                raise ValueError('Strong proposal omitted original observation reference')
            result={'sample':ordinal+1,'role':row['role'],'candidate_id':proposal.candidate_id,
                'canonical_state':row['canonical_state'],'proposed':proposal.model_dump(),
                'exact_state_match':proposal.property_state==row['canonical_state'],
                'accepted_state':row['canonical_state'],'model_never_overrides_static_evidence':True,
                'wall_seconds':time.monotonic()-started}
            results.append(result);journal.write({'event':'proposal_assessment',**result})
            usage=provider_usage([json.loads(line)for line in events_path.read_text().splitlines()])
            if usage['requests_without_reported_usage']or usage['usage_conflicts']:raise RuntimeError('Reported usage unavailable')
            if usage['reported_total_tokens']>protocol['max_reported_tokens']:raise RuntimeError('Reported token cap exceeded; no further call permitted')
            finish();print('Completed sample '+str(ordinal+1)+': '+proposal.property_state,flush=True)
            if not result['exact_state_match']and proposal.property_state in {'SUPPORTED','REFUTED','CONFLICT'}:
                raise RuntimeError('Unsupported strong proposal retained; remaining trial stopped')
        status='COMPLETED';phase='completed';summary=finish()
        print(json.dumps({'status':status,'usage':summary['usage'],'output':str(output)}),flush=True)
        return 0
    except BaseException as error:
        status='STOPPED';journal.write({'event':'trial_stopped','phase':phase,'error_type':type(error).__name__})
        summary=finish(type(error).__name__)
        print(json.dumps({'status':status,'phase':phase,'error_type':type(error).__name__,
            'usage':summary['usage'],'output':str(output)}),flush=True)
        return 2


if __name__=='__main__':raise SystemExit(main())
