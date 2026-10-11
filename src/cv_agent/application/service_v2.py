"""Versioned static local packages: evidence is complete before summary projection."""
from __future__ import annotations
import ast
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time
from uuid import uuid4

from cv_agent.agents.discovery import RepositoryDiscovery, discover_python_repository
from cv_agent.application.context import ContextManifest, ReadGrant, SourceReadView
from cv_agent.application.evidence import reduce_observations
from cv_agent.application.errors import ProductDeliveryError
from cv_agent.application.identity import analysis_implementation_digest, canonical_digest, source_digest
from cv_agent.application.local_evidence import EvidenceStore, LocalEvidenceError, LocalEvidenceBudgetError, read_descriptor
from cv_agent.application.operations import discover_operations, registered_calls_on_line
from cv_agent.application.preflight import preflight, PROPERTY_TO_TOOL, STATIC_TOOLS
from cv_agent.application.source_snapshot import SourceFile, SourceSnapshot, freeze_source_snapshot
from cv_agent.code_adapters.python import parse_python_source
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import ToolObservation, ValidationSubject
from cv_agent.domain.product_result import Diagnosis, FindingView
from cv_agent.domain.product_result_v2 import (LocalFinding, ProductIdentityV2, ResourceLimits,
    ReviewAction, ReviewCountsV2, ReviewResultV2)
from cv_agent.domain.types import Candidate, CodeDocument
from cv_agent.presentation.commit import commit_directory
from cv_agent.retrieval.index import FrozenRepositoryIndex
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation import full_agent_tools

EXCLUDED = frozenset({'data','artifacts','audit','.hermes'})
MAX_CERTIFICATE_BYTES = 2*1024*1024


def _json(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)


def _write(path, value):
    with Path(path).open('w',encoding='utf-8') as stream:
        os.fchmod(stream.fileno(),0o600)
        stream.write(_json(value)+'\n');stream.flush();os.fsync(stream.fileno())


def semantic_digest(limits: ResourceLimits):
    return canonical_digest('product-semantic-engine-v2', {'profile':'product_triage_v2',
        'implementation':analysis_implementation_digest(),'limits':limits.model_dump(mode='json'),
        'operation_rules':'static-operation-rules-v2','admission':'observation-admission-v1'})


def _registry(index):
    return ToolRegistry([t for t in full_agent_tools(index) if t.name in STATIC_TOOLS],
                        max_output_bytes=MAX_CERTIFICATE_BYTES)


def derive_packaged_documents(source_files):
    """Regenerate syntax metadata from bytes; serialized metadata is not authority."""
    import io,tokenize
    docs=[]
    for path,entry in sorted(source_files.items()):
        if entry['raw']is None or entry.get('error_stage')=='limit':continue
        raw=base64.b64decode(entry['raw'],validate=True)
        try:
            encoding,_=tokenize.detect_encoding(io.BytesIO(raw).readline);text=raw.decode(encoding)
            spans=parse_python_source('authorized-local-source',path,text)
        except (SyntaxError,UnicodeError,LookupError,ValueError):continue
        docs.extend(s.document for s in spans)
        docs.append(CodeDocument(repository_id='authorized-local-source',path=f'{path}::<module>@1-{max(1,len(text.splitlines()))}',
            text=text,language='python',adapter_tier='ast'))
    return tuple(sorted(docs,key=lambda d:d.path))


def derive_packaged_operations(source_files, hashes, index):
    """Rebuild the enumerated operation inventory from the same sealed bytes."""
    import io,tokenize
    files={};errors=[]
    indexed_files={d.path.split('::',1)[0]for d in index.documents.values()}
    for path,entry in sorted(source_files.items()):
        raw=None if entry['raw']is None else base64.b64decode(entry['raw'],validate=True)
        encoding=text=None
        if raw is not None:
            try:
                encoding,_=tokenize.detect_encoding(io.BytesIO(raw).readline);text=raw.decode(encoding)
            except (SyntaxError,UnicodeError,LookupError):pass
        error=None if path in indexed_files else 'UnavailablePackagedSyntax'
        files[path]=SourceFile(path,raw,hashes[path],encoding,text,error)
        if error is not None:errors.append({'path':path,'error_type':error})
    snapshot=SourceSnapshot(root=Path('.'),files=files,excluded_dirs=EXCLUDED)
    discovery=RepositoryDiscovery(index=index,candidates=(),report={
        'repository_id':'authorized-local-source','source_sha256':{p:h for p,h in hashes.items()if h is not None},
        'source_snapshot_digest':snapshot.source_digest,'parse_errors':errors})
    return discover_operations(snapshot,discovery)


def analyze_operation(index, candidate: Candidate, admitted: frozenset[str], producer: str):
    """One registered static producer over an explicitly admitted exact operation."""
    subject=candidate_subject(index,candidate)
    selected=PROPERTY_TO_TOOL.get(candidate.property_id,'run_static_check')
    locator=candidate.metadata['operation_locator']
    # These validators historically bind source lines. Multiple registered
    # operations on a line remain ambiguous; argument construction alone is
    # not a second operation. The validator still receives the complete slice
    # and must retain unresolved argument effects. Permission has its locator.
    if selected!='validate_permission_mode':
        source=index.documents[candidate.path]
        local_line=candidate.line-int(re.search(r'@(\d+)-',candidate.path)[1])+1
        try:
            calls=registered_calls_on_line(source,local_line)
        except SyntaxError:
            calls=[]
        if selected!='run_static_check' and len(calls)!=1:
            return ToolObservation(tool=selected,status='blocked',content=_json({
                'reason_code':'exact_operation_semantics_not_supported',
                'summary':'This operation needs an exact binding not supplied by the line-level validator.'}))
    arguments=({'source_path':candidate.path,'max_hops':2}
               if selected in {'inspect_command_construction','probe_python_eval'}else{'path':candidate.path})
    scope=ToolExecutionScope(admitted_paths=admitted,candidate_path=candidate.path,subject=subject,
        max_observation_tokens=MAX_CERTIFICATE_BYTES,operation_locator=locator)
    return _registry(index).invoke(ModelToolCall(call_id=producer,name=selected,arguments=arguments),
        allowed=(selected,),scope=scope,citation_id=producer)


def _action(property_id,state):
    if state=='CONFLICT':
        return ReviewAction(kind='reconcile-conflict',required_input=('核对相同操作的完整正反记录及其前提。',),
            reanalysis='在同一源码与契约下核对原生产者，保留全部记录后重新归并。',
            done_condition='冲突原因有可核对记录；未消除时保持 CONFLICT。')
    inputs={
        'chmod-mode-others-write':'核对该 chmod 的 mode 赋值位置、整数允许取值和相关绑定；动态值不得猜测为常量。',
        'command-execution':'提供该输入的实际来源、允许值及消费边界；调用或可疑名称不能建立外部控制。',
        'dynamic-evaluation':'核对所选 eval/exec 的真实 callee 绑定、输入来源和获准函数切片。',
    }
    if state=='UNKNOWN':
        return ReviewAction(kind='supply-input'if property_id in inputs else'review-lead',
            required_input=(inputs.get(property_id,'为这条操作明确主体、资源、输入范围和要检查的性质；当前只有语法线索。'),),
            reanalysis='显式授权缺失上下文后，对同一快照和精确操作重新运行相应静态检查。',
            done_condition='得到匹配的有界依据，或记录仍未支持的构造/动态前提并保持 UNKNOWN。')
    return ReviewAction(kind='review-property',required_input=('核对本地完整证据、声明性质与项目政策是否适用。',),
        reanalysis='源码或分析前提改变时，建立新快照再分析；不自动应用补丁。',
        done_condition='维护者记录有限性质的处理决定；应用安全、公开可达性和远程权限另行评估。')


def project_share(result: ReviewResultV2, summary_bytes:int):
    rows=[];used=0
    for f in result.findings:
        row={'candidate_id':f.candidate_id,'location':f.operation_locator,
             'property_state':'UNKNOWN','local_conclusion_available':f.property_state!='UNKNOWN',
             'review_action':f.review_action.model_dump(mode='json')}
        size=len(_json(row).encode())
        if used+size>summary_bytes:continue
        rows.append(row);used+=size
    return {'schema_version':'product-share-v2','verification_availability':'NOT_VERIFIABLE',
        'findings':rows,'candidate_total':result.counts.candidate_total,
        'omitted_candidates':result.counts.candidate_total-len(rows),
        'summary_body_bytes':used,'summary_body_budget':summary_bytes,
        'metadata_budget_exempt':True,'notice':'完整依据在用户私有本地包；该分享件不提供可独立复核的强断言。'}


def render_local_report(result):
    rows=['# 本地静态审查 v2','',f'运行：{result.run_state}；候选：{result.counts.candidate_total}；'
        f'无冲突解决：{result.counts.resolved_without_conflict}；冲突：{result.counts.conflict}',
        '','完整原记录位于私有本地包。公共分享件 share.json 不携带证明资格。',
        '应用安全、公共入口与远程权限均未评估。','']
    order={'CONFLICT':0,'SUPPORTED':1,'UNKNOWN':2,'REFUTED':3}
    rows += ['优先队列最多显示 10 项；完整清单和分母保留在 result.json。','']
    for f in sorted(result.findings,key=lambda x:(order[x.property_state],x.candidate_id))[:10]:
        l=f.operation_locator
        rows += [f'## {f.candidate_id}',f"位置：{l['source_path']}:{l['start_line']}，UTF-8 列 {l['start_col_utf8']}–{l['end_col_utf8']}。",
            f'性质：{f.contract.property_id}；量词：{f.contract.quantifier}；状态：{f.property_state}；类别：{f.display_class}。',
            f'分析：{f.analysis_state}；记录：{f.persistence_state}；本地依据：{f.local_verification}。',
            '已建立事实：'+'；'.join(f.facts or('尚无完整性质事实。',)),
            '条件前提：'+'；'.join(f.assumptions or('仅限声明的候选和有界模型，不建立实际执行或部署权限。',)),
            '缺项：'+'；'.join(f.missing_obligations or('该有限性质有依据；应用层政策仍待核对。',)),
            '责任方：'+f.review_action.owner,'需要输入：'+'；'.join(f.review_action.required_input),
            '再分析：'+f.review_action.reanalysis,'完成条件：'+f.review_action.done_condition,
            '本地定位：`cv-agent view RUN --candidate-id '+f.candidate_id+' --source-root SOURCE`。','']
    rows += ['## 诊断','',*[f'- {d.stage}: {d.reason_code} ({d.owner})'for d in result.diagnoses]]
    return '\n'.join(rows)+'\n'


def run_review_v2(source_root:Path,output:Path,*,summary_bytes:int=8192,context_manifest=None,
                  context_bytes:int=8192,limits:dict|None=None):
    started=time.monotonic();source_root=Path(source_root);output=Path(output)
    if type(summary_bytes)is not int or summary_bytes<0:raise ValueError('summary byte budget must be nonnegative')
    policy=ResourceLimits.model_validate(limits or{})
    frozen_semantic_digest=semantic_digest(policy)
    if output.exists()or output.is_symlink():raise FileExistsError('Output already exists')
    output.parent.mkdir(parents=True,exist_ok=True)
    staging=Path(tempfile.mkdtemp(prefix=f'.{output.name}-v2-',dir=output.parent))
    private=staging/'.private';private.mkdir(mode=0o700)
    store=EvidenceStore(private/'evidence',max_bytes=policy.max_record_bytes)
    run_id='review-v2-'+uuid4().hex;state='COMPLETED';diagnoses=[];findings=[];materials=[]
    source_hashes={};documents=[];source_files={};scope_receipts=[];admitted=frozenset();index=None
    nfiles=nread=nparsed=nerrors=0;complete=True;calls=0;cancelled=False;store_exhausted=False;halt_reason=None
    phase_times={};view_digest=canonical_digest('retrieval-view-v1',[])
    def diagnose(stage,reason,owner='analyzer'):
        diagnoses.append(Diagnosis(stage=stage,reason_code=reason,message=reason,owner=owner,retry_policy='manual'))
    def progress(event):
        with (private/'progress.jsonl').open('a',encoding='utf-8')as f:
            os.fchmod(f.fileno(),0o600);f.write(_json(event)+'\n');f.flush();os.fsync(f.fileno())
    check=preflight(source_root)
    if not check.ready:
        state='BLOCKED';complete=False;diagnoses.extend(check.diagnoses)
    else:
        t=time.monotonic()
        try:
            snapshot=freeze_source_snapshot(source_root,exclude_dirs=EXCLUDED,max_files=policy.max_files,
                max_source_bytes=policy.max_source_bytes,max_ast_nodes=policy.max_ast_nodes)
            source_hashes=snapshot.file_hashes;nfiles=snapshot.enumerated_files;nread=snapshot.read_files
            complete=snapshot.inventory_complete
            if not complete:state='PARTIAL';diagnose('index',snapshot.resource_reason or'inventory_incomplete')
            discovery=discover_python_repository(source_root,'authorized-local-source',snapshot=snapshot)
            index=discovery.index;documents=[index.documents[p].model_dump(mode='json')for p in sorted(index.documents)]
            candidates=discover_operations(snapshot,discovery)
            nparsed=discovery.report['parsed_files'];nerrors=len(discovery.report['parse_errors'])
            if nerrors:state='PARTIAL';diagnose('index','source_parse_or_read_error')
            source_files={p:{'sha256':e.sha256,'encoding':e.encoding,'raw':None if e.raw is None
                else base64.b64encode(e.raw).decode(),'error_type':e.error_type,'error_stage':e.error_stage}
                for p,e in snapshot.files.items()}
            source_view=SourceReadView(source_root,source_hashes,byte_budget=context_bytes,snapshot=snapshot)
            manifest=None if context_manifest is None else ContextManifest.model_validate(context_manifest)
            grants=([ReadGrant(path=p,start_line=1,end_line=max(1,len(e.text.splitlines())),reason='explicit authorized root')
                     for p,e in snapshot.files.items()if e.text is not None and e.error_type is None]
                    if manifest is None else manifest.initial)
            for extension,items in ((False,grants),(True,()if manifest is None else manifest.extensions)):
                for g in items:
                    try:source_view.extend(g)if extension else source_view.admit(g)
                    except (OSError,ValueError):state='PARTIAL';diagnose('input','context_grant_rejected','user')
            def covers(doc):
                m=re.search(r'@(\d+)-(\d+)$',doc.path)
                return source_view.covers(doc.path.split('::',1)[0],int(m[1]),int(m[2]))
            admitted=frozenset(p for p,d in index.documents.items()if covers(d));view_digest=source_view.revision
            scope_receipts=[r.model_dump(mode='json')for r in source_view.receipts]
        except KeyboardInterrupt:
            cancelled=True;state='CANCELLED';candidates=();diagnose('index','review_cancelled','user')
        except MemoryError:raise
        except (OSError,ValueError,SyntaxError)as error:
            state='BLOCKED';candidates=();diagnose('index','snapshot_or_context_invalid','user')
            progress({'phase':'index','error_type':type(error).__name__})
        phase_times['source_index_seconds']=time.monotonic()-t
        t=time.monotonic()
        admitted_digest=canonical_digest('analysis-path-view-v2',sorted(admitted))
        for ordinal,candidate in enumerate(candidates):
            subject=candidate_subject(index,candidate);observation=None;descriptor=None
            analysis='NOT_STARTED';persist='NOT_ATTEMPTED';verification='UNAVAILABLE';refs=[];producer=run_id+f'/static/{ordinal+1}'
            if cancelled:reason='review_cancelled'
            elif store_exhausted:reason='LOCAL_RECORD_LIMIT';state='PARTIAL'
            elif halt_reason is not None:reason=halt_reason;state='PARTIAL'
            elif ordinal>=policy.max_candidates:reason='CANDIDATE_LIMIT';state='PARTIAL'
            elif time.monotonic()-started>=policy.wall_seconds:reason='ANALYSIS_WALL_LIMIT';state='PARTIAL'
            elif candidate.path not in admitted:analysis='BLOCKED';reason='candidate_span_not_admitted';state='PARTIAL'
            else:
                reason=None;calls+=1
                try:
                    observation=analyze_operation(index,candidate,admitted,producer)
                    analysis='COMPLETED'if observation.status=='ok'else'BLOCKED'
                except KeyboardInterrupt:
                    cancelled=True;state='CANCELLED';reason='review_cancelled'
                except MemoryError:raise
                except Exception as error:
                    analysis='FAILED';state='PARTIAL';reason='static_internal_error'
                    halt_reason='stopped_after_internal_error'
                    progress({'phase':'analysis','candidate_id':candidate.candidate_id,'error_type':type(error).__name__})
                if observation is not None:
                    context={'source_digest':snapshot.source_digest,'view_digest':view_digest,
                        'candidate':candidate.model_dump(mode='json'),'admitted_paths_digest':admitted_digest}
                    try:
                        descriptor=store.persist(producer,observation,context=context)
                        read_descriptor(descriptor,context=context,max_bytes=policy.max_record_bytes)
                        persist='COMPLETE';verification='VERIFIED';refs=[Path(descriptor['path']).name]
                    except LocalEvidenceBudgetError:
                        store_exhausted=True;persist='FAILED';verification='INCOMPLETE';state='PARTIAL';reason='LOCAL_RECORD_LIMIT'
                    except (OSError,LocalEvidenceError):
                        descriptor=None
                        persist='FAILED';verification='INCOMPLETE';state='PARTIAL';reason='local_evidence_not_persisted'
                        halt_reason='stopped_after_persistence_error'
            if reason:diagnose('analysis',reason,'user'if reason=='candidate_span_not_admitted'else'analyzer')
            pairs=()if descriptor is None else((producer,observation),)
            finding,_=reduce_observations(subject,pairs)
            # Unknown scope facts retain producer's original status in private records.
            if observation is not None and observation.status!='ok':state='PARTIAL'
            if reason:
                finding=finding.model_copy(update={'missing_obligations':(*finding.missing_obligations,reason)})
            findings.append(LocalFinding(**finding.model_dump(),operation_locator=candidate.metadata['operation_locator'],
                display_class='BOUNDED_PROPERTY'if finding.property_state!='UNKNOWN'else
                    'NEEDS_INPUT'if candidate.property_id in PROPERTY_TO_TOOL else'REVIEW_LEAD',
                analysis_state=analysis,persistence_state=persist,local_verification=verification,
                review_action=_action(candidate.property_id,finding.property_state),record_refs=tuple(refs),
                producer_ids=(producer,)if observation is not None else()))
            materials.append({'candidate':candidate.model_dump(mode='json'),
                'descriptor':None if descriptor is None else{**descriptor,'path':Path(descriptor['path']).name},
                'producer_id':producer,'analysis_state':analysis,'persistence_state':persist})
            progress({'phase':'analysis','candidate_id':candidate.candidate_id,'analysis_state':analysis,
                      'persistence_state':persist})
        phase_times['analysis_persistence_seconds']=time.monotonic()-t
    states=Counter(f.property_state for f in findings);analysis_states=Counter(f.analysis_state for f in findings)
    counts=ReviewCountsV2(source_files_enumerated=nfiles,source_files_read=nread,parsed_files=nparsed,
        parse_errors=nerrors,inventory_complete=complete,candidate_total=len(findings),
        **{'analysis_'+s.lower():analysis_states[s]for s in ('NOT_STARTED','COMPLETED','BLOCKED','FAILED')},
        evidence_persisted_candidates=sum(f.persistence_state=='COMPLETE'for f in findings),
        supported=states['SUPPORTED'],refuted=states['REFUTED'],unknown=states['UNKNOWN'],conflict=states['CONFLICT'],
        has_sufficient_evidence=states['SUPPORTED']+states['REFUTED']+states['CONFLICT'],
        resolved_without_conflict=states['SUPPORTED']+states['REFUTED'])
    result=ReviewResultV2(run_id=run_id,run_state=state,findings=tuple(findings),counts=counts,diagnoses=tuple(diagnoses),
        identity=ProductIdentityV2(source_digest=source_digest(source_hashes),semantic_engine_digest=frozen_semantic_digest,
            retrieval_view_revision=view_digest,delivery_policy_digest=canonical_digest('delivery-policy-v2',{'summary_bytes':summary_bytes})),
        resource_limits=policy,accounting={'model_requests':0,'target_executions':0,
            'analysis_tool_attempts':calls,'verification_tool_attempts':sum(m['descriptor']is not None for m in materials),
            'tool_calls':calls+sum(m['descriptor']is not None for m in materials),
            'source_bytes':sum(len(base64.b64decode(v['raw']))for v in source_files.values()if v['raw']is not None),
            'record_bytes':store.used_bytes,'phase_seconds':phase_times,'total_seconds':time.monotonic()-started},
        scope_admissions=tuple(scope_receipts),artifacts={'result':'result.json','report':'report.md',
            'share':'share.json','private_manifest':'.private/material_manifest.json'})
    try:
        _write(private/'sources.json',{'files':source_files,'hashes':source_hashes,'documents':documents})
        _write(private/'material_manifest.json',{'version':'local-material-manifest-v2','identity':result.identity.model_dump(mode='json'),
            'admitted_paths':sorted(admitted),'materials':materials,
            'complete':all(m['persistence_state']!='FAILED'for m in materials)})
        _write(staging/'result.json',result.model_dump(mode='json'))
        with (staging/'report.md').open('w',encoding='utf-8')as f:
            f.write(render_local_report(result));f.flush();os.fsync(f.fileno())
        _write(staging/'share.json',project_share(result,summary_bytes))
        _write(staging/'manifest.json',{'version':'local-package-manifest-v2','run_id':run_id,
            'files':{p.relative_to(staging).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(staging.rglob('*'))if p.is_file()}})
    except (OSError,ValueError,TypeError)as error:
        raise ProductDeliveryError('LOCAL_PACKAGE_PREPARATION_FAILED')from error
    if not verify_bundle(staging)['valid']:
        raise ProductDeliveryError('GENERATED_LOCAL_PACKAGE_INVALID')
    try:
        commit_directory(staging,output)
    except FileExistsError as error:
        raise ProductDeliveryError('OUTPUT_ALREADY_EXISTS')from error
    except OSError as error:
        raise ProductDeliveryError('LOCAL_PACKAGE_COMMIT_FAILED')from error
    try:_write(output/'.private/completion.json',{'authoritative':False,'run_id':run_id,'output_complete_seconds':time.monotonic()-started})
    except OSError:pass
    return result


def verify_bundle(output:Path):
    """Read-only consistency and registered static replay, not external authentication."""
    output=Path(output)
    try:
        manifest=json.loads((output/'manifest.json').read_text())
        if manifest['version']!='local-package-manifest-v2':raise ValueError('Unknown manifest')
        for path,digest in manifest['files'].items():
            p=Path(path)
            if p.is_absolute()or'..'in p.parts or(output/p).is_symlink():raise ValueError('Manifest path escape')
            if hashlib.sha256((output/p).read_bytes()).hexdigest()!=digest:raise ValueError('Package file missing or tampered')
        mandatory={'result.json','report.md','share.json','.private/sources.json','.private/material_manifest.json'}
        if not mandatory<=manifest['files'].keys():raise ValueError('Missing required package files')
        result=ReviewResultV2.model_validate_json((output/'result.json').read_text())
        sources=json.loads((output/'.private/sources.json').read_text())
        hashes={p:None if e['raw']is None else hashlib.sha256(base64.b64decode(e['raw'],validate=True)).hexdigest()
                for p,e in sources['files'].items()}
        if hashes!=sources['hashes']or source_digest(hashes)!=result.identity.source_digest:raise ValueError('Source identity mismatch')
        derived=derive_packaged_documents(sources['files'])
        if [d.model_dump(mode='json')for d in derived]!=sources['documents']:
            raise ValueError('Syntax metadata is not derived from the sealed source bytes')
        index=FrozenRepositoryIndex(derived)
        expected_candidates=derive_packaged_operations(sources['files'],hashes,index)
        # Every analyzed slice is derived from the packaged raw file bytes.
        import io,tokenize
        for d in index.documents.values():
            raw=base64.b64decode(sources['files'][d.path.split('::',1)[0]]['raw'],validate=True)
            encoding,_=tokenize.detect_encoding(io.BytesIO(raw).readline);text=raw.decode(encoding)
            first,last=map(int,re.search(r'@(\d+)-(\d+)$',d.path).groups())
            if d.text!=''.join(text.splitlines(keepends=True)[first-1:last]):raise ValueError('Index is not derived from sealed bytes')
        if result.identity.semantic_engine_digest!=semantic_digest(result.resource_limits):raise ValueError('Analyzer version drift')
        materials=json.loads((output/'.private/material_manifest.json').read_text())
        if materials['identity']!=result.identity.model_dump(mode='json'):raise ValueError('Material identity mismatch')
        if len(materials['materials'])!=len(result.findings):raise ValueError('Material inventory mismatch')
        if [c.model_dump(mode='json')for c in expected_candidates]!=[m['candidate']for m in materials['materials']]:
            raise ValueError('Operation inventory differs from the sealed source bytes')
        parsed_files=len({d.path.split('::',1)[0]for d in derived})
        if (result.counts.source_files_enumerated!=len(hashes)
                or result.counts.source_files_read!=sum(h is not None for h in hashes.values())
                or result.counts.parsed_files!=parsed_files
                or result.counts.parse_errors!=len(hashes)-parsed_files):
            raise ValueError('Source-stage denominators differ from the packaged inventory')
        if result.counts.inventory_complete and any(e.get('error_stage')=='limit'for e in sources['files'].values()):
            raise ValueError('A resource-limited source inventory cannot be complete')
        admitted=frozenset(materials['admitted_paths'])
        if not admitted<=index.documents.keys():raise ValueError('Analysis view contains unknown documents')
        admitted_digest=canonical_digest('analysis-path-view-v2',sorted(admitted))
        for material,finding in zip(materials['materials'],result.findings,strict=True):
            candidate=Candidate.model_validate(material['candidate']);subject=candidate_subject(index,candidate)
            loc=candidate.metadata['operation_locator']
            if loc['file_sha256']!=hashes[loc['source_path']]or loc['source_digest']!=result.identity.source_digest:
                raise ValueError('Operation does not bind the packaged raw bytes')
            expected_id='operation-'+canonical_digest('source-operation-id-v2',{
                'repository_id':candidate.repository_id,'rule':candidate.metadata['rule'],**loc})[:32]
            if candidate.candidate_id!=expected_id or candidate.case_id!=expected_id or candidate.line!=loc['start_line']:
                raise ValueError('Operation identity differs from its exact source locator')
            if subject!=finding.subject or candidate.metadata['operation_locator']!=finding.operation_locator:raise ValueError('Exact candidate/subject mismatch')
            descriptor=material['descriptor']
            if descriptor is None:
                if finding.property_state!='UNKNOWN'or finding.record_refs:raise ValueError('Strong finding without evidence')
                continue
            if descriptor['path']not in finding.record_refs or descriptor['producer_id']not in finding.producer_ids:raise ValueError('Missing record reference')
            if '.private/evidence/'+descriptor['path']not in manifest['files']:raise ValueError('Record omitted from manifest')
            producer,observation=read_descriptor(descriptor,directory=output/'.private/evidence',
                max_bytes=result.resource_limits.max_record_bytes)
            context=descriptor['context']
            if context['source_digest']!=result.identity.source_digest or context['view_digest']!=result.identity.retrieval_view_revision \
                    or context['candidate']!=material['candidate'] or context['admitted_paths_digest']!=admitted_digest:
                raise ValueError('Evidence context mismatch')
            replay=analyze_operation(index,candidate,admitted,producer)
            if replay.model_dump(mode='json')!=observation.model_dump(mode='json'):raise ValueError('Untrusted record differs from registered static producer')
            reduced,_=reduce_observations(subject,((producer,observation),))
            if reduced.property_state!=finding.property_state or reduced.evidence_refs!=finding.evidence_refs:
                raise ValueError('Local state differs from complete original evidence')
        return {'valid':True,'run_id':result.run_id,'run_state':result.run_state,
                'scope':'USER_OWNED_SELF_GENERATED_PACKAGE','external_origin_authenticated':False,
                'model_requests':0,'target_executions':0}
    except (OSError,ValueError,TypeError,KeyError,LocalEvidenceError)as error:
        return {'valid':False,'reason_code':'local_package_invalid','error_type':type(error).__name__,
                'model_requests':0,'target_executions':0}


def view_finding(output:Path,candidate_id:str,source_root:Path):
    if not verify_bundle(output)['valid']:raise ValueError('Local package cannot be verified')
    result=ReviewResultV2.model_validate_json((Path(output)/'result.json').read_text())
    selected=next((f for f in result.findings if f.candidate_id==candidate_id),None)
    if selected is None:raise ValueError('Unknown exact candidate')
    limits=result.resource_limits
    snapshot=freeze_source_snapshot(source_root,exclude_dirs=EXCLUDED,max_files=limits.max_files,
        max_source_bytes=limits.max_source_bytes,max_ast_nodes=limits.max_ast_nodes)
    if snapshot.source_digest!=result.identity.source_digest:raise ValueError('SOURCE_DRIFT: selected source no longer matches')
    loc=selected.operation_locator;entry=snapshot.files[loc['source_path']]
    tree=ast.parse(entry.text)
    node=next((n for n in ast.walk(tree)if isinstance(n,ast.Call)and(n.lineno,n.end_lineno,n.col_offset,n.end_col_offset)==
        (loc['start_line'],loc['end_line'],loc['start_col_utf8'],loc['end_col_utf8'])),None)
    if node is None:raise ValueError('SOURCE_DRIFT: exact operation is unavailable')
    return {'candidate_id':candidate_id,'source':ast.get_source_segment(entry.text,node),
            'operation_locator':loc,'source_digest':snapshot.source_digest,'view_scope':'LOCAL_ONLY'}
