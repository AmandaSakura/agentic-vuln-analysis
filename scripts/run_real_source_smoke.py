"""Candidate-level live wiring on real development code; no reference-label scoring."""
import hashlib
import json
import os
from uuid import uuid4

from run_development_benchmark import (
    project_root,CONFIG,utc_now,Journal,Budget,BudgetExceeded,run_candidate,snapshot_sources,AgentSystemVersion)
from cv_agent.code_adapters import load_code_repository
from cv_agent.retrieval import RepositoryIndex
from cv_agent.scanner import StaticScanner
from cv_agent.vulngym_subset import select_vulngym_subjects
from cv_agent.provenance import git_identity
from cv_agent.benchmark_evaluation import provider_usage


def save(directory):
    events=[json.loads(line) for line in (directory/'events.jsonl').read_text().splitlines()]
    results=[event['result'] for event in events if event['event']=='trial_result']
    payload=dict(purpose='Real development-source integration, no reference labels or accuracy metric',
        claim_eligible=False,results=results,
        usage=provider_usage(events))
    temporary=directory/'results.json.tmp'
    temporary.write_text(json.dumps(payload,indent=2)+'\n')
    temporary.replace(directory/'results.json')


def main(config_path='configs/real_source_smoke.json'):
    if not os.environ.get('ANTIGRAVITY_API_KEY'):
        raise ValueError('ANTIGRAVITY_API_KEY is required')
    config=json.loads((project_root/config_path).read_text())
    model_config=json.loads((project_root/config['model_config']).read_text())
    directory=project_root/'artifacts/real_source_smoke'/uuid4().hex
    directory.mkdir(parents=True)
    metadata=dict(started_at=utc_now(),config=config,model_config=model_config,subjects=[],
                  source_sha256=snapshot_sources(directory),claim_eligible=False)
    journal=Journal(directory/'events.jsonl')
    journal.write({'event':'run_start'})
    budget=Budget(config['max_requests'],config['max_seconds'])
    print(f'Run directory: {directory}',flush=True)
    try:
        for subject in select_vulngym_subjects(project_root/'data/raw/VulnGym/data/entries.jsonl'):
            if subject.repository_url not in config['repositories']:
                continue
            checkout=project_root/'data/subjects'/subject.slug/subject.commit
            identity=git_identity(checkout)
            if identity.revision!=subject.commit or identity.dirty:
                raise ValueError('Real-source check requires an unchanged pinned checkout')
            repository=load_code_repository(subject.repository_url,checkout)
            documents=[doc for doc in repository.documents if doc.path.startswith(config['source_prefix'])]
            candidates=StaticScanner().scan(subject.repository_url,documents)
            if not candidates:
                raise ValueError(f'No source-only scanner candidates in {subject.repository_url}')
            candidate=min(candidates,key=lambda item:hashlib.sha256(
                (config['selection_seed']+item.candidate_id).encode()).hexdigest())
            metadata['subjects'].append(dict(repository=subject.repository_url,
                identity=identity.model_dump(mode='json'),source_documents=len(documents),
                candidate_count=len(candidates),selected_candidate=candidate.model_dump(mode='json'),
                parse_error_paths=list(repository.parse_error_paths)))
            (directory/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
            index=RepositoryIndex(documents)
            for system in config['systems']:
                budget.check()
                result=run_candidate(index,candidate,AgentSystemVersion(system),journal,budget,model_config=model_config)
                save(directory)
                print(f"{subject.slug}/{system}: {result['status']} {result['predicted_label']} "
                      f"calls={result['model_calls']} {result.get('error','')}",flush=True)
    except BudgetExceeded as error:
        journal.write({'event':'budget_stop','error':str(error)})
    finally:
        save(directory)


if __name__=='__main__':
    main()
