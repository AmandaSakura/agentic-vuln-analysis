"""Bounded exploratory comparison with shared BM25 scorer and source metadata."""
import json
import os
from uuid import uuid4

from cv_agent.runtime.paths import PROJECT_ROOT as project_root
from cv_agent.runtime.journal import utc_now, Journal
from cv_agent.runtime.budget import Budget, BudgetExceeded
from cv_agent.evaluation.runners.run_development_benchmark import run_candidate, summarize
from cv_agent.runtime.snapshots import snapshot_sources
from cv_agent.evaluation.datasets.owasp_live import load_owasp_agentic_inputs
from cv_agent.harness import AgentSystemVersion
from cv_agent.retrieval.bm25 import MetadataBM25Index
from cv_agent.runtime.provenance import build_run_identity
from cv_agent.evaluation.runners.run_micro_benchmark import load_default_model_config


def main():
    if not os.environ.get('ANTIGRAVITY_API_KEY'):
        raise ValueError('ANTIGRAVITY_API_KEY is required')
    model_config = load_default_model_config(project_root)
    config=json.loads((project_root/'configs/experiments/retrieval_validation_matrix.json').read_text())
    frozen=json.loads((project_root/'configs/datasets/development_manifest.json').read_text())
    identity=build_run_identity(project_root,{'BenchmarkJava':project_root/'data/raw/BenchmarkJava'})
    if identity['datasets']!=frozen['identity']['datasets']:
        raise ValueError('Dataset differs from frozen manifest')
    ids=[next(case for case in frozen['case_ids']
              if frozen['labels'][case]['category']==category
              and frozen['labels'][case]['vulnerable']==vulnerable)
         for category in config['categories'] for vulnerable in (False,True)]
    manifest={**frozen,'dataset_name':'OWASP 强文本基线与图检索开发对照',
              'systems':[item[0] for item in config['variants']],
              'comparisons':[[item[0] for item in config['variants']]],
              'sampling_note':'固定清单中的四类正负用例；两组共享源码元信息、BM25评分器和上下文预算，仅改变检索邻域。属于探索性开发评测。'}
    inputs=load_owasp_agentic_inputs(project_root/'data/raw',case_ids=ids)
    index=MetadataBM25Index(inputs.index.documents.values())
    directory=project_root/'artifacts/retrieval_validation_matrix'/uuid4().hex
    directory.mkdir(parents=True)
    (directory/'metadata.json').write_text(json.dumps(dict(started_at=utc_now(),config=config,
        model_config=model_config,manifest=manifest,case_ids=ids,identity=identity,
        source_sha256=snapshot_sources(project_root, directory)),indent=2)+'\n')
    journal=Journal(directory/'events.jsonl')
    journal.write({'event':'run_start'})
    budget=Budget(config['max_requests'],config['max_seconds'])
    print(f'Run directory: {directory}',flush=True)
    try:
        for position,candidate in enumerate(inputs.candidates):
            variants=config['variants'] if position%2==0 else list(reversed(config['variants']))
            for name,system in variants:
                budget.check()
                result=run_candidate(index,candidate,AgentSystemVersion(system),journal,budget,report_system=name,model_config=model_config)
                summarize(directory,manifest,ids)
                print(f"{candidate.case_id}/{name}: {result['status']} {result['predicted_label']} "
                      f"calls={result['model_calls']} {result.get('error','')}",flush=True)
    except BudgetExceeded as error:
        journal.write({'event':'budget_stop','error':str(error)})
    finally:
        summarize(directory,manifest,ids)


if __name__=='__main__':
    main()
