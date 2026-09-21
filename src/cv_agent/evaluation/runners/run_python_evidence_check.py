"""Bounded live check of actual Python validator evidence; synthetic, not a benchmark claim."""
from dataclasses import asdict
import json
import os
from uuid import uuid4

from cv_agent.evaluation.runners.run_micro_benchmark import BENCHMARK_CASES, build_case_harness, load_default_model_config
from cv_agent.runtime.paths import PROJECT_ROOT as project_root
from cv_agent.runtime.journal import utc_now
from cv_agent.runtime.budget import Budget, BudgetExceeded
from cv_agent.runtime.journal import Journal
from cv_agent.evaluation.runners.run_development_benchmark import run_candidate, summarize
from cv_agent.runtime.snapshots import snapshot_sources
from cv_agent.harness import AgentSystemVersion


def main():
    if not os.environ.get('ANTIGRAVITY_API_KEY'):
        raise ValueError('ANTIGRAVITY_API_KEY is required')
    model_config = load_default_model_config(project_root)
    cases=BENCHMARK_CASES[:2]
    manifest=dict(dataset_name='Python 手写用例验证工具检查',systems=['E3','E4','E5'],
        sampling_note='两个手写 Python 用例，仅检查工具证据链，不是公开基准或效果评测。',
        labels={case.case_id:dict(vulnerable=case.ground_truth=='VULNERABLE',category='synthetic-python-eval')
                for case in cases})
    directory=project_root/'artifacts/python_evidence_check'/uuid4().hex
    directory.mkdir(parents=True)
    (directory/'metadata.json').write_text(json.dumps(dict(
        started_at=utc_now(),purpose='Synthetic validator integration; not independent efficacy evaluation',
        config=model_config,manifest=manifest,cases=[asdict(case) for case in cases],
        source_sha256=snapshot_sources(project_root, directory),limits=dict(requests=60,seconds=900)),indent=2)+'\n')
    journal=Journal(directory/'events.jsonl')
    journal.write({'event':'run_start'})
    budget=Budget(60,900)
    print(f'Run directory: {directory}',flush=True)
    try:
        for system in manifest['systems']:
            for case in cases:
                budget.check()
                index,candidate=build_case_harness(case)
                result=run_candidate(index,candidate,AgentSystemVersion(system),journal,budget,model_config=model_config)
                summarize(directory,manifest,[item.case_id for item in cases])
                print(f"{case.case_id}/{system}: {result['status']} {result['predicted_label']} "
                      f"requests={result['model_calls']} {result.get('error','')}",flush=True)
    except BudgetExceeded as error:
        journal.write({'event':'budget_stop','error':str(error)})
    finally:
        summarize(directory,manifest,[item.case_id for item in cases])


if __name__=='__main__':
    main()
