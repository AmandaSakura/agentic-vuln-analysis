"""Run the frozen OWASP development matrix with durable evidence and limits."""
import json
import os
import signal
from uuid import uuid4

from cv_agent.evaluation.runners.run_micro_benchmark import load_default_model_config
from cv_agent.runtime.paths import PROJECT_ROOT as project_root
from cv_agent.runtime.journal import Journal, Trial, RecordedTools, utc_now
from cv_agent.evaluation.datasets.owasp_live import load_owasp_agentic_inputs, select_owasp_entry
from cv_agent.evaluation.protocols.development import require_development_acceptance
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.evaluation.metrics import metrics, paired, replay_fast_prefix, provider_usage
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentSystemVersion
from cv_agent.evaluation.datasets.java_fixture import java_command_fixture_cases
from cv_agent.runtime.model import OpenAICompatibleChatModel
from cv_agent.runtime.provenance import build_run_identity
from cv_agent.retrieval.bm25 import MetadataBM25Index
from cv_agent.runtime.budget import Budget, BudgetExceeded, BudgetStopped, LockedBudget, execute_trials
from cv_agent.evaluation.execution import run_candidate as _run_candidate
from cv_agent.runtime.journal import LockedJournal
from cv_agent.runtime.snapshots import snapshot_sources as _snapshot_sources
from cv_agent.tools.validation import full_agent_tools


def run_candidate(index, candidate, system, journal, budget, report_system=None, model_config=None, registered_tools=None, api_key=None, graph_direction="forward", graph_ranking="lexical"):
    """Preserve the historical script API and its default model configuration."""
    return _run_candidate(
        index, candidate, system, journal, budget, report_system,
        model_config=load_default_model_config(project_root) if model_config is None else model_config,
        registered_tools=registered_tools, api_key=api_key,
        graph_direction=graph_direction, graph_ranking=graph_ranking,
    )


def summarize(run_dir, manifest, case_ids):
    events = [json.loads(line) for line in (run_dir/'events.jsonl').read_text().splitlines()]
    observed = {(event['result']['case_id'], event['result']['system']): event['result']
                for event in events if event['event'] == 'trial_result'}
    rows = []
    for case_id in case_ids:
        for system in manifest['systems']:
            row = dict(observed.get((case_id, system), dict(
                case_id=case_id, system=system, status='not_run', predicted_label=None,
                model_calls=0, tool_calls=0, latency_sec=0, verdict=None)))
            row['ground_truth'] = ('VULNERABLE' if manifest['labels'][case_id]['vulnerable'] else 'SAFE')
            row['category'] = manifest['labels'][case_id]['category']
            rows.append(row)
    summary = {
        'claim_eligible': False, 'dataset_role': 'development',
        'systems': {system: metrics([row for row in rows if row['system'] == system])
                    for system in manifest['systems']},
        'categories': {category: {
            system: metrics([row for row in rows if row['system'] == system
                             and row['category'] == category])
            for system in manifest['systems']}
            for category in sorted({row['category'] for row in rows})},
        'paired': {f'{left}_vs_{right}': paired(rows, left, right)
                   for left, right in manifest.get('comparisons',[('E2', 'E3'), ('E3', 'E4'), ('E4', 'E5')])
                   if left in manifest['systems'] and right in manifest['systems']},
        'failure_details': [{key: row.get(key) for key in
                            ('case_id', 'system', 'status', 'error_type', 'error')}
                           for row in rows if row['status'] in {'failed', 'interrupted'}],
        'full_review_prefix_replays': {
            row['case_id']: replay_fast_prefix(row['verdict']) for row in rows
            if row['system']=='E4' and row.get('verdict') is not None},
    }
    summary['usage'] = provider_usage(events)
    for name, payload in [('results.json', rows), ('summary.json', summary)]:
        temporary = run_dir/(name+'.tmp')
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2)+'\n')
        temporary.replace(run_dir/name)
    lines = ['# '+manifest.get('dataset_name','OWASP 开发评测'), '',
             manifest.get('sampling_note','固定分层样本；不是未见测试集，不证明真实项目泛化或历史提升百分比。'),
             '未运行、失败、弃权均保留在总体分母中；类别平衡抽样不代表实际漏洞分布。',
             'E2/E3 使用相同 Harness 预算。E3/E4 是规划与多专家的组合差异。',
             'E4/E5 独立运行；标签不一致时禁止宣称等价提前退出。调用差异是观测值，不能直接解释为因果节省。',
             'Wilson 区间仅描述当前样本，不校正同源模板依赖，不是跨项目置信区间。', '',
             '|系统|TP|FP|TN|FN|弃权|失败|中断|未运行|覆盖率|严格召回|总体FPR|请求|',
             '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for system, value in summary['systems'].items():
        fields = [value[key] for key in ('tp','fp','tn','fn','abstained','failed','interrupted',
                                         'not_run','coverage','strict_recall','population_fpr','model_requests')]
        lines.append('|'+system+'|'+'|'.join(str(field) for field in fields)+'|')
    lines.extend(['', '失败详情、类别指标、配对胜负、区间及用量见 summary.json；完整证据见 events.jsonl。',
                  '无法获取服务价格时费用为未知，不声称免费。'])
    (run_dir/'report.md').write_text('\n'.join(lines)+'\n')
    return summary


def snapshot_sources(run_dir):
    return _snapshot_sources(project_root, run_dir)


def run(pilot, positive_check=False, graph_check=False, lexical_check=False, fast_check=False):
    if not os.environ.get('ANTIGRAVITY_API_KEY'):
        raise ValueError('ANTIGRAVITY_API_KEY is required')
    manifest = json.loads((project_root/'configs/datasets/development_manifest.json').read_text())
    config = json.loads((project_root/'configs/experiments/development_benchmark.json').read_text())
    if not pilot:
        require_development_acceptance(project_root, config, manifest)
    model_config = load_default_model_config(project_root) if pilot else json.loads((project_root / config['model_config']).read_text())
    ids = manifest['pilot_case_ids'] if pilot else manifest['case_ids']
    if positive_check:
        ids = [case for case in manifest['pilot_case_ids']
               if manifest['labels'][case]['vulnerable']]
        manifest = {**manifest, 'systems': ['E1']}
    if graph_check:
        manifest = {**manifest, 'systems': ['E3', 'E4', 'E5']}
    if lexical_check:
        manifest = {**manifest, 'systems': ['E2_metadata_bm25']}
    if fast_check:
        ids = [case for case in manifest['pilot_case_ids'] if manifest['labels'][case]['vulnerable']]
        manifest = {**manifest, 'systems': ['E5']}
    identity = build_run_identity(project_root, {'BenchmarkJava': project_root/'data/raw/BenchmarkJava'})
    if identity['datasets'] != manifest['identity']['datasets']:
        raise ValueError('Dataset checkout differs from frozen manifest')
    inputs = load_owasp_agentic_inputs(project_root/'data/raw', case_ids=ids)
    candidates = inputs.candidates if pilot else select_owasp_entry(inputs, config['entry_method'])
    index = MetadataBM25Index(inputs.index.documents.values()) if lexical_check else inputs.index
    fixture_cases = (
        java_command_fixture_cases(project_root, index, candidates)
        if not pilot and config['entry_method'] == 'doPost'
        else ()
    )
    registered_tools = full_agent_tools(index, fixture_cases=fixture_cases)
    run_dir = project_root/'artifacts/development_benchmark'/uuid4().hex
    run_dir.mkdir(parents=True)
    source_hashes = snapshot_sources(run_dir)
    metadata = dict(started_at=utc_now(), pilot=pilot, positive_check=positive_check,
                    graph_check=graph_check,
                    fast_check=fast_check,
                    retrieval_variant='metadata_bm25' if lexical_check else 'original',
                    case_ids=ids, config=model_config, concurrency=1 if pilot else config['concurrency'],
                    entry_method='doGet' if pilot else config['entry_method'],
                    fixture_case_ids=[case.case_id for case in fixture_cases],
                    manifest=manifest, identity=identity,
                    source_sha256=source_hashes,
                    limits=dict(requests=20 if fast_check else 8 if positive_check else 16 if lexical_check else 60 if graph_check else config['pilot_max_model_requests'] if pilot else 6600,
                                seconds=180 if positive_check else 900 if graph_check else config['pilot_wall_seconds'] if pilot else 86400))
    (run_dir/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
    journal = LockedJournal(run_dir/'events.jsonl')
    journal.write({'event':'run_start'})
    print(f'Run directory: {run_dir}', flush=True)
    budget = LockedBudget(**metadata['limits'])
    def execute(task):
        name, candidate = task
        budget.check()
        system = AgentSystemVersion.E2_TEXT_SINGLE if lexical_check else AgentSystemVersion(name)
        return run_candidate(index, candidate, system, journal, budget, report_system=name,
                             model_config=model_config, registered_tools=registered_tools)
    def progress(row):
        with journal.lock:
            summarize(run_dir, manifest, ids)
        print(f"{row['case_id']}/{row['system']}: {row['status']}: {row['predicted_label']}; "
              f"calls={row['model_calls']}; error={row.get('error_type', '')}", flush=True)
    def interrupt(signum, frame):
        raise KeyboardInterrupt('Experiment stop requested')
    previous_handler = signal.signal(signal.SIGTERM, interrupt)
    try:
        execute_trials([(name, candidate) for name in manifest['systems'] for candidate in candidates],
                       execute, budget, progress, metadata['concurrency'])
    except BudgetExceeded as error:
        journal.write({'event':'budget_stop', 'error':str(error)})
        print(str(error), flush=True)
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
        summarize(run_dir, manifest, ids)
    return run_dir


if __name__ == '__main__':
    run(pilot=False)
