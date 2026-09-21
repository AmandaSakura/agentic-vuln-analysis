"""Run the frozen OWASP development matrix with durable evidence and limits."""
import json
import os
import hashlib
from pathlib import Path
import time
import signal
from threading import Event, RLock
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from uuid import uuid4

from run_micro_benchmark import CONFIG, Journal, Trial, RecordedTools, project_root, utc_now
from cv_agent.agentic_live import load_owasp_agentic_inputs, select_owasp_entry
from cv_agent.experiment_acceptance import require_development_acceptance
from cv_agent.agentic_workflow import AgenticPipeline
from cv_agent.benchmark_evaluation import metrics, paired, replay_fast_prefix, provider_usage
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentSystemVersion
from cv_agent.java_fixture import java_command_fixture_cases
from cv_agent.model_runtime import OpenAICompatibleChatModel
from cv_agent.provenance import build_run_identity
from cv_agent.lexical_baseline import MetadataBM25Index
from cv_agent.live_gate import fingerprint_files
from cv_agent.validation_tools import full_agent_tools


class BudgetExceeded(RuntimeError):
    pass


class BudgetStopped(BudgetExceeded):
    pass


class Budget:
    def __init__(self, requests, seconds):
        self.limit = requests
        self.used = 0
        self.deadline = time.monotonic() + seconds
        self.cancelled = Event()

    def check(self):
        if self.cancelled.is_set():
            raise BudgetStopped('Experiment stopped; no further requests admitted')
        if self.used >= self.limit or time.monotonic() >= self.deadline:
            raise BudgetExceeded('Predeclared request or wall-time limit reached')

    def stop(self):
        self.cancelled.set()

    def observer(self, trial, role):
        def record(event):
            if event['event'] == 'model_start':
                self.check()
                self.used += 1
            trial.record({'role': role, **event})
        return record


class LockedBudget(Budget):
    def __init__(self, requests, seconds):
        super().__init__(requests, seconds)
        self.lock = RLock()

    def observer(self, trial, role):
        record = super().observer(trial, role)
        def observe(event):
            with self.lock:
                record(event)
        return observe

    def stop(self):
        with self.lock:
            super().stop()


class LockedJournal(Journal):
    def __init__(self, path):
        super().__init__(path)
        self.lock = RLock()

    def write(self, event):
        with self.lock:
            super().write(event)


def execute_trials(tasks, worker, budget, progress, concurrency):
    """Only active slots are submitted; stop closes admission before joining."""
    iterator = iter(tasks)
    executor = ThreadPoolExecutor(max_workers=concurrency)
    pending = set()
    try:
        for _ in range(concurrency):
            task = next(iterator, None)
            if task is not None:
                pending.add(executor.submit(worker, task))
        while pending:
            finished, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in finished:
                progress(future.result())
            for _ in finished:
                task = next(iterator, None)
                if task is not None:
                    pending.add(executor.submit(worker, task))
    except BaseException:
        budget.stop()
        for future in pending:
            future.cancel()
        raise
    finally:
        executor.shutdown(wait=True, cancel_futures=True)


def run_candidate(index, candidate, system, journal, budget, report_system=None, model_config=CONFIG, registered_tools=None, api_key=None, graph_direction="forward", graph_ranking="lexical"):
    system_name = report_system or system.value
    trial = Trial(candidate.case_id, system_name, journal)
    start = time.perf_counter()
    result = dict(case_id=candidate.case_id, system=system_name,
                  status='failed', predicted_label=None, verdict=None)
    trial.record({'event': 'trial_start'})
    interruption = None
    try:
        budget.check()
        spec = FULL_SYSTEM_HARNESS.system_spec(system)
        roles = set(spec.expert_order) | ({'planner'} if spec.planner_enabled else set())
        models = {role: OpenAICompatibleChatModel(
            **model_config, api_key=api_key if api_key is not None else os.environ['ANTIGRAVITY_API_KEY'],
            observer=budget.observer(trial, role)) for role in sorted(roles)}
        verdict = AgenticPipeline(index=index, system=system, models=models,
                                  graph_direction=graph_direction,
                                  graph_ranking=graph_ranking,
                                  tools=RecordedTools(index, trial, registered_tools)).run(candidate)
        result.update(predicted_label=verdict.label,
                      status='abstained' if verdict.label == 'ABSTAIN' else 'completed',
                      verdict=verdict.model_dump(mode='json'))
    except (Exception, KeyboardInterrupt) as error:
        interruption = error if isinstance(error, KeyboardInterrupt) else None
        result.update(error_type=type(error).__name__, error=str(error),
                      status='interrupted' if interruption is not None else
                      'not_run' if isinstance(error, BudgetExceeded) and trial.model_calls == 0
                      else 'interrupted' if isinstance(error, BudgetStopped)
                      else 'failed')
    result.update(model_calls=trial.model_calls, tool_calls=trial.tool_calls,
                  latency_sec=round(time.perf_counter()-start, 3))
    trial.record({'event': 'trial_result', 'result': result})
    if interruption is not None:
        raise interruption
    return result


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
    sources = fingerprint_files(project_root)
    source_hashes = {}
    for source in sources:
        relative = source.relative_to(project_root)
        content = source.read_bytes()
        snapshot = run_dir/'source'/relative
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(content)
        source_hashes[str(relative)] = hashlib.sha256(content).hexdigest()
    return source_hashes


def run(pilot, positive_check=False, graph_check=False, lexical_check=False, fast_check=False):
    if not os.environ.get('ANTIGRAVITY_API_KEY'):
        raise ValueError('ANTIGRAVITY_API_KEY is required')
    manifest = json.loads((project_root/'configs/development_manifest.json').read_text())
    config = json.loads((project_root/'configs/development_benchmark.json').read_text())
    if not pilot:
        require_development_acceptance(project_root, config, manifest)
    model_config = CONFIG if pilot else json.loads((project_root / config['model_config']).read_text())
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
