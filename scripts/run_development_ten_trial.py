"""Ten fixed development trials, at most two simultaneous model requests."""
import json
from uuid import uuid4
import signal

from run_development_benchmark import (project_root, run_candidate,
                                       snapshot_sources, summarize, utc_now,
                                       LockedBudget, LockedJournal, execute_trials)
from cv_agent.agentic_live import load_owasp_agentic_inputs, select_owasp_entry
from cv_agent.agent_tools import candidate_subject
from cv_agent.experiment_acceptance import acceptance_issues, transport_issues, require_verification_capability
from cv_agent.java_fixture import java_command_fixture_cases
from cv_agent.validation_tools import full_agent_tools
from cv_agent.harness import AgentSystemVersion
from cv_agent.live_gate import require_passing_tests, source_fingerprint
from cv_agent.provenance import build_run_identity


def acceptance(rows, summary, expected, subjects):
    return not acceptance_issues(rows, summary, expected, subjects)


def validate_configuration(config):
    if (len(config['case_ids']) != 2 or len(set(config['case_ids'])) != 2
            or config['systems'] != ['E1', 'E2', 'E3', 'E4', 'E5']
            or config['max_trials'] != 10 or config['concurrency'] not in {1, 2}
            or config['entry_method'] != 'doPost'):
        raise ValueError('Ten-trial protocol requires two unique cases, E1–E5, doPost and concurrency one or two')


def run():
    config_path = project_root / 'configs/development_ten_trial.json'
    config = json.loads(config_path.read_text())
    validate_configuration(config)
    manifest = json.loads((project_root / 'configs/development_manifest.json').read_text())
    identity = build_run_identity(project_root, {'BenchmarkJava': project_root / 'data/raw/BenchmarkJava'})
    if identity['datasets'] != manifest['identity']['datasets']:
        raise ValueError('Dataset differs from frozen manifest')
    inputs = load_owasp_agentic_inputs(project_root / 'data/raw', case_ids=config['case_ids'])
    candidates = select_owasp_entry(inputs, config['entry_method'])
    fixture_cases = java_command_fixture_cases(project_root, inputs.index, candidates)
    tools = full_agent_tools(inputs.index, fixture_cases=fixture_cases)
    require_verification_capability(tools)
    subjects = {candidate.case_id: candidate_subject(inputs.index, candidate) for candidate in candidates}
    require_passing_tests()  # Gate once before worker threads; later checks verify the same snapshot.
    model_config = json.loads((project_root / config['model_config']).read_text())
    directory = project_root / 'artifacts/development_benchmark' / uuid4().hex
    directory.mkdir(parents=True)
    manifest = {**manifest, 'systems': config['systems'],
                'dataset_name': 'Ten-trial doPost development diagnostic',
                'sampling_note': 'Fixed development pair; changed entry protocol; no held-out claim.'}
    hashes = snapshot_sources(directory)
    (directory / 'metadata.json').write_text(json.dumps(dict(
        started_at=utc_now(), config=config, model_config=model_config,
        source_fingerprint=source_fingerprint(project_root),
        subjects={case: subject.model_dump(mode='json') for case, subject in subjects.items()},
        manifest=manifest, identity=identity, source_sha256=hashes), indent=2))
    journal = LockedJournal(directory / 'events.jsonl')
    journal.write({'event': 'run_start'})
    # Point full-run admission at the latest attempt immediately. An incomplete
    # or failed new batch must not leave an older success as the active gate.
    pointer = project_root / 'artifacts/development_acceptance.json'
    temporary = pointer.with_suffix('.tmp')
    temporary.write_text(json.dumps({'run_directory': str(directory.relative_to(project_root))}))
    temporary.replace(pointer)
    budget = LockedBudget(config['max_requests'], config['max_seconds'])
    print(f'Run directory: {directory}', flush=True)
    expected = {(case, system): 'VULNERABLE' if manifest['labels'][case]['vulnerable'] else 'SAFE'
                for case in config['case_ids'] for system in config['systems']}
    def worker(task):
        system, candidate = task
        return run_candidate(inputs.index, candidate, AgentSystemVersion(system), journal,
                             budget, model_config=model_config, registered_tools=tools)
    def progress(row):
        with journal.lock:
            summarize(directory, manifest, config['case_ids'])
        print(f"{row['case_id']}/{row['system']}: {row['status']} {row['predicted_label']}", flush=True)
    def interrupt(signum, frame):
        raise KeyboardInterrupt('Experiment stop requested')
    previous_handler = signal.signal(signal.SIGTERM, interrupt)
    try:
        execute_trials([(system, candidate) for system in config['systems'] for candidate in candidates],
                       worker, budget, progress, config['concurrency'])
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
        summary = summarize(directory, manifest, config['case_ids'])
        rows = json.loads((directory / 'results.json').read_text())
        issues = acceptance_issues(rows, summary, expected, subjects)
        events = [json.loads(line) for line in journal.path.read_text().splitlines()]
        issues.extend(transport_issues(events, model_config))
        if budget.cancelled.is_set():
            issues.append('Experiment interrupted')
        decision = dict(passed=not issues, issues=issues, criteria=config['acceptance'], automatic_expansion=False)
        (directory / 'acceptance.json').write_text(json.dumps(decision, indent=2))
        journal.write({'event': 'run_end', 'interrupted': budget.cancelled.is_set()})
    print(json.dumps(decision), flush=True)


if __name__ == '__main__':
    run()
