"""Run a source-only Python repository pilot; never load evaluator references."""
import hashlib
import json
from pathlib import Path
from uuid import uuid4

from cv_agent.runtime.budget import Budget
from cv_agent.evaluation.runners.run_development_benchmark import run_candidate
from cv_agent.runtime.snapshots import snapshot_sources
from cv_agent.runtime.journal import Journal
from cv_agent.runtime.paths import PROJECT_ROOT as project_root
from cv_agent.evaluation.metrics import provider_usage
from cv_agent.harness import AgentSystemVersion
from cv_agent.retrieval.bm25 import MetadataBM25Index
from cv_agent.runtime.admission import require_passing_tests
from cv_agent.runtime.provenance import git_identity
from cv_agent.agents.discovery import discover_python_repository, select_pilot_candidates
from cv_agent.evaluation.repository import RepositoryPilotConfig, validate_heldout_membership
from cv_agent.code_adapters.source_files import read_source_bytes


def save_json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def prepare(config, root):
    if config.dataset_role == 'heldout_pilot':
        frozen = json.loads((root / 'configs/datasets/vulngym_heldout_inputs_v3.json').read_text())
        validate_heldout_membership(config, frozen)
    inventory = {'dataset_role': config.dataset_role, 'claim_eligible': False,
                 'candidate_protocol': 'source_only_static_discovery',
                 'selection_protocol': 'First N candidates sorted by source path, line and rule; no reference locations.',
                 'systems': [system.value for system in config.systems], 'subjects': []}
    runtime = {}
    for subject in config.subjects:
        checkout = root / subject.checkout
        identity = git_identity(checkout)
        if identity.revision != subject.commit or identity.dirty:
            raise ValueError('Subject must be a clean checkout of the pinned commit')
        source_root = checkout / subject.source_prefix
        discovery = discover_python_repository(source_root, subject.repository_id)
        selected = select_pilot_candidates(discovery.candidates, config.candidate_limit_per_subject)
        inventory['subjects'].append({
            'repository_id': subject.repository_id, 'repository_url': subject.repository_url,
            'commit': subject.commit, 'source_prefix': subject.source_prefix,
            'discovery': discovery.report,
            'candidates': [candidate.model_dump(mode='json') for candidate in discovery.candidates],
            'selected_case_ids': [candidate.case_id for candidate in selected],
        })
        runtime[subject.repository_id] = (source_root, discovery, selected)
    return inventory, runtime


def verify_source_snapshot(source_root, report):
    for path, expected in report['source_sha256'].items():
        if hashlib.sha256(read_source_bytes(source_root, path)).hexdigest() != expected:
            raise ValueError(f'Subject source changed after discovery: {path}')


def run(config_path, *, root=project_root, output=None):
    config = RepositoryPilotConfig.model_validate_json(config_path.read_text())
    require_passing_tests()
    output = output or root / 'artifacts/python_repository_pilot' / uuid4().hex
    output.mkdir(parents=True, exist_ok=False)
    inventory, runtime = prepare(config, root)
    model_config = json.loads((root / config.model_config_path).read_text())
    save_json(output / 'inventory.json', inventory)
    save_json(output / 'metadata.json', {
        'config': config.model_dump(mode='json'), 'model_config': model_config,
        'source_sha256': snapshot_sources(root, output),
        'claim_eligible': False, 'max_cells': 10,
    })
    for identity, (_, discovery, _) in runtime.items():
        save_json(output / f'{identity}-documents.json',
                  [document.model_dump(mode='json') for document in discovery.index.documents.values()])
    rows = [{'case_id': candidate.case_id, 'system': system.value, 'status': 'not_run',
             'predicted_label': None, 'model_calls': 0, 'tool_calls': 0,
             'latency_sec': 0, 'verdict': None}
            for _, _, selected in runtime.values() for candidate in selected for system in config.systems]
    save_json(output / 'results.json', rows)
    journal = Journal(output / 'events.jsonl')
    journal.write({'event': 'repository_pilot_start', 'cells': len(rows)})
    budget = Budget(config.max_requests, config.max_seconds)
    print(f'Run directory: {output}; planned cells: {len(rows)}', flush=True)
    position = 0
    try:
        for source_root, discovery, selected in runtime.values():
            for candidate in selected:
                for system in config.systems:
                    verify_source_snapshot(source_root, discovery.report)
                    index = (MetadataBM25Index(discovery.index.documents.values())
                             if system == AgentSystemVersion.E2_TEXT_SINGLE else discovery.index)
                    row = run_candidate(index, candidate, system, journal, budget, model_config=model_config)
                    rows[position] = row
                    position += 1
                    save_json(output / 'results.json', rows)
                    print(f'{position}/{len(rows)} {candidate.case_id} {system.value}: '
                          f'{row["status"]} {row["predicted_label"]}', flush=True)
                    if row['status'] in {'failed', 'interrupted', 'not_run'}:
                        budget.stop()
                        return output
    finally:
        events = [json.loads(line) for line in journal.path.read_text().splitlines()]
        save_json(output / 'usage.json', provider_usage(events))
    return output


if __name__ == '__main__':
    run(project_root / 'configs/experiments/python_repository_pilot.json')
