"""Bounded 3-arm E4/E4_RULE_V1/E4_JEV_V3 comparison on hp003."""
from __future__ import annotations

import json
import os
from typing import Literal
from uuid import uuid4

from pydantic import Field, model_validator

from cv_agent.domain.types import FrozenModel
from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairCell, heldout_truth
from cv_agent.evaluation.datasets.advisory_tasks import build_tasks
from cv_agent.evaluation.datasets.composition import load_advisory_config
from cv_agent.evaluation.execution import run_candidate
from cv_agent.evaluation.metrics import metrics, provider_usage
from cv_agent.evaluation.results import save_json
from cv_agent.harness import AgentSystemVersion
from cv_agent.runtime.admission import require_passing_tests
from cv_agent.runtime.budget import Budget
from cv_agent.runtime.jev import JevRoutingConfig
from cv_agent.runtime.journal import Journal
from cv_agent.runtime.paths import PROJECT_ROOT
from cv_agent.runtime.provider import load_experiment_model
from cv_agent.runtime.snapshots import snapshot_sources


class JevV3ComparisonConfig(FrozenModel):
    dataset_role: Literal['development']
    claim_eligible: Literal[False]
    advisory_profile: Literal['configs/profiles/advisory_matrix_v4.json']
    case_ids: tuple[str, ...] = Field(min_length=1, max_length=2)
    systems: tuple[Literal['E4_JEV_V3', 'E4_RULE_V1', 'E4'], ...]
    fixture_policy: Literal['disabled'] = 'disabled'
    expert_policy: Literal['fixed'] = 'fixed'
    concurrency: int = 1
    max_requests: int = Field(ge=1)
    max_seconds: int = Field(ge=1)
    routing: JevRoutingConfig

    @model_validator(mode='after')
    def fixed_order(self):
        if self.systems != ('E4_JEV_V3', 'E4_RULE_V1', 'E4'):
            raise ValueError('Comparison runs E4_JEV_V3, E4_RULE_V1, E4 in that exact order')
        if len(set(self.case_ids)) != len(self.case_ids):
            raise ValueError('Comparison case IDs must be unique')
        return self


def summarize(output, rows, systems, events):
    usage = provider_usage(events)
    routing_records = [
        {'case_id': row['case_id'], 'system': row['system'], **row['verdict']['routing']}
        for row in rows
        if row.get('verdict') and row['verdict'].get('routing')
    ]
    summary = {
        'dataset_role': 'development',
        'claim_eligible': False,
        'systems': {name: metrics([row for row in rows if row['system'] == name]) for name in systems},
        'usage': usage,
        'usage_by_system': {name: provider_usage([e for e in events if e.get('system') == name]) for name in systems},
        'usage_by_role': {role: provider_usage([e for e in events if e.get('role') == role])
                          for role in ('routing', 'planner', 'scan', 'taint', 'authz')},
        'routing': routing_records,
        'note': 'Bounded development 3-arm comparison on hp003; no held-out generalization claim. Monetary cost remains unknown.',
    }
    save_json(output / 'results.json', rows)
    save_json(output / 'usage.json', usage)
    save_json(output / 'summary.json', summary)


def run(root=PROJECT_ROOT, output=None, *, config_path='configs/experiments/jev_v3_hp003_comparison.json'):
    config = JevV3ComparisonConfig.model_validate_json((root / config_path).read_text())
    if config.routing.mode != 'off' and not os.environ.get('JEV_API_KEY', '').strip():
        raise ValueError('Fill JEV_API_KEY in .env.experiments before running Jev V3 comparison')
    advisory = load_advisory_config(root, config.advisory_profile)
    payload = advisory.model_dump(mode='json', by_alias=True)
    payload['selected_cells'] = [
        PythonHeldoutPairCell(case_id=case, system=AgentSystemVersion.E4_GRAPH_MULTI).model_dump(mode='json')
        for case in config.case_ids
    ]
    payload['expected_abstentions'] = []
    advisory = type(advisory).model_validate(payload)
    model_config, api_key = load_experiment_model(root, advisory.model_config_path)
    tasks, subjects, identities = build_tasks(root, advisory, fixture_policy=config.fixture_policy)
    require_passing_tests()
    output = output or root / 'artifacts/jev_v3_comparison' / uuid4().hex
    output.mkdir(parents=True, exist_ok=False)
    save_json(output / 'metadata.json', {
        'config': config.model_dump(mode='json'),
        'model_config': model_config,
        'source_sha256': snapshot_sources(root, output),
        'case_identities': identities,
        'subjects': {name: value.model_dump(mode='json') for name, value in subjects.items()},
        'fixture_policy': config.fixture_policy,
        'expert_policy': config.expert_policy,
        'claim_eligible': False,
    })
    rows = [
        dict(case_id=candidate.case_id, system=name, ground_truth=heldout_truth(revision_role),
             category=pair_id, status='not_run', predicted_label=None, verdict=None,
             model_calls=0, tool_calls=0, latency_sec=0)
        for pair_id, revision_role, _, candidate, _, _ in tasks for name in config.systems
    ]
    journal = Journal(output / 'events.jsonl')
    journal.write({'event': 'run_start', 'dataset_role': 'development', 'fixture_policy': config.fixture_policy})
    budget = Budget(config.max_requests, config.max_seconds)
    summarize(output, rows, config.systems, [])
    print(f'Run directory: {output}; planned cells: {len(rows)}', flush=True)
    position = 0
    try:
        for _, _, index, candidate, registered, _ in tasks:
            for name in config.systems:
                row = run_candidate(
                    index, candidate, AgentSystemVersion.E4_GRAPH_MULTI,
                    journal, budget, report_system=name, model_config=model_config, api_key=api_key,
                    registered_tools=registered, graph_direction=advisory.graph_direction,
                    graph_ranking=advisory.graph_ranking,
                    routing_config=config.routing if name == 'E4_JEV_V3' else None,
                    expert_policy=config.expert_policy,
                )
                rows[position].update(row)
                position += 1
                events = [json.loads(line) for line in journal.path.read_text().splitlines()]
                summarize(output, rows, config.systems, events)
                print(f'{position}/{len(rows)} {candidate.case_id} {name}: {row["status"]}', flush=True)
                if row['status'] in {'failed', 'interrupted', 'not_run'}:
                    raise RuntimeError(f'Comparison stopped: {row.get("error", row["status"])}')
    finally:
        budget.stop()
        journal.write({'event': 'run_end', 'completed_cells': position})
        events = [json.loads(line) for line in journal.path.read_text().splitlines()]
        summarize(output, rows, config.systems, events)
    return output


if __name__ == '__main__':
    run()
