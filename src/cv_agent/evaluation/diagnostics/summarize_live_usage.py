"""Audit recorded provider usage without rewriting historical run results."""

from cv_agent.runtime.paths import PROJECT_ROOT
import json
from pathlib import Path

from cv_agent.evaluation.metrics import provider_usage


def audit_usage(root: Path):
    runs = []
    for family in ('development_benchmark', 'python_evidence_check',
                   'retrieval_validation_matrix', 'real_source_smoke', 'transport_probe',
                   'transport_token_probe', 'transport_raw_diagnostic', 'micro_benchmark',
                   'langchain_agent_eval', 'langchain_transport_probe'):
        for path in sorted((root / 'artifacts' / family).glob('*/events.jsonl')):
            events = [json.loads(line) for line in path.read_text().splitlines()]
            metadata = json.loads((path.parent / 'metadata.json').read_text())
            runs.append(dict(path=str(path.parent.relative_to(root)),
                             started_at=metadata.get('started_at'),
                             usage=provider_usage(events)))
    for path in sorted((root / 'artifacts/transport_raw_diagnostic').glob('*/raw_response.json')):
        if (path.parent / 'events.jsonl').exists():
            continue  # New diagnostics are already counted by their journal.
        raw = json.loads(path.read_text())
        body = raw['response_body']
        usage = provider_usage([
            {'event': 'model_start'},
            {'event': 'model_response_received', 'summary': {'usage': raw.get('usage')}},
            ({'event': 'model_reply', 'reply': {'model_id': body.get('model', 'unknown')}}
             if isinstance(body, dict) and body.get('choices') else
             {'event': 'model_invalid_response', 'summary': {}}),
        ])
        runs.append(dict(path=str(path.parent.relative_to(root)), started_at=None,
                         usage=usage, journal_format='legacy_raw_response'))
    fields = ('requests', 'responses', 'invalid_responses',
              'requests_without_reported_usage', 'reported_total_tokens')
    result = dict(runs=runs,
                  totals={field: sum(run['usage'][field] for run in runs) for field in fields},
                  monetary_cost=None,
                  note='Recorded event journals in ten explicit families plus legacy raw diagnostics. '
                       'Missing usage and unknown provider pricing are not zero cost. '
                       'This is a usage audit, not an effectiveness evaluation.')
    return result


def main():
    root = PROJECT_ROOT
    result = audit_usage(root)
    output = root / 'artifacts/live_usage_audit.json'
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
