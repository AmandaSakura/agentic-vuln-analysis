"""Offline response-ID correlation; export whitelisted diagnostics, never raw proxy logs."""
import json
from pathlib import Path

from cv_agent.benchmark_evaluation import provider_usage
from cv_agent.proxy_diagnostics import native_records


def classify_response(event, records):
    raw = event['raw_response']
    response_id = raw.get('id')
    matches = [record for record in records if record['response_id'] == response_id]
    if matches and any(match != matches[0] for match in matches[1:]):
        raise ValueError('Conflicting native evidence for response ID')
    result = dict(case_id=event['case_id'], sample=event['system'], response_id=response_id,
                  reported_total_tokens=raw.get('usage', {}).get('total_tokens'),
                  diagnosis='nonempty_choices' if raw.get('choices') else 'empty_response_unresolved')
    if matches:
        result.update(matches[0])
        if matches[0]['block_reason']:
            result['diagnosis'] = 'upstream_blocked'
        elif not raw.get('choices'):
            result['diagnosis'] = 'upstream_empty_unresolved'
    return result


def main():
    root = Path(__file__).resolve().parents[1]
    config = json.loads((root / 'configs/langchain_transport_audit.json').read_text())
    records = []
    for path in sorted(Path(config['proxy_logs']).glob(config['log_pattern'])):
        records.extend(native_records(path.read_text()))
    runs = []
    for name in config['runs']:
        events = [json.loads(line) for line in (root / name / 'events.jsonl').read_text().splitlines()]
        rows = [classify_response(event, records) for event in events
                if event['event'] == 'model_response_received']
        runs.append(dict(run=name, responses=rows, usage=provider_usage(events)))
    report = dict(runs=runs, native_responses_matched=len(records),
                  note='Only response-ID matched native evidence establishes upstream blocking. '
                       'Unmatched historical empty responses remain unresolved. No new API calls.')
    (root / config['output']).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
