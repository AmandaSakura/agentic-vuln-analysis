"""Seal the new engine/live gate independently of the preceding engine's runs."""
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUN = ROOT / 'artifacts/static_dispatch_repair_20261002/5e4cb3d80ded43e29021123b9882618f'
sys.path.insert(0, str(HERE.parent / 'live_static_pilot_20261001'))
from run_v2 import read_json, sha
from reference_protocol import validate_proposal
sys.path.insert(0, str(HERE.parent / 'static_pipeline_20261002'))
from pipeline import hashes
from cv_agent.evaluation.metrics import provider_usage
from cv_agent.runtime.admission import source_fingerprint
from cv_agent.runtime.journal import audit_journal


def main():
    summary = read_json(RUN / 'summary.json')
    assert summary['status'] == 'COMPLETED'
    rows = read_json(RUN / 'private-input-manifest.json')
    protocol = read_json(HERE / 'protocol.json')
    metadata = read_json(RUN / 'metadata.json')
    prompts = read_json(RUN / 'frozen-prompts.json')
    events = [json.loads(line) for line in (RUN / 'events.jsonl').read_text().splitlines()]
    replies = [event for event in events if event['event'] == 'model_reply']
    usage = provider_usage(events)
    audit = audit_journal(RUN / 'events.jsonl')
    assert usage == summary['usage'] and audit == summary['ledger_audit']
    assert len(rows) == len(replies) == len(summary['results']) == usage['requests'] == 6
    assert not audit['issues'] and not audit['uncertain_request_ids']
    assert not usage['requests_without_reported_usage'] and not usage['usage_conflicts']
    assert usage['reported_total_tokens'] <= protocol['max_reported_tokens']
    for row, event, result, source, prompt in zip(rows, replies, summary['results'], protocol['source_controls'], prompts, strict=True):
        import hashlib
        assert row['source_sha256'] == hashlib.sha256(source.encode()).hexdigest()
        proposal = validate_proposal(event['reply']['content'], row['payload'])
        assert proposal.model_dump() == result['proposed']
        assert proposal.property_state == row['canonical_state'] == result['accepted_state']
        assert hashes(Path(row['bundle'])) == row['delivery']['original_sha256']
        assert hashes(Path(row['delivery']['copy_bundle'])) == row['delivery']['copy_sha256']
        assert all(row['delivery']['checks'].values()) and all(result['delivery'].values())
        assert 'canonical_state' not in json.loads(prompt[1]['content'])
        delivery = read_json(RUN / ('model-review-' + str(row['sample']) + '.json'))
        assert delivery['candidate_id'] == proposal.candidate_id and delivery['proposed'] == proposal.model_dump()
    assert [row['canonical_state'] for row in rows] == ['SUPPORTED', 'REFUTED'] + ['UNKNOWN'] * 4
    gate = read_json(RUN / 'gate-receipt.json')
    assert gate['source_fingerprint'] == metadata['source_fingerprint'] == source_fingerprint(ROOT)
    gate_line = next(line for line in (HERE / 'execution.log').read_text().splitlines() if 'pytest.log' in line)
    gate_path = Path(gate_line.split()[-1])
    match = re.search(r'(\d+) passed in ([0-9.]+)s', gate_path.read_text())
    assert match is not None
    gate.update(passed=int(match[1]), pytest_seconds=float(match[2]), log=str(gate_path.relative_to(ROOT)))
    previous = read_json(ROOT / 'audit/static_pipeline_20261002/result.json')
    assert all(sha(ROOT / path) == digest for path, digest in previous['evidence_sha256'].items())
    receipt = {'schema': 'static-dispatch-repair-live-acceptance-v1', 'status': 'COMPLETED',
        'run': str(RUN.relative_to(ROOT)), 'validated_replies': 6, 'usage': usage, 'ledger_audit': audit,
        'gate': gate, 'canonical_states': [row['canonical_state'] for row in rows],
        'model_vs_canonical': {'denominator': 6, 'exact_matches': 6, 'wrong_strong_proposals': 0},
        'protocol_rejections': [], 'public_delivery_verified': 6,
        'scope': 'Explicit v2 static dispatch repair and bounded evidence consumption on benign owned controls',
        'regressions': {'dispatch_cases': 12, 'initial_failures': 4, 'initial_positive_passes': 6,
                        'final_dispatch_passes': 12, 'combined_passes_before_added_alias_controls': 22},
        'previous_engine_receipt': 'audit/static_pipeline_20261002/result.json',
        'previous_engine_raw_artifacts_unchanged': True,
        'limits': {'target_executions': 0, 'model_tools': [], 'heldout_claim_eligible': False,
            'human_benefit_measured': False, 'production_R17_enabled': False, 'G_A_changed': False},
        'evidence_sha256': {str((RUN / name).relative_to(ROOT)): sha(RUN / name) for name in
            ('metadata.json', 'private-input-manifest.json', 'frozen-prompts.json', 'events.jsonl',
             'summary.json', 'gate-receipt.json', 'rollout-decision.json')},
        'gate_log_sha256': sha(gate_path)}
    receipt['evidence_sha256'].update({str(path.relative_to(ROOT)): sha(path) for path in RUN.glob('model-review-*.json')})
    (HERE / 'result.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'usage': usage, 'gate': gate, 'matched': 6}))


if __name__ == '__main__':
    main()
