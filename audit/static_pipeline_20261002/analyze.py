"""Read-only reconciliation after the fixed live run; reference labels stay here."""
from collections import Counter
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUN = ROOT / 'artifacts/static_pipeline_20261002/8d71ecddcc0c4267bf953ca2ea6a0ec9'
FAILED = ROOT / 'artifacts/static_pipeline_20261002/80f132bdc87a4e449b723a3136b5f3d4'
sys.path.insert(0, str(HERE.parent / 'live_static_pilot_20261001'))
from run_v2 import read_json, sha
from reference_protocol import ProposalProtocolError, validate_proposal
from cv_agent.evaluation.metrics import provider_usage
from cv_agent.runtime.admission import source_fingerprint
from cv_agent.runtime.journal import audit_journal
sys.path.insert(0, str(HERE))
from pipeline import hashes


def table(pairs):
    return [{'expected': a, 'actual': b, 'count': count}
            for (a, b), count in sorted(Counter(pairs).items())]


def main():
    summary = read_json(RUN / 'summary.json')
    assert summary['status'] in {'COMPLETED', 'STOPPED'}
    rows = read_json(RUN / 'private-input-manifest.json')
    prompts = read_json(RUN / 'frozen-prompts.json')
    events = [json.loads(line) for line in (RUN / 'events.jsonl').read_text().splitlines()]
    usage = provider_usage(events)
    audit = audit_journal(RUN / 'events.jsonl')
    assert usage == summary['usage'] and audit == summary['ledger_audit']
    assert not audit['issues'] and not usage['usage_conflicts']
    assert usage['requests'] <= 36 and usage['reported_total_tokens'] <= 120000
    reference_path = ROOT / 'audit/product_recovery_20261001/quality_reference.json'
    assert sha(reference_path) == read_json(HERE / 'protocol.json')['reference_sha256']
    reference = read_json(reference_path)
    by_id = {case['case_id']: case for case in reference['cases']}
    assert len(rows) == len(by_id) == 36
    static_pairs = []
    for row, prompt in zip(rows, prompts, strict=True):
        case = by_id[row['case_id']]
        assert row['source_sha256'] == case['source_sha256']
        assert row['selected_line'] == case['selected_line']
        view = json.loads(prompt[1]['content'])
        assert 'canonical_state' not in view and 'expected_state' not in view
        assert 'case_id' not in view and row['case_id'] not in prompt[1]['content']
        assert all(row['delivery']['checks'].values())
        assert hashes(Path(row['bundle'])) == row['delivery']['original_sha256']
        assert hashes(Path(row['delivery']['copy_bundle'])) == row['delivery']['copy_sha256']
        assert row['delivery']['original_sha256'] == row['delivery']['copy_sha256']
        static_pairs.append((case['expected_state'], row['canonical_state']))
    replies = [event for event in events if event['event'] == 'model_reply']
    assessed = []
    rejected = []
    for row, event in zip(rows, replies):
        try:
            proposed = validate_proposal(event['reply']['content'], row['payload'])
        except ProposalProtocolError as error:
            rejected.append({'sample': row['sample'], 'reason': error.reason_code,
                             'invalid_refs': list(error.invalid_refs)})
            continue
        assessed.append({'sample': row['sample'], 'expected': by_id[row['case_id']]['expected_state'],
                         'canonical': row['canonical_state'], 'proposed': proposed.property_state})
    assert len(assessed) == len(summary['results'])
    for row, result in zip(assessed, summary['results'], strict=True):
        assert row['sample'] == result['sample'] and row['proposed'] == result['proposed']['property_state']
        assert all(result['delivery'].values())
        delivered = read_json(RUN / ('model-review-' + str(result['sample']) + '.json'))
        assert delivered['proposed'] == result['proposed'] and delivered['canonical_state'] == result['canonical_state']
        assert delivered['candidate_id'] == result['candidate_id']
    decisions = [(index, event) for index, event in enumerate(events) if event['event'] == 'expansion_admitted']
    if usage['requests'] > 8:
        assert len(decisions) == 1 and decisions[0][1]['requests_at_admission'] == 8
        before = events[:decisions[0][0]]
        assert sum(event['event'] == 'model_start' for event in before) == 8
        assert sum(event['event'] == 'delivery_verified' for event in before) == 8
        assert read_json(RUN / 'rollout-decision.json')['status'] == 'PILOT_PASS_EXPANSION_ADMITTED'
    assert all(summary['boundary_checks'].values())
    failure = read_json(FAILED / 'summary.json')
    assert failure['status'] == 'STOPPED' and failure['phase'] == 'static_preparation'
    assert failure['usage']['requests'] == failure['usage']['reported_total_tokens'] == 0
    previous = read_json(ROOT / 'audit/live_controls36_20261002/result.json')
    assert all(sha(ROOT / path) == digest for path, digest in previous['evidence_sha256'].items())
    gate_receipt = read_json(RUN / 'gate-receipt.json')
    assert gate_receipt['source_fingerprint'] == read_json(RUN / 'metadata.json')['source_fingerprint']
    assert source_fingerprint(ROOT) == gate_receipt['source_fingerprint']
    gate_lines = [line for line in (HERE / 'execution.log').read_text().splitlines()
                  if 'pytest.log' in line]
    gate_logs = []
    for line in gate_lines:
        for word in line.split():
            path = Path(word.rstrip(').'))
            if path.name == 'pytest.log' and path.is_file():
                gate_logs.append(path)
    assert len(gate_logs) == 1
    gate_match = re.search(r'(\d+) passed in ([0-9.]+)s', gate_logs[0].read_text())
    assert gate_match is not None
    gate_receipt.update(passed=int(gate_match[1]), pytest_seconds=float(gate_match[2]),
                        log=str(gate_logs[0].relative_to(ROOT)))
    # The gate directory is bound by fingerprint and the actual process receipt.
    receipt = {
        'schema': 'owned-static-delivery-pipeline-reconciliation-v1', 'status': summary['status'],
        'run': str(RUN.relative_to(ROOT)), 'stop_reason': summary['stop_reason'],
        'scope': 'Public local static delivery pipeline and separate bounded model evidence review; no target execution',
        'planned': 36, 'requests': usage['requests'], 'validated_replies': len(assessed),
        'protocol_rejections': rejected, 'usage': usage, 'ledger_audit': audit,
        'not_requested': 36 - usage['requests'], 'gate': gate_receipt,
        'current_source_fingerprint_matches_gate': True,
        'public_cli_delivery': {'planned_controls': 36, 'completed_controls': len(assessed),
            'checks_per_control': ['review', 'verify', 'copy_verify', 'view', 'report', 'share'],
            'immutable_packages_and_copies': True, 'post_reply_delivery_verified': len(assessed),
            'boundary_checks': summary['boundary_checks']},
        'rollout': summary['rollout'],
        'preserved_initial_failure': {
            'run': str(FAILED.relative_to(ROOT)), 'requests': 0, 'reported_tokens': 0,
            'classification': 'experiment-oracle-bug; view promises the exact operation, not full function source',
            'offline_regressions': 4, 'before': '4 failed', 'after': '4 passed',
            'production_code_changed': False,
            'evidence_sha256': {str((FAILED / name).relative_to(ROOT)): sha(FAILED / name)
                               for name in ('metadata.json', 'events.jsonl', 'summary.json')}},
        'model_vs_canonical': {
            'denominator': len(assessed), 'exact_matches': sum(r['proposed'] == r['canonical'] for r in assessed),
            'wrong_strong_proposals': sum(r['proposed'] in {'SUPPORTED', 'REFUTED', 'CONFLICT'}
                                         and r['proposed'] != r['canonical'] for r in assessed),
            'confusion': table((r['canonical'], r['proposed']) for r in assessed)},
        'static_vs_development_reference': {
            'denominator': 36, 'exact_matches': sum(a == b for a, b in static_pairs),
            'confusion': table(static_pairs)},
        'model_vs_development_reference': {
            'denominator': len(assessed), 'exact_matches': sum(r['expected'] == r['proposed'] for r in assessed),
            'confusion': table((r['expected'], r['proposed']) for r in assessed)},
        'reference_sha256': sha(reference_path),
        'limits': {'heldout_claim_eligible': False, 'human_independent': False,
                   'human_benefit_measured': False, 'target_executions': 0,
                   'production_R17_enabled': False, 'G_A_changed': False},
        'evidence_sha256': {str((RUN / name).relative_to(ROOT)): sha(RUN / name) for name in
            ('metadata.json', 'private-input-manifest.json', 'frozen-prompts.json', 'events.jsonl',
             'summary.json', 'gate-receipt.json')},
        'gate_log_sha256': {str(path.relative_to(ROOT)): sha(path) for path in gate_logs}}
    receipt['evidence_sha256'].update({str(path.relative_to(ROOT)): sha(path)
        for path in sorted(RUN.glob('model-review-*.json'))})
    if (RUN / 'rollout-decision.json').is_file():
        receipt['evidence_sha256'][str((RUN / 'rollout-decision.json').relative_to(ROOT))] = sha(RUN / 'rollout-decision.json')
    (HERE / 'result.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({key: receipt[key] for key in
                     ('status', 'requests', 'validated_replies', 'protocol_rejections',
                      'model_vs_canonical', 'static_vs_development_reference', 'model_vs_development_reference')}, indent=2))


if __name__ == '__main__':
    main()
