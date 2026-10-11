"""Read-only final reconciliation of source coverage and versioned live costs."""
from collections import Counter
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / 'live_static_pilot_20261001'))
from run_v2 import read_json, sha, write
sys.path.insert(0, str(HERE.parent / 'static_pipeline_20261002'))
from pipeline import hashes
from cv_agent.runtime.admission import source_fingerprint


def main():
    live = read_json(HERE / 'result.json')
    components = read_json(HERE / 'component-result.json')
    assert components['status'] == 'COMPONENT_STATIC_COVERAGE_COMPLETED'
    assert components['completed_components'] == components['planned_components'] == 12
    run = ROOT / components['run']
    metadata = read_json(run / 'metadata.json')
    assert source_fingerprint(ROOT) == live['gate']['source_fingerprint'] == metadata['source_and_test_fingerprint']
    coverage = {}
    totals = Counter()
    rows = []
    matched_prior_blocks = []
    blocked_before = read_json(ROOT / 'audit/static_pipeline_20261002/inventory-result.json')
    assert blocked_before['blocked_candidates'] == 9
    before_units = {row['unit']: row for row in blocked_before['results']}
    for row in components['results']:
        bundle = run / row['unit']
        copied = run / (row['unit'] + '-copy')
        assert hashes(bundle) == row['package_sha256'] == row['copy_sha256'] == hashes(copied)
        actual = read_json(bundle / 'result.json')
        assert actual['run_state'] == 'COMPLETED'
        assert row['counts'] == actual['counts']
        assert actual['counts']['inventory_complete'] and actual['counts']['parse_errors'] == 0
        assert actual['counts']['analysis_blocked'] == actual['counts']['analysis_failed'] == 0
        assert actual['accounting']['model_requests'] == actual['accounting']['target_executions'] == 0
        findings_by_id = {finding['candidate_id']: finding for finding in actual['findings']}
        for blocked in before_units[row['unit']]['blocked_findings']:
            path = blocked['operation_locator']['source_path']
            assert row['source_inventory'][path] == before_units[row['unit']]['source_inventory'][path]
            current = findings_by_id[blocked['candidate_id']]
            assert current['operation_locator'] == blocked['operation_locator']
            assert current['analysis_state'] == 'COMPLETED' and current['property_state'] == 'UNKNOWN'
            matched_prior_blocks.append({'candidate_id': blocked['candidate_id'], 'source_path': path,
                'source_sha256_unchanged': True, 'operation_locator_unchanged': True,
                'before_analysis': 'BLOCKED', 'after_analysis': 'COMPLETED', 'after_property': 'UNKNOWN'})
        assert not set(coverage) & set(row['source_inventory'])
        coverage.update(row['source_inventory'])
        for key in ('source_files_read', 'parsed_files', 'candidate_total', 'analysis_completed',
                    'analysis_blocked', 'analysis_failed', 'unknown', 'supported', 'refuted', 'conflict'):
            totals[key] += actual['counts'][key]
        rows.append({'unit': row['unit'], 'files': row['source_files'],
            'candidates': actual['counts']['candidate_total'], 'analysis_completed': actual['counts']['analysis_completed'],
            'blocks_before': before_units[row['unit']]['counts']['analysis_blocked'],
            'blocks_after': actual['counts']['analysis_blocked'],
            'property_states': {key: actual['counts'][key] for key in ('supported', 'refuted', 'unknown', 'conflict')}})
    assert coverage == metadata['source_inventory']
    assert coverage == {str(path.relative_to(ROOT / 'src')): sha(path) for path in (ROOT / 'src').rglob('*.py')}
    assert totals['source_files_read'] == components['covered_files'] == components['source_files'] == 239
    previous_live = read_json(ROOT / 'audit/static_pipeline_20261002/result.json')
    for receipt in (live, previous_live):
        assert all(sha(ROOT / path) == digest for path, digest in receipt['evidence_sha256'].items())
    requests = live['usage']['requests'] + previous_live['usage']['requests']
    tokens = live['usage']['reported_total_tokens'] + previous_live['usage']['reported_total_tokens']
    assert requests == 42 and tokens == 50536
    assert len(matched_prior_blocks) == 9
    receipt = {'schema': 'static-pipeline-iteration-final-v1',
        'status': 'STATIC_DISPATCH_REPAIRED_COMPONENT_ROLLOUT_PASS',
        'source_and_test_fingerprint': source_fingerprint(ROOT), 'current_gate': live['gate'],
        'regressions': live['regressions'], 'latest_live': {'requests': 6, 'reported_tokens': 8214,
            'valid_replies': 6, 'state_matches': 6, 'reference_errors': 0, 'wrong_strong_proposals': 0},
        'this_user_turn_live_cost': {'requests': requests, 'reported_tokens': tokens,
            'request_cap': 42, 'reported_token_cap': 150000, 'within_budget': True,
            'protocols_kept_separate': True, 'pooled_unchanged_protocol_success_claim': False},
        'component_coverage': {'files': 239, 'source_bytes': components['source_bytes'],
            'source_ast_nodes': components['source_ast_nodes'], 'components': 12,
            'source_membership_duplicate_or_missing': 0, 'counts': dict(totals), 'rows': rows,
            'all_private_packages_and_complete_copies_valid': True,
            'cross_component_context_admitted': False},
        'preserved_failures': {
            'initial_delivery_oracle': previous_live['preserved_initial_failure'],
            'monolithic_ast_limit': components['preserved_monolithic'],
            'component_strict_rollout': 'audit/static_pipeline_20261002/component-result.json',
            'before_repair_blocks': 9, 'after_repair_blocks': totals['analysis_blocked'],
            'exact_prior_block_matches': matched_prior_blocks,
            'historical_package_verification_scope': 'The prior engine snapshot; no current-engine verification claim for ancestor bundles'},
        'limits': {'target_executions': 0, 'full_attack_witness_matrix_admitted': False,
            'monolithic_full_src_pass': False, 'component_static_rollout_pass': True,
            'application_security_assessed': False, 'independent_project_quality_measured': False,
            'human_benefit_measured': False, 'heldout_claim_eligible': False,
            'named_mode_14_unknown_controls_resolved': False, 'production_R17_enabled': False, 'G_A_changed': False},
        'evidence_sha256': {str(path.relative_to(ROOT)): sha(path) for path in
            (HERE / 'result.json', HERE / 'component-result.json', run / 'metadata.json', run / 'summary.json',
             ROOT / 'audit/static_pipeline_20261002/result.json', ROOT / 'audit/static_pipeline_20261002/inventory-result.json',
             ROOT / 'audit/static_pipeline_20261002/component-result.json', ROOT / 'audit/static_pipeline_20261002/owned-project-result.json')},
        'source_inventory_sha256': coverage}
    write(HERE / 'final-result.json', receipt)
    print('Component source coverage: 239/239; counts: ' + str(dict(totals)))
    print('Live calls this user turn: ' + str(requests) + '; reported tokens: ' + str(tokens))


if __name__ == '__main__':
    main()
