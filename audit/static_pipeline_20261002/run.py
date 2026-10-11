"""Fixed single-shot review of 36 owned static controls; no target execution."""
import ast
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
PILOT = HERE.parent / 'live_static_pilot_20261001'
sys.path.insert(0, str(PILOT))
from run_v2 import credential, read_json, sha, write
from run import inputs_from_bundle
sys.path.insert(0, str(HERE))
from pipeline import build_bundle, check_boundaries, check_delivery, post_reply_delivery
from reference_protocol import SYSTEM, ProposalProtocolError, make_model_view, validate_proposal
from cv_agent.domain.chat import ChatMessage
from cv_agent.evaluation.metrics import provider_usage
from cv_agent.runtime.admission import require_passing_tests, source_fingerprint
from cv_agent.runtime.journal import Journal, Trial, audit_journal
from cv_agent.runtime.model import OpenAICompatibleChatModel
from cv_agent.runtime.paths import PROJECT_ROOT

ROOT = PROJECT_ROOT


def main():
    protocol = read_json(HERE / 'protocol.json')
    config = read_json(ROOT / protocol['model_config'])
    output = ROOT / 'artifacts/static_pipeline_20261002' / uuid4().hex
    output.mkdir(parents=True, mode=0o700)
    events_path = output / 'events.jsonl'
    events_path.touch(mode=0o600)
    journal = Journal(events_path)
    results = []
    rows = []
    status, phase = 'PREPARING', 'static_preparation'
    frozen_files = [Path(__file__), HERE / 'protocol.json', HERE / 'pipeline.py', PILOT / 'run.py',
                    PILOT / 'run_v2.py', PILOT / 'reference_protocol.py']
    hashes = {str(path): sha(path) for path in frozen_files}
    assert sha(ROOT / 'audit/product_recovery_20261001/quality_reference.json') == protocol['reference_sha256']
    boundary_checks = {}
    rollout = {'status': 'NOT_ADMITTED', 'pilot_count': protocol['pilot_count'],
               'expansion_count': protocol['expansion_count']}
    write(output / 'metadata.json', {
        'protocol': protocol, 'config': {**config, 'max_tokens': protocol['max_output_tokens']},
        'source_fingerprint': source_fingerprint(ROOT), 'frozen_files': hashes,
        'started_at': datetime.now(timezone.utc).isoformat(),
        'reference_labels_loaded_by_runner': False, 'model_tools': [], 'target_executions': 0})
    print('Run directory: ' + str(output), flush=True)

    def usage():
        return provider_usage([json.loads(line) for line in events_path.read_text().splitlines()])

    def finish(reason=None):
        summary = {
            'status': status, 'phase': phase, 'stop_reason': reason, 'results': results,
            'usage': usage(), 'ledger_audit': audit_journal(events_path),
            'completed_candidates': len(results), 'planned_candidates': protocol['max_requests'],
            'boundary_checks': boundary_checks, 'rollout': rollout,
            'unassessed_samples': list(range(len(results) + 1, protocol['max_requests'] + 1)),
            'heldout_claim_eligible': False, 'human_independent': False,
            'target_executions': 0, 'production_R17_enabled': False, 'G_A_changed': False,
            'finished_at': datetime.now(timezone.utc).isoformat()}
        write(output / 'summary.json', summary)
        return summary

    try:
        cases = sorted((ROOT / protocol['source_root']).iterdir())
        assert len(cases) == protocol['max_requests'] and all(case.is_dir() for case in cases)
        with tempfile.TemporaryDirectory(prefix='cv-agent-owned-controls36-') as folder:
            for ordinal, case in enumerate(cases, 1):
                original = case / 'entry.py'
                tree = ast.parse(original.read_text())
                calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                         and isinstance(node.func, ast.Attribute) and node.func.attr == 'chmod'
                         and isinstance(node.func.value, ast.Name) and node.func.value.id == 'os']
                assert len(calls) == 1
                neutral = Path(folder) / ('item-' + str(ordinal))
                neutral.mkdir()
                shutil.copyfile(original, neutral / 'entry.py')
                bundle = build_bundle(neutral, output / ('static-' + str(ordinal)))
                candidates = inputs_from_bundle(bundle, 'owned_development_control')
                selected = [row for row in candidates
                            if row['payload']['contract']['property_id'] == 'chmod-mode-others-write'
                            and row['payload']['operation_locator']['source_path'] == 'entry.py'
                            and row['payload']['operation_locator']['start_line'] == calls[0].lineno]
                assert len(selected) == 1
                row = selected[0]
                assert row['payload']['operation_locator']['file_sha256'] == sha(original)
                row.update(sample=ordinal, case_id=case.name, selected_line=calls[0].lineno,
                           source_sha256=sha(original))
                row['delivery'] = check_delivery(neutral, bundle, row)
                if ordinal == 1:
                    boundary_checks = check_boundaries(neutral, bundle, row)
                rows.append(row)
                print('Prepared public static pipeline ' + str(ordinal), flush=True)
        assert set(row['canonical_state'] for row in rows[:protocol['pilot_count']]) == {'SUPPORTED', 'REFUTED', 'UNKNOWN'}
        assert set(boundary_checks) == set(protocol['boundary_controls']) and all(boundary_checks.values())
        write(output / 'private-input-manifest.json', rows)
        messages = [[ChatMessage(role='system', content=SYSTEM),
                     ChatMessage(role='user', content=json.dumps(make_model_view(row['payload']), ensure_ascii=False))]
                    for row in rows]
        write(output / 'frozen-prompts.json', [[m.model_dump(mode='json') for m in batch] for batch in messages])
        phase, status = 'full_pytest_gate', 'GATING'
        finish()
        started = time.monotonic()
        require_passing_tests()
        write(output / 'gate-receipt.json', {'actual_in_process_gate_passed': True,
            'seconds': time.monotonic() - started, 'source_fingerprint': source_fingerprint(ROOT),
            'saved_stamp_used': False, 'credential_loaded_before_gate': False})
        key = credential(ROOT / protocol['credential_file'], protocol['credential_name'])
        status = 'RUNNING'
        for row, batch in zip(rows, messages, strict=True):
            phase = 'model_requests'
            assert all(sha(Path(path)) == digest for path, digest in hashes.items())
            current = usage()
            assert current['requests'] < protocol['max_requests']
            assert not current['requests_without_reported_usage'] and not current['usage_conflicts']
            reservation = len(json.dumps([m.model_dump(mode='json') for m in batch], ensure_ascii=False).encode()) + protocol['max_output_tokens'] + protocol['request_framing_reservation']
            if current['reported_total_tokens'] + reservation > protocol['max_reported_tokens']:
                raise RuntimeError('Conservative reservation exceeds remaining token cap')
            sample = row['sample']
            journal.write({'event': 'reservation', 'sample': sample, 'reserved_token_units': reservation})
            trial = Trial('sample-' + str(sample), 'owned-static-delivery-pipeline', journal)
            model = OpenAICompatibleChatModel(**{**config, 'max_tokens': protocol['max_output_tokens']},
                api_key=key, observer=trial.observe('evidence_reader'))
            started = time.monotonic()
            reply = model.complete(batch, ())
            if reply.model_id != config['model'] or reply.tool_calls:
                raise RuntimeError('Unexpected returned model or tool request')
            phase = 'reply_protocol_validation'
            proposal = validate_proposal(reply.content, row['payload'])
            result = {'sample': sample, 'case_id': row['case_id'],
                'candidate_id': proposal.candidate_id, 'canonical_state': row['canonical_state'],
                'proposed': proposal.model_dump(),
                'exact_state_match': proposal.property_state == row['canonical_state'],
                'accepted_state': row['canonical_state'], 'model_never_overrides_static_evidence': True,
                'wall_seconds': time.monotonic() - started}
            results.append(result)
            journal.write({'event': 'proposal_assessment', **result})
            current = usage()
            if current['requests_without_reported_usage'] or current['usage_conflicts']:
                raise RuntimeError('Reported usage unavailable or conflicting')
            if current['reported_total_tokens'] > protocol['max_reported_tokens']:
                raise RuntimeError('Reported token cap exceeded')
            if not result['exact_state_match']:
                raise RuntimeError('Proposal differs from canonical observation; batch stopped')
            phase = 'post_reply_delivery'
            result['delivery'] = post_reply_delivery(row)
            write(output / ('model-review-' + str(sample) + '.json'), {
                'scope': 'Separate bounded static evidence review; not part of the authoritative product package',
                'source_sha256': row['source_sha256'], 'candidate_id': result['candidate_id'],
                'canonical_state': result['canonical_state'], 'proposed': result['proposed'],
                'authority': 'canonical-static-observation', 'target_executions': 0,
                'delivery': result['delivery']})
            journal.write({'event': 'delivery_verified', 'sample': sample, **result['delivery']})
            if sample == protocol['pilot_count']:
                assert len(results) == protocol['pilot_count'] and all(r['exact_state_match'] for r in results)
                assert all(all(r['delivery'].values()) for r in results)
                rollout = {'status': 'PILOT_PASS_EXPANSION_ADMITTED', 'pilot_count': protocol['pilot_count'],
                           'expansion_count': protocol['expansion_count'], 'requests_at_admission': current['requests'],
                           'reported_tokens_at_admission': current['reported_total_tokens']}
                write(output / 'rollout-decision.json', rollout)
                journal.write({'event': 'expansion_admitted', **rollout})
                print('Eight-input pilot passed; expanding to the remaining 28 static controls', flush=True)
            finish()
            print('Completed sample ' + str(sample) + ': ' + proposal.property_state, flush=True)
            if not result['exact_state_match'] and proposal.property_state in {'SUPPORTED', 'REFUTED', 'CONFLICT'}:
                raise RuntimeError('Unsupported strong proposal retained; remaining batch stopped')
        status, phase = 'COMPLETED', 'completed'
        summary = finish()
        print(json.dumps({'status': status, 'usage': summary['usage'], 'output': str(output)}), flush=True)
        return 0
    except BaseException as error:
        status = 'STOPPED'
        reason = error.reason_code if isinstance(error, ProposalProtocolError) else type(error).__name__
        journal.write({'event': 'trial_stopped', 'phase': phase, 'error_type': type(error).__name__,
            'reason_code': reason, 'rejected_proposal': error.proposed if isinstance(error, ProposalProtocolError) else None,
            'invalid_refs': list(error.invalid_refs) if isinstance(error, ProposalProtocolError) else []})
        summary = finish(reason)
        print(json.dumps({'status': status, 'phase': phase, 'reason': reason,
                         'usage': summary['usage'], 'output': str(output)}), flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
