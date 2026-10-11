"""Expand the validated local static product to the owned complete src root."""
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
from uuid import uuid4

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from pipeline import build_bundle, cli, hashes
sys.path.insert(0, str(HERE.parent / 'live_static_pilot_20261001'))
from run_v2 import read_json, sha, write
from cv_agent.runtime.admission import source_fingerprint
from cv_agent.runtime.paths import PROJECT_ROOT

ROOT = PROJECT_ROOT


def main():
    accepted = read_json(HERE / 'result.json')
    assert accepted['status'] == 'COMPLETED' and accepted['validated_replies'] == 36
    assert accepted['model_vs_canonical']['exact_matches'] == 36
    assert not accepted['protocol_rejections'] and not accepted['ledger_audit']['issues']
    assert all(accepted['public_cli_delivery']['boundary_checks'].values())
    assert accepted['rollout']['status'] == 'PILOT_PASS_EXPANSION_ADMITTED'
    assert source_fingerprint(ROOT) == accepted['gate']['source_fingerprint']
    assert all(sha(ROOT / path) == digest for path, digest in accepted['evidence_sha256'].items())
    protocol = read_json(HERE / 'owned-project-protocol.json')
    output = ROOT / 'artifacts/owned_static_rollout_20261002' / uuid4().hex
    output.mkdir(parents=True, mode=0o700)
    metadata = {'protocol': protocol, 'admission_receipt_sha256': sha(HERE / 'result.json'),
        'source_and_test_fingerprint': source_fingerprint(ROOT),
        'script_sha256': sha(Path(__file__)), 'helper_sha256': sha(HERE / 'pipeline.py'),
        'started_at': datetime.now(timezone.utc).isoformat()}
    write(output / 'metadata.json', metadata)
    print('Owned static rollout directory: ' + str(output), flush=True)
    try:
        bundle = build_bundle(ROOT / protocol['source_root'], output / 'project')
        result = read_json(bundle / 'result.json')
        verification = cli(output, 'owned-project-verify', ['verify', bundle])
        assert verification['valid']
        copied = output / 'project-copy'
        shutil.copytree(bundle, copied)
        assert hashes(bundle) == hashes(copied)
        copy_verification = cli(output, 'owned-project-copy-verify', ['verify', copied])
        assert copy_verification['valid']
        share = read_json(copied / 'share.json')
        assert share['verification_availability'] == 'NOT_VERIFIABLE'
        assert all(f['property_state'] == 'UNKNOWN' for f in share['findings'])
        assert (copied / 'report.md').is_file()
        assert source_fingerprint(ROOT) == metadata['source_and_test_fingerprint']
        receipt = {'status': 'OWNED_STATIC_ROLLOUT_COMPLETED', 'run': str(output.relative_to(ROOT)),
            'source_root': protocol['source_root'], 'run_state': result['run_state'],
            'counts': result['counts'], 'accounting': result['accounting'], 'identity': result['identity'],
            'private_package_valid': True, 'complete_copy_valid': True,
            'share_authority': share['verification_availability'],
            'model_requests': 0, 'target_executions': 0,
            'heldout_claim_eligible': False, 'whole_application_security_assessed': False,
            'production_R17_enabled': False, 'G_A_changed': False,
            'finished_at': datetime.now(timezone.utc).isoformat(),
            'package_sha256': hashes(bundle), 'copy_sha256': hashes(copied),
            'metadata_sha256': sha(output / 'metadata.json')}
        write(output / 'summary.json', receipt)
        write(HERE / 'owned-project-result.json', receipt)
        print(json.dumps({key: receipt[key] for key in ('status', 'run', 'counts', 'model_requests', 'target_executions')}), flush=True)
        return 0
    except BaseException as error:
        failure = {'status': 'OWNED_STATIC_ROLLOUT_STOPPED', 'error_type': type(error).__name__,
            'run': str(output.relative_to(ROOT)), 'model_requests': 0, 'target_executions': 0,
            'whole_application_security_assessed': False,
            'finished_at': datetime.now(timezone.utc).isoformat()}
        write(output / 'summary.json', failure)
        write(HERE / 'owned-project-result.json', failure)
        print(json.dumps(failure), flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
