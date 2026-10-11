"""One fixed source-coverage experiment; no credentials, model or target execution."""
import ast
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import shutil
import sys
import tempfile
from uuid import uuid4

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from pipeline import cli, hashes
from inventory_review import review_inventory
sys.path.insert(0, str(HERE.parent / 'live_static_pilot_20261001'))
from run_v2 import read_json, sha, write
from cv_agent.runtime.admission import source_fingerprint
from cv_agent.runtime.paths import PROJECT_ROOT

ROOT = PROJECT_ROOT
PARTIAL = ROOT / 'artifacts/owned_static_rollout_20261002/32fd6fd6e3e44c579d18603344f58a7a'


def main():
    admission = read_json(HERE / 'result.json')
    assert admission['status'] == 'COMPLETED' and admission['validated_replies'] == 36
    assert source_fingerprint(ROOT) == admission['gate']['source_fingerprint']
    partial = read_json(PARTIAL / 'project/result.json')
    assert partial['run_state'] == 'PARTIAL' and not partial['counts']['inventory_complete']
    assert any(d['reason_code'] == 'SOURCE_AST_LIMIT' for d in partial['diagnoses'])
    protocol = read_json(HERE / 'inventory-protocol.json')
    source_root = ROOT / protocol['source_root']
    files = sorted(source_root.rglob('*.py'))
    inventory = {str(path.relative_to(source_root)): sha(path) for path in files}
    membership = {}
    for unit in protocol['units']:
        membership[unit] = [path for path in files if (
            len(path.relative_to(source_root).parts) == 2 if unit == 'root'
            else path.relative_to(source_root).parts[:2] == ('cv_agent', unit))]
    allocated = [str(path.relative_to(source_root)) for group in membership.values() for path in group]
    assert Counter(allocated) == Counter(inventory.keys())
    assert all(membership.values())
    ast_nodes = sum(sum(1 for _ in ast.walk(ast.parse(path.read_text()))) for path in files)
    output = ROOT / 'artifacts/source_inventory_20261002' / uuid4().hex
    output.mkdir(parents=True, mode=0o700)
    metadata = {'protocol': protocol, 'source_inventory': inventory, 'source_files': len(files),
        'source_bytes': sum(path.stat().st_size for path in files), 'source_ast_nodes': ast_nodes,
        'source_and_test_fingerprint': source_fingerprint(ROOT),
        'script_sha256': sha(Path(__file__)), 'protocol_sha256': sha(HERE / 'inventory-protocol.json'),
        'admission_receipt_sha256': sha(HERE / 'result.json'),
        'started_at': datetime.now(timezone.utc).isoformat()}
    write(output / 'metadata.json', metadata)
    print('Component rollout directory: ' + str(output), flush=True)
    partial_verify = cli(output, 'preserved-partial-package-verify', ['verify', PARTIAL / 'project'])
    assert partial_verify['valid']
    results = []
    status = 'PREPARING'

    def finish(reason=None):
        summary = {'status': status, 'run': str(output.relative_to(ROOT)), 'stop_reason': reason,
            'planned_components': len(protocol['units']), 'completed_components': len(results),
            'source_files': len(files), 'source_bytes': metadata['source_bytes'], 'source_ast_nodes': ast_nodes,
            'covered_files': sum(r['source_files'] for r in results), 'results': results,
            'model_requests': 0, 'target_executions': 0, 'heldout_claim_eligible': False,
            'whole_application_security_assessed': False, 'cross_component_context_admitted': False,
            'production_R17_enabled': False, 'G_A_changed': False,
            'preserved_monolithic': {'run': str(PARTIAL.relative_to(ROOT)), 'counts': partial['counts'],
                'diagnoses': partial['diagnoses'], 'private_package_valid': partial_verify['valid'],
                'result_sha256': sha(PARTIAL / 'project/result.json'),
                'manifest_sha256': sha(PARTIAL / 'project/manifest.json')},
            'finished_at': datetime.now(timezone.utc).isoformat()}
        write(output / 'summary.json', summary)
        summary['full_matrix_admitted'] = False
        summary['partial_components'] = [row['unit'] for row in results if row['run_state'] == 'PARTIAL']
        summary['blocked_candidates'] = sum(row['counts']['analysis_blocked'] for row in results)
        write(HERE / 'inventory-result.json', summary)
        return summary

    try:
        with tempfile.TemporaryDirectory(prefix='cv-agent-owned-components-') as folder:
            status = 'RUNNING'
            for unit in protocol['units']:
                neutral = Path(folder) / unit
                for original in membership[unit]:
                    relative = original.relative_to(source_root)
                    destination = neutral / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(original, destination)
                expected = {str(path.relative_to(source_root)): inventory[str(path.relative_to(source_root))]
                            for path in membership[unit]}
                assert hashes(neutral) == expected
                bundle = review_inventory(neutral, output / unit)
                result = read_json(bundle / 'result.json')
                assert result['counts']['inventory_complete'] and result['counts']['parse_errors'] == 0
                assert result['counts']['source_files_read'] == len(expected)
                assert cli(output, unit + '-verify', ['verify', bundle])['valid']
                copied = output / (unit + '-copy')
                shutil.copytree(bundle, copied)
                assert hashes(bundle) == hashes(copied)
                assert cli(output, unit + '-copy-verify', ['verify', copied])['valid']
                share = read_json(copied / 'share.json')
                assert share['verification_availability'] == 'NOT_VERIFIABLE'
                assert all(f['property_state'] == 'UNKNOWN' for f in share['findings'])
                assert (copied / 'report.md').is_file()
                results.append({'unit': unit, 'source_files': len(expected), 'source_inventory': expected,
                    'run_state': result['run_state'], 'readiness_gate_passed': result['run_state'] == 'COMPLETED',
                    'blocked_findings': [{'candidate_id': finding['candidate_id'],
                        'operation_locator': finding['operation_locator'],
                        'property_id': finding['contract']['property_id'],
                        'missing_obligations': finding['missing_obligations']}
                        for finding in result['findings'] if finding['analysis_state'] == 'BLOCKED'],
                    'counts': result['counts'], 'accounting': result['accounting'], 'identity': result['identity'],
                    'private_package_valid': True, 'complete_copy_valid': True,
                    'share_authority': share['verification_availability'],
                    'package_sha256': hashes(bundle), 'copy_sha256': hashes(copied)})
                finish()
                print('Completed component ' + unit + ': ' + str(len(expected)) + ' files, '
                      + str(result['counts']['candidate_total']) + ' candidates', flush=True)
        assert {path: digest for row in results for path, digest in row['source_inventory'].items()} == inventory
        assert {str(path.relative_to(source_root)): sha(path) for path in sorted(source_root.rglob('*.py'))} == inventory
        assert source_fingerprint(ROOT) == metadata['source_and_test_fingerprint']
        assert sha(Path(__file__)) == metadata['script_sha256']
        assert sha(HERE / 'inventory-protocol.json') == metadata['protocol_sha256']
        status = 'SOURCE_INVENTORY_DIAGNOSTIC_COMPLETED_WITH_READINESS_LIMITS'
        summary = finish()
        print('Full byte coverage completed: ' + str(summary['covered_files']) + '/' + str(len(files)), flush=True)
        return 0
    except BaseException as error:
        status = 'COMPONENT_STATIC_COVERAGE_STOPPED'
        finish(type(error).__name__)
        print('Component coverage stopped: ' + type(error).__name__, flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
