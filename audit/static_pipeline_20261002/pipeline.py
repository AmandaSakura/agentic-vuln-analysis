"""Exercise only the public local static delivery flow on owned source."""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from cv_agent.application.product_boundary import worker_environment


def hashes(folder):
    return {str(path.relative_to(folder)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(folder.rglob('*')) if path.is_file()}


def cli(log_root, name, arguments, *, expected=0):
    result = subprocess.run([sys.executable, '-m', 'cv_agent', *map(str, arguments)],
                            capture_output=True, text=True, timeout=150, env=worker_environment())
    for suffix, text in [('stdout.json', result.stdout), ('stderr.txt', result.stderr)]:
        path = log_root / (name + '.' + suffix)
        path.write_text(text)
        os.chmod(path, 0o600)
    assert result.returncode == expected, (name, result.returncode, result.stderr, result.stdout)
    return json.loads(result.stdout)


def build_bundle(source, output):
    result = cli(output.parent, output.name + '-review',
                 ['review', source, '--output', output, '--profile', 'product_triage_v2'])
    assert result['run_state'] == 'COMPLETED'
    assert result['accounting']['model_requests'] == result['accounting']['target_executions'] == 0
    assert result == json.loads((output / 'result.json').read_text())
    return output


def exact_source(source, row):
    locator = row['payload']['operation_locator']
    text = (source / locator['source_path']).read_text()
    coordinates = tuple(locator[key] for key in ('start_line', 'end_line', 'start_col_utf8', 'end_col_utf8'))
    operations = [node for node in ast.walk(ast.parse(text)) if isinstance(node, ast.Call)
                  and (node.lineno, node.end_lineno, node.col_offset, node.end_col_offset) == coordinates]
    assert len(operations) == 1
    return ast.get_source_segment(text, operations[0])


def check_delivery(source, bundle, row):
    log_root = bundle.parent
    name = bundle.name
    assert cli(log_root, name + '-verify', ['verify', bundle])['valid']
    copied = log_root / (name + '-copy')
    shutil.copytree(bundle, copied)
    assert hashes(bundle) == hashes(copied)
    assert cli(log_root, name + '-copy-verify', ['verify', copied])['valid']
    view = cli(log_root, name + '-view', ['view', copied, '--candidate-id', row['payload']['candidate_id'],
                                        '--source-root', source])
    assert view['candidate_id'] == row['payload']['candidate_id']
    assert view['operation_locator'] == row['payload']['operation_locator']
    assert view['source'] == exact_source(source, row)
    report = (copied / 'report.md').read_text()
    assert row['payload']['candidate_id'] in report and row['canonical_state'] in report
    share = json.loads((copied / 'share.json').read_text())
    assert share['verification_availability'] == 'NOT_VERIFIABLE'
    assert all(item['property_state'] == 'UNKNOWN' for item in share['findings'])
    return {'checks': {key: True for key in ('review', 'verify', 'copy_verify', 'view', 'report', 'share')},
            'copy_bundle': str(copied), 'original_sha256': hashes(bundle), 'copy_sha256': hashes(copied)}


def check_boundaries(source, bundle, row):
    log_root = bundle.parent
    bad = log_root / 'deliberately-corrupted-copy'
    shutil.copytree(bundle, bad)
    evidence = next((bad / '.private/evidence').glob('*.json'))
    evidence.write_text('{}\n')
    corrupted = cli(log_root, 'negative-evidence-corruption', ['verify', bad], expected=2)
    assert not corrupted['valid']
    before = (source / 'entry.py').read_bytes()
    (source / 'entry.py').write_bytes(before + b'\n# owned drift control\n')
    drift = cli(log_root, 'negative-source-drift', ['view', bundle, '--candidate-id', row['payload']['candidate_id'],
                                                '--source-root', source], expected=2)
    assert not drift['valid'] and 'SOURCE_DRIFT' in drift['reason_code']
    (source / 'entry.py').write_bytes(before)
    assert cli(log_root, 'restored-source-positive', ['view', bundle,
        '--candidate-id', row['payload']['candidate_id'], '--source-root', source])['source'] == exact_source(source, row)
    original_hashes = hashes(bundle)
    cli(log_root, 'negative-existing-output', ['review', source, '--output', bundle,
        '--profile', 'product_triage_v2'], expected=2)
    assert hashes(bundle) == original_hashes
    tiny = log_root / 'one-byte-share-positive'
    result = cli(log_root, 'one-byte-share-review', ['review', source, '--output', tiny,
        '--profile', 'product_triage_v2', '--summary-bytes', '1'])
    baseline = json.loads((bundle / 'result.json').read_text())
    assert [(f['candidate_id'], f['property_state']) for f in result['findings']] == [
        (f['candidate_id'], f['property_state']) for f in baseline['findings']]
    assert result['identity']['semantic_engine_digest'] == baseline['identity']['semantic_engine_digest']
    assert result['identity']['delivery_policy_digest'] != baseline['identity']['delivery_policy_digest']
    share = json.loads((tiny / 'share.json').read_text())
    assert not share['findings'] and share['omitted_candidates'] == share['candidate_total']
    assert cli(log_root, 'one-byte-share-verify', ['verify', tiny])['valid']
    return {key: True for key in ('evidence_corruption_rejected', 'source_drift_rejected',
                                  'existing_output_preserved', 'one_byte_share_preserves_private_state')}


def post_reply_delivery(row):
    delivery = row['delivery']
    original = Path(row['bundle'])
    copied = Path(delivery['copy_bundle'])
    assert hashes(original) == delivery['original_sha256']
    assert hashes(copied) == delivery['copy_sha256']
    assert cli(original.parent, original.name + '-post-reply-verify', ['verify', original])['valid']
    assert cli(original.parent, original.name + '-post-reply-copy-verify', ['verify', copied])['valid']
    return {'original_unchanged': True, 'copy_unchanged': True,
            'original_reverified': True, 'copy_reverified': True}
