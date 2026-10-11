"""Seal actual final gate and preservation receipts; never replace old results."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from record_final_freeze import fingerprint


ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
WORK=ROOT/'artifacts/design_review_recovery_20261001'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    destination=HERE/'final-validation.json'
    if destination.exists():raise FileExistsError('Final receipt already exists')
    frozen=json.loads((HERE/'final-source-freeze.json').read_text())
    final=fingerprint()
    if final['sha256']!=frozen['sha256']:raise ValueError('Source/tests changed during final validation')
    log=WORK/'final_full_pytest_attempt2.log'
    match=re.search(r'^([0-9]+) passed in ([0-9.]+)s',log.read_text(),re.M)
    if match is None:raise ValueError('A complete passing final pytest receipt is required')
    exit_status=(WORK/'final_full_pytest_attempt2.exit').read_text().strip()
    if exit_status!='0':raise ValueError('Full pytest exit was not zero')
    harness_path=HERE/'final-harness-check.json'
    harness=json.loads(harness_path.read_text())
    if harness.get('status')!='PASS':raise ValueError('Harness check did not pass')
    baseline=json.loads((WORK/'baseline.json').read_text())
    preserved={path:sha(ROOT/path)==digest for path,digest in baseline['historical_report_sha256'].items()}
    if not all(preserved.values()):raise ValueError('A historical report/source artifact changed')
    # This is mechanical equality of historical experiment/config bytes only;
    # no label is parsed, output, selected or sent to the detector.
    legacy_paths=[p for p in baseline['source_sha256']if p.startswith(('configs/','scripts/'))]
    legacy_equal=all(sha(ROOT/p)==baseline['source_sha256'][p]for p in legacy_paths)
    if not legacy_equal:raise ValueError('Historical configuration/script bytes changed')
    release=HERE/'release-final-patch1'
    bundle=json.loads((release/'bundle-receipt.json').read_text())
    if sha(release/bundle['archive'])!=bundle['sha256']:raise ValueError('Final release ZIP hash differs')
    source_manifest=json.loads((release/'source/source-manifest.json').read_text())
    if not all(sha(ROOT/'src/cv_agent'/entry['path'])==entry['sha256']for entry in source_manifest['included']):
        raise ValueError('Installed source snapshot differs from final validated source')
    extracted=[json.loads((release/f'extracted-bundle-acceptance-{n}.json').read_text())for n in (1,2)]
    if not all(r['accepted']and r['archive_sha256']==bundle['sha256']for r in extracted):
        raise ValueError('Extracted clean installs do not bind the final archive')
    artifact_paths=['final_full_pytest_attempt1.log','final_full_pytest_attempt2.log',
        'v2_stage_failures_before.log','v2_presentation_failure_before.log','v2_stage_count_before.log',
        'final_v2_controls.log','dependency_binding_before.log','dependency_cli_layout_after.log']
    receipt={'schema':'recovery-final-validation-v1','recorded_at_utc':datetime.now(timezone.utc).isoformat(),
        'source_tests_freeze_sha256':frozen['sha256'],'unchanged_during_final_validation':True,
        'full_pytest':{'command':'uv run --no-sync pytest','exit_code':0,'passed':int(match[1]),'seconds':float(match[2]),
            'log':log.relative_to(ROOT).as_posix(),'log_sha256':sha(log)},
        'harness':{'command':'uv run --no-sync cv-agent harness-check','passed':True,'receipt':harness_path.relative_to(ROOT).as_posix(),'sha256':sha(harness_path)},
        'prior_full_suite':{'failed':15,'passed':2904,'log':'artifacts/design_review_recovery_20261001/final_full_pytest_attempt1.log'},
        'preservation':{'all_previous_reports_unchanged':True,'historical_report_files':len(preserved),
            'previous_config_and_script_files_unchanged':True,'config_script_files':len(legacy_paths)},
        'logs':{p:{'path':(WORK/p).relative_to(ROOT).as_posix(),'sha256':sha(WORK/p)}for p in artifact_paths},
        'real_model_requests':0,'network':False,'third_party_target_execution':False,
        'missing_actual_user_failure':'NOT_REPRODUCED_MISSING_INPUT',
        'human_quality_and_value':'NOT_MEASURED',
        'fresh_additional_reviewer':'NOT_COMPLETED; no independent review pass claimed',
        'fixed_trial_release':{'archive':(release/bundle['archive']).relative_to(ROOT).as_posix(),
            'sha256':bundle['sha256'],'bytes':bundle['bytes'],'wheel_sha256':bundle['wheel_sha256'],
            'source_tree_sha256':bundle['source_tree_sha256'],'included_source_files':len(source_manifest['included']),
            'same_final_source':True,'external_clean_installs':2,'matched_hashes_per_extraction':[r['verified_file_count']for r in extracted]},
        'historic_gates':{'G_A':'NO','GP2':'NOT_ENABLED','GP3':'NOT_MEASURED','GP4':'NOT_MEASURED'}}
    destination.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'receipt':destination.relative_to(ROOT).as_posix(),'passed':receipt['full_pytest']['passed'],
        'seconds':receipt['full_pytest']['seconds'],'preserved_report_files':len(preserved)}))


if __name__=='__main__':main()
