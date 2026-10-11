"""Seal final typed-receipt revision without overwriting prior gate receipts."""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re
from record_final_freeze import fingerprint

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
WORK=ROOT/'artifacts/design_review_recovery_20261001'


def load(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    destination=HERE/'final-validation-patch2.json'
    if destination.exists():raise FileExistsError('Final typed-receipt validation already sealed')
    frozen=load(HERE/'final-source-freeze-patch2.json')
    assert fingerprint()['sha256']==frozen['sha256']
    log=WORK/'final_full_pytest_attempt3.log'
    match=re.search(r'^([0-9]+) passed in ([0-9.]+)s',log.read_text(),re.M)
    assert match and (WORK/'final_full_pytest_attempt3.exit').read_text().strip()=='0'
    harness=HERE/'final-harness-check-patch2.json';assert load(harness)['status']=='PASS'
    baseline=load(WORK/'baseline.json')
    assert all(sha(ROOT/path)==digest for path,digest in baseline['historical_report_sha256'].items())
    legacy=[p for p in baseline['source_sha256']if p.startswith(('configs/','scripts/'))]
    assert all(sha(ROOT/p)==baseline['source_sha256'][p]for p in legacy)
    release=HERE/'release-final-patch2';bundle=load(release/'bundle-receipt.json')
    assert sha(release/bundle['archive'])==bundle['sha256']
    manifest=load(release/'source/source-manifest.json')
    assert all(sha(ROOT/'src/cv_agent'/entry['path'])==entry['sha256']for entry in manifest['included'])
    extracted=[load(release/f'extracted-bundle-acceptance-{i}.json')for i in (1,2)]
    assert all(r['accepted']and r['archive_sha256']==bundle['sha256']for r in extracted)
    scope_logs=['scope_receipt_before.log','scope_receipt_after.log']
    receipt={'schema':'recovery-final-validation-v1','revision':'patch2',
        'recorded_at_utc':datetime.now(timezone.utc).isoformat(),
        'source_tests_freeze_sha256':frozen['sha256'],'source_test_files':len(frozen['files']),
        'unchanged_during_final_validation':True,
        'full_pytest':{'command':'uv run --no-sync pytest','exit_code':0,'passed':int(match[1]),'seconds':float(match[2]),
            'log':log.relative_to(ROOT).as_posix(),'log_sha256':sha(log)},
        'harness':{'command':'uv run --no-sync cv-agent harness-check','passed':True,
            'receipt':harness.relative_to(ROOT).as_posix(),'sha256':sha(harness)},
        'previous_verified_patch1_receipt':'audit/product_recovery_20261001/final-validation.json',
        'preservation':{'all_previous_reports_unchanged':True,'historical_report_files':len(baseline['historical_report_sha256']),
            'previous_config_and_script_files_unchanged':True,'config_script_files':len(legacy)},
        'RF06':{'before_failed':1,'after_affected_passed':37,'after_seconds':5.32,
            'returned_receipt_immutable':True,'persisted_package_mutation_claim':False,
            'logs':{p:{'path':(WORK/p).relative_to(ROOT).as_posix(),'sha256':sha(WORK/p)}for p in scope_logs}},
        'fixed_trial_release':{'archive':(release/bundle['archive']).relative_to(ROOT).as_posix(),
            'sha256':bundle['sha256'],'bytes':bundle['bytes'],'wheel_sha256':bundle['wheel_sha256'],
            'source_tree_sha256':bundle['source_tree_sha256'],'included_source_files':len(manifest['included']),
            'same_final_source':True,'external_clean_installs':2,'matched_hashes_per_extraction':[r['verified_file_count']for r in extracted]},
        'quality_receipt':'audit/product_recovery_20261001/quality-final-patch2/summary.json',
        'real_model_requests':0,'external_network_requests':0,'target_execution_experiments':0,
        'missing_actual_user_failure':'NOT_REPRODUCED_MISSING_INPUT','human_quality_and_value':'NOT_MEASURED',
        'fresh_additional_reviewer':'NOT_COMPLETED; no independent review pass claimed',
        'historic_gates':{'G_A':'NO','GP2':'NOT_ENABLED','GP3':'NOT_MEASURED','GP4':'NOT_MEASURED'}}
    destination.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'receipt':str(destination),'passed':int(match[1]),'seconds':float(match[2]),'files':len(frozen['files'])}))


if __name__=='__main__':main()
