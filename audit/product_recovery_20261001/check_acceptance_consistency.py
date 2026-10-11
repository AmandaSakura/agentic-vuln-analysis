"""Check final document counts and evidence pointers against actual receipts."""
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path

from record_final_freeze import fingerprint


HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]


def load(path):return json.loads(path.read_text())


def main():
    matrix=load(HERE/'acceptance.json');final=load(HERE/'final-validation-patch2.json')
    suite=matrix['full_suite']['final_attempt']
    assert suite['passed']==final['full_pytest']['passed']
    assert suite['seconds']==final['full_pytest']['seconds']
    assert suite['exit_code']==0
    assert fingerprint()['sha256']==final['source_tests_freeze_sha256']
    for key,prefix,start,stop in [('issues','F',1,23),('tasks','R',0,18),('acceptance_checks','V',1,61)]:
        ids=[row['id']for row in matrix[key]]
        assert len(ids)==len(set(ids))
        assert set(ids)=={f'{prefix}{i:02d}'for i in range(start,stop)}
        for row in matrix[key]:
            assert row['status']and row['classification']and row['finding']
            assert row['evidence']
            for target in row['evidence']:
                filename,_,function=target.partition('::');path=ROOT/filename
                assert path.is_file(),target
                if function:
                    assert function in {n.name for n in ast.walk(ast.parse(path.read_text()))
                        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))},target
    for filename,digest in matrix['evidence_sha256'].items():
        assert hashlib.sha256((ROOT/filename).read_bytes()).hexdigest()==digest,filename
    bundle=load(ROOT/matrix['release']['receipt'])
    assert matrix['release']['zip_sha256']==bundle['sha256']==final['fixed_trial_release']['sha256']
    assert matrix['release']['zip_bytes']==bundle['bytes']==final['fixed_trial_release']['bytes']
    quality=matrix['quality_controls'];reference=load(ROOT/quality['receipt'])
    assert 'patch2'in quality['receipt'],'Quality must bind the final patched source version'
    for key in ('case_count','exact_state_matches','wrong_strong_states','missing_or_duplicate_locations'):
        assert quality[key]==reference[key]
    assert quality['human_independent']is False and quality['accuracy_or_fpr_claim']is False
    assert matrix['history']['G_A']=='NO'and matrix['history']['R17']=='CLOSED_NOT_ENABLED'
    assert matrix['status']=='ENGINEERING_TRIAL_VALIDATED_PRODUCT_USER_HUMAN_GATES_OPEN'
    receipt={'schema':'recovery-acceptance-document-consistency-v1','passed':True,
        'acceptance_sha256':hashlib.sha256((HERE/'acceptance.json').read_bytes()).hexdigest(),
        'verification_sha256':hashlib.sha256((HERE/'verification.md').read_bytes()).hexdigest(),
        'matrix_counts':{'issues':22,'tasks':18,'acceptance_checks':60},
        'status_counts':{key:dict(Counter(row['status']for row in matrix[key]))
            for key in ('issues','tasks','acceptance_checks')},
        'evidence_files_verified':len(matrix['evidence_sha256']),
        'final_source_test_fingerprint_unchanged':True,'full_suite_passed':suite['passed'],
        'same_final_release_and_quality_receipts':True,'user_human_gates_open':True}
    (HERE/'acceptance-consistency.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'passed':True,'evidence_files':receipt['evidence_files_verified'],
        'matrix_counts':receipt['matrix_counts']}))


if __name__=='__main__':main()
