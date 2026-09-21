from cv_agent.heldout_manifest import prepare_heldout
import pytest


def entry(identity,repo,advisory,verified=1):
    return dict(entry_id=identity,repo_url=repo,report_id=advisory,verify=verified,
                commit='a'*40,entry_point='secret-reference-path',critical_operation='answer',trace=['oracle'])


def test_development_repository_and_advisory_cannot_enter_heldout():
    rows=[entry('d','https://github.com/Owner/Dev.git/','r1'),
          entry('shared','https://github.com/other/repo','r1'),
          entry('good','https://github.com/other/repo','r2'),
          entry('unverified','https://github.com/other/repo','r3',0)]
    result=prepare_heldout(rows,['https://github.com/owner/dev'])
    assert set(result['evaluator_labels'])=={'good'}
    assert result['detector_inputs']==[dict(repository_url='https://github.com/other/repo',commit='a'*40)]
    assert {row['reason'] for row in result['excluded']}=={
        'development_repository','development_advisory','unverified'}
    assert result['summary']['verified_fixed_negatives']==0
    assert result['summary']['claim_eligible'] is False


def test_duplicate_reference_ids_are_rejected():
    row=entry('one','https://github.com/other/repo','r1')
    with pytest.raises(ValueError,match='Duplicate'):
        prepare_heldout([row,row],[])


def test_effective_split_excludes_the_pilot_used_for_scanner_development():
    import json
    from pathlib import Path
    from cv_agent.repository_pilot import RepositoryPilotConfig, validate_heldout_membership
    from cv_agent.harness import FULL_SYSTEM_HARNESS
    root = Path(__file__).parents[1]
    frozen = json.loads((root / 'configs/vulngym_heldout_inputs_v3.json').read_text())
    assert frozen['split_version'] == 3
    assert {'https://github.com/langchain-ai/langchain', 'https://github.com/nltk/nltk'} <= set(
        FULL_SYSTEM_HARNESS.development_repositories)
    assert not any(subject['repository_url'] == 'https://github.com/nltk/nltk'
                   for subject in frozen['subjects'])
    next_pilot = RepositoryPilotConfig.model_validate_json((root / 'configs/python_heldout_pilot.json').read_text())
    validate_heldout_membership(next_pilot, frozen)
    used_pilot = RepositoryPilotConfig.model_validate_json((root / 'configs/python_nltk_development_pilot.json').read_text())
    with pytest.raises(ValueError, match='frozen independent'):
        validate_heldout_membership(used_pilot, frozen)
