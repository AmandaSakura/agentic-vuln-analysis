import pytest

from cv_agent.evaluation.discovery import score_discovery


def inventory():
    return {'systems': ['E3'], 'subjects': [{
        'repository_id': 'subject-01', 'repository_url': 'https://github.com/example/project',
        'commit': 'a' * 40, 'source_prefix': 'src', 'discovery': {'parse_errors': []},
        'candidates': [
            {'case_id': 'c1', 'path': 'engine.py::entry@1-10', 'line': 3},
            {'case_id': 'c2', 'path': 'engine.py::entry@1-10', 'line': 7}],
        'selected_case_ids': ['c1'],
    }]}


def reference(identity='r1', line=3, commit='a' * 40):
    return {'entry_id': identity, 'report_id': 'advisory-1',
            'repo_url': 'https://github.com/example/project', 'commit': commit, 'verify': 1,
            'critical_operation': {'file': 'src/engine.py', 'line': line}}


def prediction(identity='c1', label='VULNERABLE', status='completed'):
    return {'case_id': identity, 'system': 'E3', 'predicted_label': label, 'status': status}


def test_exact_location_matching_and_unreviewed_denominators():
    report = score_discovery(inventory(), [prediction()], [reference(), reference('r2', 7)])
    assert report['reference_entries'] == 2
    assert report['discovered_entries'] == 2
    assert report['discovery_recall'] == 1
    system = report['systems']['E3']
    assert system['detected_entries'] == 1
    assert system['observed_reference_recall'] == 0.5
    assert system['unreviewed_candidates'] == 1
    assert system['provisional'] is True
    assert system['false_positive_rate'] is None
    assert system['detected_advisories'] == 1


def test_nearby_findings_and_other_commits_do_not_count_as_hits_or_negatives():
    report = score_discovery(inventory(), [prediction()], [reference(line=4), reference('r2', commit='b'*40)])
    assert report['reference_entries'] == 1
    assert report['excluded_reference_entries'] == 1
    assert report['discovered_entries'] == 0
    assert report['systems']['E3']['detected_entries'] == 0
    assert report['systems']['E3']['unmatched_vulnerable_predictions'] == 1
    assert report['systems']['E3']['false_positive_rate'] is None


@pytest.mark.parametrize('rows', [[], [prediction(status='failed', label=None)],
                                  [prediction(status='abstained', label='ABSTAIN')]])
def test_absent_failed_and_abstained_results_cannot_count_as_detection(rows):
    report = score_discovery(inventory(), rows, [reference()])
    assert report['systems']['E3']['detected_entries'] == 0
    assert report['systems']['E3']['observed_reference_recall'] == 0


def test_duplicate_results_and_unknown_candidates_are_rejected():
    with pytest.raises(ValueError, match='Duplicate'):
        score_discovery(inventory(), [prediction(), prediction()], [reference()])
    with pytest.raises(ValueError, match='Unknown'):
        score_discovery(inventory(), [prediction('invented')], [reference()])


def test_unknown_reference_location_is_explicit_not_silently_dropped():
    label = reference()
    label['critical_operation'] = None
    report = score_discovery(inventory(), [], [label])
    assert report['reference_entries'] == 1
    assert report['unscorable_reference_entries'] == ['r1']
    assert report['claim_eligible'] is False
