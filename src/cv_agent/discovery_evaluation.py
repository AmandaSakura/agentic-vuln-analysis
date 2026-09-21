"""Evaluator-only reference matching; this module is never imported by discovery."""
from collections import Counter
from pathlib import PurePosixPath

from .heldout_manifest import repository_key


def score_discovery(inventory: dict, results: list[dict], references: list[dict]) -> dict:
    subjects = {}
    candidates = {}
    selected = set()
    systems = inventory['systems']
    for subject in inventory['subjects']:
        key = (repository_key(subject['repository_url']), subject['commit'])
        if key in subjects:
            raise ValueError('Duplicate repository/commit subject')
        subjects[key] = subject
        for candidate in subject['candidates']:
            identity = candidate['case_id']
            if identity in candidates:
                raise ValueError('Duplicate candidate identity')
            path = str(PurePosixPath(subject['source_prefix']) / candidate['path'].split('::', 1)[0])
            candidates[identity] = (*key, path, candidate['line'])
        selected.update(subject['selected_case_ids'])
    if selected - candidates.keys():
        raise ValueError('Unknown selected candidate')
    observed = {}
    valid_statuses = {'completed', 'abstained', 'failed', 'interrupted', 'not_run'}
    for row in results:
        key = (row['case_id'], row['system'])
        if key in observed:
            raise ValueError('Duplicate candidate/system result')
        if key[0] not in selected or key[1] not in systems:
            raise ValueError('Unknown or unselected candidate/system result')
        if row['status'] not in valid_statuses:
            raise ValueError('Unknown result status')
        if row['status'] == 'completed' and row['predicted_label'] not in {'SAFE', 'VULNERABLE'}:
            raise ValueError('Completed result requires a material prediction')
        observed[key] = row

    entries = {}
    advisories = {}
    unscorable = []
    excluded = 0
    seen = set()
    for row in references:
        identity = row['entry_id']
        if identity in seen:
            raise ValueError('Duplicate reference entry')
        seen.add(identity)
        key = (repository_key(row['repo_url']), row['commit'])
        if key not in subjects or row.get('verify') not in (1, True):
            excluded += 1
            continue
        reference = row['critical_operation']
        valid_location = (isinstance(reference, dict) and isinstance(reference.get('file'), str)
                          and type(reference.get('line')) is int and reference['line'] > 0)
        entries[identity] = ((*key, str(PurePosixPath(reference['file'])), reference['line'])
                             if valid_location else None)
        advisories[identity] = (key[0], row['report_id'])
        if not valid_location:
            unscorable.append(identity)
    locations = set(candidates.values())
    discovered = {identity for identity, location in entries.items() if location in locations}
    total = len(entries)
    system_reports = {}
    for system in systems:
        rows = [observed.get((identity, system), {'status': 'not_run', 'predicted_label': None})
                for identity in sorted(selected)]
        counts = Counter(row['status'] for row in rows)
        predictions = {identity for identity in selected
                       if (row := observed.get((identity, system))) is not None
                       and row['status'] == 'completed' and row['predicted_label'] == 'VULNERABLE'}
        predicted_locations = {candidates[identity] for identity in predictions}
        detected = {identity for identity, location in entries.items() if location in predicted_locations}
        reviewed = counts['completed'] + counts['abstained']
        system_reports[system] = {
            'selected_candidates': len(selected), 'status_counts': dict(counts),
            'unreviewed_candidates': len(candidates) - reviewed,
            'detected_entries': len(detected), 'detected_entry_ids': sorted(detected),
            'observed_reference_recall': len(detected) / total if total else None,
            'reference_advisories': len(set(advisories.values())),
            'detected_advisories': len({advisories[identity] for identity in detected}),
            'unmatched_vulnerable_predictions': sum(
                candidates[identity] not in entries.values() for identity in predictions),
            'false_positive_rate': None,
            'provisional': reviewed != len(candidates) or bool(unscorable),
        }
    return {
        'claim_eligible': False, 'reference_entries': total,
        'excluded_reference_entries': excluded, 'unscorable_reference_entries': unscorable,
        'discovered_entries': len(discovered), 'discovered_entry_ids': sorted(discovered),
        'discovery_recall': len(discovered) / total if total else None,
        'candidate_count': len(candidates), 'systems': system_reports,
        'parse_errors': {subject['repository_id']: subject['discovery']['parse_errors']
                         for subject in subjects.values()},
        'matching_protocol': 'Exact repository, commit, critical-operation file and source line.',
        'limitations': [
            'References are dataset-verified positives; unmatched predictions are not established false positives.',
            'No verified negative population is provided; false-positive rate is not estimable.',
            'A bounded pilot leaves unreviewed candidates in the reference denominator; observed recall is provisional.',
            'Source-location matches and model predictions do not establish exploit reproduction.',
        ],
    }
