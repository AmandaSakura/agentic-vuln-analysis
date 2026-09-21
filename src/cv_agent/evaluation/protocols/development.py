"""Evidence-aware admission from the fixed ten-trial pilot to the full matrix."""
import json
from collections import Counter

from cv_agent.domain.review import AgentExpertVote
from cv_agent.domain.evidence import ValidationSubject
from cv_agent.evaluation.metrics import provider_usage
from cv_agent.runtime.admission import source_fingerprint
from cv_agent.agents.react import validate_conclusion


_RETRIEVAL_EVIDENCE_PREFIXES = ('local:', 'text:', 'graph:', 'hybrid:')


def require_verification_capability(tools):
    # Admission is necessary, not proof that a particular candidate is supported.
    # Runtime subject/evidence checks remain mandatory for every final verdict.
    available = {status for tool in tools if tool.available for status in tool.validation_statuses}
    if not {'CONFIRMED', 'REFUTED'} <= available:
        raise ValueError('Verification acceptance requires available executed validators for '
                         'CONFIRMED and REFUTED; current tools cannot establish both. No model requests admitted.')


def acceptance_issues(rows, summary, expected, subjects):
    issues = []
    cells = [(row.get('case_id'), row.get('system')) for row in rows]
    if len(expected) != 10 or Counter(cells) != Counter(expected.keys()):
        issues.append('Expected exactly ten distinct declared case/system cells')
    for row in rows:
        cell = (row.get('case_id'), row.get('system'))
        label = expected.get(cell)
        if (row.get('status') != 'completed' or label is None or
                row.get('predicted_label') != label or row.get('ground_truth') != label):
            issues.append(f'{cell}: missing, failed, abstained or incorrect prediction')
            continue
        verdict = row.get('verdict') or {}
        matching = False
        subject = subjects.get(row['case_id'])
        for payload in verdict.get('votes', []):
            try:
                vote = AgentExpertVote.model_validate(payload)
                required = 'CONFIRMED' if label == 'VULNERABLE' else 'REFUTED'
                if vote.label != label or vote.validation_status != required or vote.runtime_mode != 'live':
                    continue
                retrieval_evidence = frozenset(
                    evidence_id for evidence_id in vote.evidence_ids
                    if evidence_id.startswith(_RETRIEVAL_EVIDENCE_PREFIXES)
                )
                validate_conclusion(vote, list(vote.trace), retrieval_evidence, subject=subject)
            except (ValueError, TypeError):
                continue
            matching = True
        if not matching or verdict.get('label') != label or verdict.get('runtime_mode') != 'live':
            issues.append(f'{cell}: no matching candidate-bound executed validator evidence')
    usage = summary['usage']
    if (usage['requests'] <= 0 or usage['responses'] != usage['requests']
            or sum(row.get('model_calls', 0) for row in rows) != usage['requests']
            or any(usage.get(field, 0) != 0 for field in (
                'invalid_responses', 'requests_without_reported_usage', 'usage_conflicts',
                'orphaned_responses', 'duplicate_request_starts'))):
        issues.append('Incomplete, failed or inconsistent request/usage accounting')
    return issues


def transport_issues(events, model_config):
    """Native logging must substantiate configured controls before expansion."""
    if not model_config.get('proxy_log_dir'):
        return []
    starts = {event.get('request_id') for event in events if event['event'] == 'model_start'}
    diagnostics = {event.get('request_id'): event['diagnostic'] for event in events
                   if event['event'] == 'model_proxy_diagnostic'}
    if None in starts or set(diagnostics) != starts or not starts:
        return ['Native diagnostics do not cover every request ID']
    issues = []
    if any(value.get('diagnosis') != 'upstream_response' for value in diagnostics.values()):
        issues.append('Native upstream evidence is blocked, unavailable or conflicting')
    if model_config.get('max_tokens') is not None and any(
            value.get('output_limit_status') != 'matched' for value in diagnostics.values()):
        issues.append('Configured output-token limit is not verified upstream')
    return issues


def require_development_acceptance(root, config, manifest):
    """Revalidate artifacts and current protocol; never trust a boolean pass file."""
    pointer = root / 'artifacts/development_acceptance.json'
    if not pointer.is_file():
        raise ValueError('Ten-trial acceptance is required before the full matrix')
    try:
        directory = root / json.loads(pointer.read_text())['run_directory']
        metadata = json.loads((directory / 'metadata.json').read_text())
        if metadata.get('source_fingerprint') != source_fingerprint(root):
            raise ValueError('Ten-trial acceptance source/config/tests snapshot is stale')
        pilot = metadata['config']
        model_config = json.loads((root / config['model_config']).read_text())
        if (pilot['entry_method'] != config['entry_method'] or metadata['model_config'] != model_config
                or pilot['concurrency'] != config['concurrency']
                or pilot['systems'] != manifest['systems'] or pilot['case_ids'] != manifest['pilot_case_ids']
                or metadata['identity']['datasets'] != manifest['identity']['datasets']):
            raise ValueError('Ten-trial acceptance protocol or dataset does not match full evaluation')
        events = [json.loads(line) for line in (directory / 'events.jsonl').read_text().splitlines()]
        if not events or events[-1].get('event') != 'run_end' or events[-1].get('interrupted'):
            raise ValueError('Ten-trial acceptance run is incomplete or interrupted')
        expected = {(case, system): 'VULNERABLE' if manifest['labels'][case]['vulnerable'] else 'SAFE'
                    for case in pilot['case_ids'] for system in pilot['systems']}
        # Read durable original trial results, not an editable acceptance boolean.
        rows = [{**event['result'], 'ground_truth': expected.get((event['result']['case_id'], event['result']['system']))}
                for event in events if event['event'] == 'trial_result']
        subjects = {case: ValidationSubject.model_validate(value) for case, value in metadata['subjects'].items()}
        issues = acceptance_issues(rows, {'usage': provider_usage(events)}, expected, subjects)
        issues.extend(transport_issues(events, model_config))
        if issues:
            raise ValueError('Ten-trial acceptance failed: ' + '; '.join(issues))
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError('Ten-trial acceptance artifacts are incomplete or invalid') from error
    return directory
