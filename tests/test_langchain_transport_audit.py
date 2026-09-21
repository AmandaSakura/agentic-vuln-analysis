import importlib
import json
from pathlib import Path

import pytest


@pytest.fixture
def audit(monkeypatch):
    return importlib.import_module('cv_agent.evaluation.diagnostics.audit_langchain_transport')


def log_text(response):
    return ('=== REQUEST INFO ===\nAuthorization: Bearer local-secret\n'
            '=== API REQUEST 1 ===\nAuthorization: Bearer oauth-secret\nBody:\n'
            '{"project":"private-project","request":{"generationConfig":{"temperature":0}}}\n\n'
            '=== API RESPONSE 1 ===\nStatus: 200\nHeaders:\nPrivate: hidden\nBody:\n'
            + json.dumps({'response': response}) + '\n\n=== RESPONSE ===\nStatus: 200\n')


def event(response_id, choices):
    return {'event': 'model_response_received', 'case_id': 'case', 'system': 'sample',
            'raw_response': {'id': response_id, 'choices': choices,
                             'usage': {'total_tokens': 2311}}}


def test_native_block_is_bound_to_response_and_keeps_secrets_out(audit):
    native = {'responseId': 'blocked-id', 'promptFeedback': {
        'blockReason': 'OTHER', 'blockReasonMessage': 'private message'},
        'usageMetadata': {'totalTokenCount': 2311, 'thoughtsTokenCount': 488}}
    records = audit.native_records(log_text(native))
    result = audit.classify_response(event('blocked-id', []), records)
    assert result['diagnosis'] == 'upstream_blocked'
    assert result['block_reason'] == 'OTHER'
    assert result['reported_total_tokens'] == 2311
    assert result['upstream_total_tokens'] == 2311
    assert result['upstream_max_output_tokens'] is None
    assert result['upstream_candidate_count'] == 0
    serialized = json.dumps([records, result])
    for private in ('local-secret', 'oauth-secret', 'private-project', 'private message', 'hidden'):
        assert private not in serialized


def test_valid_control_unknown_empty_and_unrelated_block_remain_distinct(audit):
    records = audit.native_records(log_text({'responseId': 'blocked-id',
        'promptFeedback': {'blockReason': 'OTHER'}, 'usageMetadata': {}}))
    assert audit.classify_response(event('other-id', []), records)['diagnosis'] == 'empty_response_unresolved'
    records += audit.native_records(log_text({'responseId': 'good-id',
        'candidates': [{'content': {'parts': [{'functionCall': {'name': 'run_static_check'}}]}}],
        'usageMetadata': {'totalTokenCount': 2311}}))
    result = audit.classify_response(event('good-id', [{'message': {'tool_calls': [{}]}}]), records)
    assert result['diagnosis'] == 'nonempty_choices'
    assert result['upstream_candidate_count'] == 1
    empty_native = audit.native_records(log_text({'responseId': 'empty-id', 'usageMetadata': {}}))
    assert audit.classify_response(event('empty-id', []), empty_native)['diagnosis'] == 'upstream_empty_unresolved'


def test_conflicting_response_ids_are_not_used_as_evidence(audit):
    first = log_text({'responseId': 'same', 'promptFeedback': {'blockReason': 'OTHER'}})
    second = log_text({'responseId': 'same', 'candidates': [{}]})
    with pytest.raises(ValueError, match='Conflicting'):
        audit.classify_response(event('same', []), audit.native_records(first + second))


def test_usage_audit_includes_transport_probes_once(tmp_path, monkeypatch):
    from cv_agent.evaluation.diagnostics.summarize_live_usage import audit_usage
    directory = tmp_path / 'artifacts/langchain_transport_probe/run'
    directory.mkdir(parents=True)
    (directory / 'metadata.json').write_text('{}')
    events = [{'event': 'model_start'}, event('blocked', []),
              {'event': 'model_invalid_response', 'summary': {'usage': {'total_tokens': 2311}}}]
    events[1]['summary'] = {'usage': {'total_tokens': 2311}}
    (directory / 'events.jsonl').write_text('\n'.join(map(json.dumps, events)))
    totals = audit_usage(tmp_path)['totals']
    assert totals['requests'] == 1
    assert totals['reported_total_tokens'] == 2311
    assert totals['invalid_responses'] == 1
