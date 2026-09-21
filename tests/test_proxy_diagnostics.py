import json

import pytest

from cv_agent.runtime.model import OpenAICompatibleChatModel


def test_runtime_records_bound_native_block_without_leaking_credentials(tmp_path, monkeypatch):
    def respond(request, **kwargs):
        request_id = request.get_header('X-cv-agent-request-id')
        assert request_id
        native = {'response': {'responseId': 'native-1',
                  'promptFeedback': {'blockReason': 'OTHER', 'blockReasonMessage': 'secret-native'},
                  'usageMetadata': {'totalTokenCount': 12}}}
        (tmp_path / 'v1-chat-completions-test.log').write_text(
            f'=== REQUEST INFO ===\nX-Cv-Agent-Request-Id: {request_id}\nAuthorization: Bearer secret-local\n'
            '=== API RESPONSE 1 ===\nBody:\n' + json.dumps(native) +
            '\n=== RESPONSE ===\nStatus: 200\n')
        return Response({'id': 'native-1', 'choices': [], 'usage': {'total_tokens': 12}})
    monkeypatch.setattr('urllib.request.urlopen', respond)
    events = []
    model = OpenAICompatibleChatModel(base_url='http://localhost/v1', model='test',
        api_key='secret-local', temperature=0, timeout_seconds=1,
        proxy_log_dir=str(tmp_path), observer=events.append)
    with pytest.raises(ValueError, match='upstream_blocked.*OTHER'):
        model.complete([], [])
    diagnostic = next(e['diagnostic'] for e in events if e['event'] == 'model_proxy_diagnostic')
    assert diagnostic['diagnosis'] == 'upstream_blocked'
    assert diagnostic['upstream_total_tokens'] == 12
    assert 'secret-' not in json.dumps(events)
    from cv_agent.evaluation.metrics import provider_usage
    assert provider_usage(events)['reported_total_tokens'] == 12
    assert provider_usage(events)['invalid_responses'] == 1


class Response:
    def __init__(self, body): self.body = body
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self): return json.dumps(self.body).encode()


@pytest.mark.parametrize('kind', ['unrelated_request', 'wrong_response', 'partial', 'missing'])
def test_missing_or_unmatched_log_never_becomes_block(tmp_path, monkeypatch, kind):
    from cv_agent.runtime import diagnostics as proxy_diagnostics
    monkeypatch.setattr(proxy_diagnostics, 'LOG_WAIT_SECONDS', 0)
    def respond(request, **kwargs):
        request_id = request.get_header('X-cv-agent-request-id')
        if kind == 'unrelated_request': request_id = 'another-request'
        native = {'response': {'responseId': 'wrong' if kind == 'wrong_response' else 'one',
                               'promptFeedback': {'blockReason': 'OTHER'}}}
        if kind != 'missing':
            (tmp_path / 'v1-chat-completions-test.log').write_text(
                f'=== REQUEST INFO ===\nX-Cv-Agent-Request-Id: {request_id}\n'
                '=== API RESPONSE 1 ===\nBody:\n' +
                ('{' if kind == 'partial' else json.dumps(native) + '\n=== RESPONSE ===\n'))
        return Response({'id': 'one', 'choices': [], 'usage': {'total_tokens': 7}})
    monkeypatch.setattr('urllib.request.urlopen', respond)
    events = []
    model = OpenAICompatibleChatModel(base_url='http://localhost/v1', model='test', api_key=None,
        temperature=0, timeout_seconds=1, proxy_log_dir=str(tmp_path), observer=events.append)
    with pytest.raises(ValueError, match='no choices'):
        model.complete([], [])
    diagnostic = next(e['diagnostic'] for e in events if e['event'] == 'model_proxy_diagnostic')
    assert diagnostic['diagnosis'] == 'native_evidence_unavailable'


def test_valid_reply_survives_unavailable_logs(tmp_path, monkeypatch):
    from cv_agent.runtime import diagnostics as proxy_diagnostics
    monkeypatch.setattr(proxy_diagnostics, 'LOG_WAIT_SECONDS', 0)
    monkeypatch.setattr('urllib.request.urlopen', lambda *a, **k:
                        Response({'choices': [{'message': {'content': 'ok'}}]}))
    model = OpenAICompatibleChatModel(base_url='http://localhost/v1', model='test', api_key=None,
        temperature=0, timeout_seconds=1, proxy_log_dir=str(tmp_path / 'absent'))
    assert model.complete([], []).content == 'ok'


def test_collector_waits_for_completed_log_and_preserves_positive_control(tmp_path, monkeypatch):
    from cv_agent.runtime import diagnostics as mod
    path = tmp_path / 'v1-chat-completions-test.log'
    path.write_text('unfinished')
    def finish(_):
        path.write_text('=== REQUEST INFO ===\nX-Cv-Agent-Request-Id: abc\n'
            '=== API RESPONSE 1 ===\nBody:\n' + json.dumps({'response': {
                'responseId': 'one', 'candidates': [{}], 'usageMetadata': {'totalTokenCount': 9}}}) +
            '\n=== RESPONSE ===\n')
    monkeypatch.setattr(mod.time, 'sleep', finish)
    result = mod.collect_diagnostic(tmp_path, 'abc', 'one')
    assert result['diagnosis'] == 'upstream_response'
    assert result['upstream_candidate_count'] == 1
    assert result['upstream_total_tokens'] == 9


def test_collector_rejects_conflicting_evidence(tmp_path):
    from cv_agent.runtime.diagnostics import collect_diagnostic
    for i, feedback in enumerate([{}, {'blockReason': 'OTHER'}]):
        (tmp_path / f'v1-chat-completions-{i}.log').write_text(
            '=== REQUEST INFO ===\nX-Cv-Agent-Request-Id: abc\n'
            '=== API RESPONSE 1 ===\nBody:\n' + json.dumps({'response': {
                'responseId': 'one', 'promptFeedback': feedback}}) + '\n=== RESPONSE ===\n')
    assert collect_diagnostic(tmp_path, 'abc', 'one')['diagnosis'] == 'native_evidence_conflict'


def test_filesystem_timestamp_rounding_does_not_drop_matching_evidence(tmp_path):
    from cv_agent.runtime.diagnostics import collect_diagnostic
    path = tmp_path / 'v1-chat-completions-one.log'
    path.write_text('=== REQUEST INFO ===\nX-Cv-Agent-Request-Id: abc\n'
        '=== API RESPONSE 1 ===\nBody:\n' + json.dumps({'response': {'responseId': 'one'}}) +
        '\n=== RESPONSE ===\n')
    assert collect_diagnostic(tmp_path, 'abc', 'one', path.stat().st_mtime + 0.01)[
        'diagnosis'] == 'upstream_response'


def test_unspecified_native_block_reason_does_not_claim_filter_block(tmp_path):
    from cv_agent.runtime.diagnostics import collect_diagnostic
    (tmp_path / 'v1-chat-completions-one.log').write_text(
        '=== REQUEST INFO ===\nX-Cv-Agent-Request-Id: abc\n'
        '=== API RESPONSE 1 ===\nBody:\n' + json.dumps({'response': {
            'responseId': 'one', 'promptFeedback': {'blockReason': 'BLOCK_REASON_UNSPECIFIED'},
            'candidates': [{}]}}) + '\n=== RESPONSE ===\n')
    result = collect_diagnostic(tmp_path, 'abc', 'one')
    assert result['diagnosis'] == 'upstream_response'
    assert result['block_reason'] is None
