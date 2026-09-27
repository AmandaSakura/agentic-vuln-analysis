import io
import json
from urllib.error import HTTPError

import pytest

from cv_agent.domain.chat import ChatMessage
from cv_agent.evaluation.metrics import provider_usage
from cv_agent.runtime.model import OpenAICompatibleChatModel


QUESTIONS = {'route': {'type': 'choice', 'criteria': {'scan': 'Inspect', 'deep': 'Deep review'}}}


def response():
    return {'model': 'jev-test', 'answers': {'route': {
        'type': 'choice', 'choice': 'scan', 'confidence': 0.9,
        'probabilities': {'scan': 0.9, 'deep': 0.1}}},
        'usage': {'input_tokens': 100, 'output_tokens': 2}}


def model(events):
    return OpenAICompatibleChatModel(base_url='https://api.typesafe.ai/v1', model='jev-latest',
        api_key='fake-jev-key', temperature=0, timeout_seconds=10,
        protocol='jev-systemone', observer=events.append)


def messages():
    return [ChatMessage(role='user', content=json.dumps({'state': {'source': 'code'}, 'questions': QUESTIONS}))]


def mock_http(monkeypatch, raw, captured):
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return json.dumps(raw).encode()
    def send(request, **kwargs):
        captured.append(request)
        return Response()
    monkeypatch.setattr('urllib.request.urlopen', send)


def test_native_jev_request_uses_gated_transport_and_counts_usage_once(monkeypatch):
    requests, events, gates = [], [], []
    mock_http(monkeypatch, response(), requests)
    monkeypatch.setattr('cv_agent.runtime.model.require_passing_tests', lambda: gates.append(True))
    reply = model(events).complete(messages(), [])
    assert gates == [True]
    assert requests[0].full_url == 'https://api.typesafe.ai/v1/systemone'
    assert requests[0].get_header('Authorization') == 'Bearer fake-jev-key'
    assert json.loads(requests[0].data) == {'model': 'jev-latest', 'state': {'source': 'code'}, 'questions': QUESTIONS}
    assert reply.usage.total_tokens == 102
    assert provider_usage(events)['reported_total_tokens'] == 102
    assert provider_usage(events)['requests'] == 1
    assert 'fake-jev-key' not in json.dumps(events)


@pytest.mark.parametrize('change', ['missing', 'unknown', 'nan', 'negative', 'sum', 'wrong_top', 'usage'])
def test_invalid_jev_answers_fail_without_retry_and_keep_usage(monkeypatch, change):
    raw = response()
    answer = raw['answers']['route']
    if change == 'missing': raw['answers'] = {}
    elif change == 'unknown': answer['probabilities'] = {'other': 1.0}; answer['choice'] = 'other'
    elif change == 'nan': answer['confidence'] = float('nan')
    elif change == 'negative': answer['probabilities'] = {'scan': 1.1, 'deep': -0.1}
    elif change == 'sum': answer['probabilities'] = {'scan': 0.9, 'deep': 0.9}
    elif change == 'wrong_top': answer['choice'] = 'deep'
    elif change == 'usage': raw['usage']['input_tokens'] = -1
    requests, events = [], []
    mock_http(monkeypatch, raw, requests)
    with pytest.raises(ValueError): model(events).complete(messages(), [])
    usage = provider_usage(events)
    assert len(requests) == usage['requests'] == usage['invalid_responses'] == 1
    assert usage['reported_total_tokens'] == (0 if change == 'usage' else 102)


def test_jev_gate_failure_prevents_http(monkeypatch):
    def reject(): raise RuntimeError('pytest failed')
    monkeypatch.setattr('cv_agent.runtime.model.require_passing_tests', reject)
    events = []
    with pytest.raises(RuntimeError, match='pytest failed'): model(events).complete(messages(), [])
    assert events == []


def test_jev_http_error_keeps_usage_and_redacts_secret(monkeypatch):
    def reject(*args, **kwargs):
        raise HTTPError('https://api.typesafe.ai/v1/systemone', 400, 'bad', {}, io.BytesIO(
            json.dumps({'error': 'fake-jev-key', 'usage': {'input_tokens': 5, 'output_tokens': 1}}).encode()))
    monkeypatch.setattr('urllib.request.urlopen', reject)
    events = []
    with pytest.raises(RuntimeError) as error: model(events).complete(messages(), [])
    assert 'fake-jev-key' not in str(error.value) + json.dumps(events)
    assert provider_usage(events)['reported_total_tokens'] == 6
