import json

import pytest

from cv_agent.domain.chat import ChatMessage
from cv_agent.evaluation.execution import run_candidate
from cv_agent.evaluation.metrics import provider_usage
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentSystemVersion
from cv_agent.runtime.budget import Budget
from cv_agent.runtime.jev import JevRoutingConfig
from cv_agent.runtime.journal import Journal
from cv_agent.runtime.model import OpenAICompatibleChatModel
from test_agentic_workflow import _index_and_candidate, _models
from test_jev_routing import router_model


def test_complete_evaluation_uses_native_jev_and_chat_experts_in_one_journal(tmp_path, monkeypatch):
    monkeypatch.setenv('JEV_API_KEY', 'fake-router-secret')
    scripted = _models()
    router = router_model()
    endpoints = []
    class Response:
        def __init__(self, raw): self.raw = raw
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return json.dumps(self.raw).encode()
    def send(request, **kwargs):
        endpoints.append(request.full_url)
        body = json.loads(request.data)
        if request.full_url.endswith('/systemone'):
            reply = router.complete([ChatMessage(role='user', content=json.dumps(
                {key: body[key] for key in ('state', 'questions')}))], [])
            return Response(dict(model='jev-test', answers=json.loads(reply.content),
                                 usage={'input_tokens': 20, 'output_tokens': 3}))
        mandate = body['messages'][0]['content']
        role = next(expert.expert for expert in FULL_SYSTEM_HARNESS.experts if mandate.startswith(expert.mandate))
        reply = scripted[role].complete([], [])
        return Response({'model': f'chat-{role}', 'choices': [{'message': OpenAICompatibleChatModel._message_payload(
            ChatMessage(role='assistant', content=reply.content, tool_calls=reply.tool_calls))}],
            'usage': {'prompt_tokens': 10, 'completion_tokens': 2, 'total_tokens': 12}})
    monkeypatch.setattr('urllib.request.urlopen', send)
    index, candidate = _index_and_candidate()
    journal = Journal(tmp_path / 'events.jsonl')
    row = run_candidate(index, candidate, AgentSystemVersion.E4_GRAPH_MULTI, journal, Budget(20, 30),
        report_system='E4_JEV', model_config={'base_url': 'https://chat.invalid/v1', 'model': 'chat-test',
                                            'temperature': 0, 'timeout_seconds': 1}, api_key='fake-expert-secret',
        routing_config=JevRoutingConfig(model='jev-latest', timeout_seconds=1, min_choice_probability=0.85, mode='active'))
    assert row['status'] == 'abstained', row.get('error')
    assert row['system'] == 'E4_JEV'
    assert endpoints.count('https://api.typesafe.ai/v1/systemone') == 1
    assert endpoints.count('https://chat.invalid/v1/chat/completions') == 6
    events = [json.loads(line) for line in journal.path.read_text().splitlines()]
    assert row['model_calls'] == provider_usage(events)['requests'] == 7
    assert row['verdict']['usage']['total_tokens'] == provider_usage(events)['reported_total_tokens'] == 95
    assert {event['role'] for event in events if event['event'] == 'model_start'} == {'routing', 'scan', 'taint', 'authz'}
    decisions = [event for event in events if event['event'] == 'routing_decision']
    assert len(decisions) == 1
    assert decisions[0]['routing']['spec_version'] == 2
    assert all(item['applied'] for item in decisions[0]['routing']['decisions'].values())
    assert 'fake-router-secret' not in journal.path.read_text()
    assert 'fake-expert-secret' not in journal.path.read_text()


def test_missing_jev_key_fails_before_any_trial_model_request(tmp_path, monkeypatch):
    monkeypatch.delenv('JEV_API_KEY', raising=False)
    index, candidate = _index_and_candidate()
    row = run_candidate(index, candidate, AgentSystemVersion.E4_GRAPH_MULTI, Journal(tmp_path / 'events.jsonl'),
        Budget(10, 10), report_system='E4_JEV', model_config={}, api_key='offline',
        routing_config=JevRoutingConfig(model='jev-latest', timeout_seconds=1, min_choice_probability=0.85))
    assert row['status'] == 'failed'
    assert 'JEV_API_KEY' in row['error']
    assert row['model_calls'] == 0


def test_routing_trial_cannot_be_mislabeled_as_original_e4(tmp_path):
    index, candidate = _index_and_candidate()
    row = run_candidate(index, candidate, AgentSystemVersion.E4_GRAPH_MULTI, Journal(tmp_path / 'events.jsonl'),
        Budget(10, 10), model_config={}, api_key='offline',
        routing_config=JevRoutingConfig(model='jev-latest', timeout_seconds=1, min_choice_probability=0.85))
    assert row['status'] == 'failed'
    assert 'E4_JEV' in row['error']
    assert row['model_calls'] == 0


def test_off_configuration_needs_no_jev_key(monkeypatch):
    monkeypatch.delenv('JEV_API_KEY', raising=False)
    model = JevRoutingConfig(model='jev-1.13.0', timeout_seconds=1,
                             min_choice_probability=0.85, mode='off').build_model(None)
    assert model.protocol == 'jev-systemone'
    assert model._api_key is None
