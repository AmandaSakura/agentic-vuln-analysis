"""Behavioral regressions from the complete post-pilot review; no live calls."""
import io
import json
from pathlib import Path
from urllib.error import HTTPError

import pytest

from cv_agent.tools.identity import candidate_subject
from cv_agent.evaluation.metrics import provider_usage
from cv_agent.runtime.model import OpenAICompatibleChatModel
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import Candidate, CodeDocument


def model(events):
    return OpenAICompatibleChatModel(base_url='http://localhost/v1', model='offline',
        api_key='test-secret', temperature=0, timeout_seconds=1, observer=events.append)


def test_subject_changes_when_candidate_line_changes():
    index = RepositoryIndex([CodeDocument(repository_id='repo', path='entry.py', text='one\ntwo')])
    candidate = Candidate(candidate_id='one', case_id='one', repository_id='repo',
                          path='entry.py', line=1, query='')
    assert candidate_subject(index, candidate) != candidate_subject(index, candidate.model_copy(update={'line': 2}))


def test_probe_cannot_stamp_another_index_witness_with_the_callers_subject():
    from cv_agent.code_adapters.python import parse_python_source
    from cv_agent.tools.registry import ToolRegistry, ToolExecutionScope
    from cv_agent.domain.chat import ModelToolCall
    from cv_agent.tools.validation import full_agent_tools
    def index(source):
        return RepositoryIndex(span.document for span in parse_python_source('repo', 'entry.py', source))
    safe = index('def entry(request):\n    return 1\n')
    unsafe = index('def entry(request):\n    return eval(request.args["x"])\n')
    path = next(iter(safe.documents))
    assert path in unsafe.documents
    candidate = Candidate(candidate_id='one', case_id='one', repository_id='repo', path=path, line=1, query='')
    scope = ToolExecutionScope(frozenset({path}), 8192, candidate_path=path, subject=candidate_subject(safe, candidate))
    registry = ToolRegistry(full_agent_tools(unsafe), max_output_bytes=8192)
    result = registry.invoke(ModelToolCall(call_id='one', name='probe_python_eval', arguments={'source_path': path}),
                             allowed=['probe_python_eval'], scope=scope)
    assert result.status == 'blocked'
    assert result.validation_status is None


def test_malformed_success_content_is_not_coerced_to_a_valid_model_reply(monkeypatch):
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return json.dumps({'choices': [{'message': {'content': {'answer': 'SAFE'}}}],
                                          'usage': {'total_tokens': 5}}).encode()
    monkeypatch.setattr('urllib.request.urlopen', lambda *a, **k: Response())
    events = []
    with pytest.raises(ValueError):
        model(events).complete([], [])
    assert provider_usage(events)['reported_total_tokens'] == 5


def test_http_error_retains_usage_and_failure_kind(monkeypatch):
    def reject(*args, **kwargs):
        raise HTTPError('http://localhost', 429, 'Rate limit', {}, io.BytesIO(json.dumps({
            'error': {'message': 'test-secret'}, 'usage': {'total_tokens': 13}}).encode()))
    monkeypatch.setattr('urllib.request.urlopen', reject)
    events = []
    with pytest.raises(RuntimeError, match='HTTP 429'):
        model(events).complete([], [])
    assert provider_usage(events)['reported_total_tokens'] == 13
    error = next(item for item in events if item['event'] == 'model_http_error')
    assert error['status_code'] == 429
    assert 'test-secret' not in json.dumps(events)


def test_non_json_response_is_recorded_as_invalid_with_unknown_usage(monkeypatch):
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return b'not-json'
    monkeypatch.setattr('urllib.request.urlopen', lambda *a, **k: Response())
    events = []
    with pytest.raises(ValueError):
        model(events).complete([], [])
    usage = provider_usage(events)
    assert usage['requests'] == usage['invalid_responses'] == usage['requests_without_reported_usage'] == 1


def test_schema_error_does_not_reintroduce_a_redacted_credential(monkeypatch):
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self):
            return b'{"choices":[{"message":{"content":"ok"}}],"usage":{"total_tokens":"test-secret"}}'
    monkeypatch.setattr('urllib.request.urlopen', lambda *a, **k: Response())
    events = []
    with pytest.raises(ValueError) as failure:
        model(events).complete([], [])
    assert 'test-secret' not in str(failure.value)
    assert 'test-secret' not in json.dumps(events)


def test_conflicting_usage_for_one_request_is_unknown_instead_of_double_spend():
    events = [dict(event='model_start', request_id='one'),
              dict(event='model_response_received', request_id='one', summary={'usage': {'total_tokens': 10}}),
              dict(event='model_response_received', request_id='one', summary={'usage': {'total_tokens': 20}})]
    usage = provider_usage(events)
    assert usage['usage_conflicts'] == usage['requests_without_reported_usage'] == 1
    assert usage['reported_total_tokens'] == 0


def test_request_ids_bind_all_model_events_and_survive_interleaving(monkeypatch):
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return b'{"choices":[{"message":{"content":"ok"}}],"usage":{"total_tokens":7}}'
    monkeypatch.setattr('urllib.request.urlopen', lambda *a, **k: Response())
    events = []
    runtime = model(events)
    runtime.complete([], [])
    runtime.complete([], [])
    starts = [e for e in events if e['event'] == 'model_start']
    assert all(e.get('request_id') for e in events)
    assert starts[0]['request_id'] != starts[1]['request_id']
    a = [e for e in events if e['request_id'] == starts[0]['request_id']]
    b = [e for e in events if e['request_id'] == starts[1]['request_id']]
    mixed = [a[0], b[0], *a[1:], *b[1:]]
    assert provider_usage(mixed)['reported_total_tokens'] == 14
    # Reading the same response record twice must not manufacture provider spend.
    assert provider_usage([*mixed, a[1]])['reported_total_tokens'] == 14


def test_unreadable_unrelated_proxy_log_does_not_hide_current_evidence(tmp_path, monkeypatch):
    from cv_agent.runtime import diagnostics as mod
    first = tmp_path / 'v1-chat-completions-1.log'
    second = tmp_path / 'v1-chat-completions-2.log'
    first.write_text('unrelated')
    second.write_text('=== REQUEST INFO ===\nX-Cv-Agent-Request-Id: current\n'
        '=== API RESPONSE 1 ===\nBody:\n' + json.dumps({'response': {
            'responseId': 'one', 'promptFeedback': {'blockReason': 'OTHER'}}}) + '\n=== RESPONSE ===\n')
    original = Path.read_text
    def read(path, *args, **kwargs):
        if path == first:
            raise PermissionError('rotated unrelated log')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', read)
    monkeypatch.setattr(Path, 'glob', lambda *args: iter([first, second]))
    monkeypatch.setattr(mod, 'LOG_WAIT_SECONDS', 0)
    assert mod.collect_diagnostic(tmp_path, 'current', 'one')['diagnosis'] == 'upstream_blocked'


def test_full_matrix_cannot_start_without_ten_trial_acceptance(monkeypatch, tmp_path):
    import cv_agent.evaluation.runners.run_development_benchmark as mod
    monkeypatch.setattr(mod, 'project_root', tmp_path)
    monkeypatch.setenv('ANTIGRAVITY_API_KEY', 'offline')
    (tmp_path / 'configs').mkdir()
    original = Path(__file__).parents[1] / 'configs'
    for name in ('datasets/development_manifest.json', 'experiments/development_benchmark.json'):
        (tmp_path / 'configs' / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / 'configs' / name).write_bytes((original / name).read_bytes())
    def no_loading(*a, **k):
        pytest.fail('full matrix loaded data before checking ten-trial acceptance')
    monkeypatch.setattr(mod, 'build_run_identity', no_loading)
    with pytest.raises(ValueError, match='acceptance'):
        mod.run(pilot=False)
