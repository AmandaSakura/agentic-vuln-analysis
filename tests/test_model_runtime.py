import pytest
import json
import io
from urllib.error import HTTPError

from cv_agent.agent_types import ChatMessage, ModelToolCall
from cv_agent.harness import FULL_SYSTEM_HARNESS
from cv_agent.model_runtime import OpenAICompatibleChatModel


@pytest.mark.parametrize("choices", [
    [], [{}], [{"message": {"content": None}}],
    [{"message": {"tool_calls": [{"id": "one", "function": {"name": "read_span", "arguments": "{broken"}}]}}],
])
def test_all_malformed_responses_keep_reported_usage(monkeypatch, choices):
    from cv_agent.benchmark_evaluation import provider_usage
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self):
            return json.dumps({"model": "offline", "choices": choices,
                               "usage": {"total_tokens": 30}}).encode()
    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: Response())
    events = []
    model = OpenAICompatibleChatModel(base_url="http://localhost/v1", model="offline",
        api_key=None, temperature=0, timeout_seconds=1, observer=events.append)
    with pytest.raises(ValueError):
        model.complete([], [])
    usage = provider_usage(events)
    assert usage["requests"] == 1
    assert usage["reported_total_tokens"] == 30
    assert usage["requests_without_reported_usage"] == 0
    assert usage["invalid_responses"] == 1


def test_invalid_provider_response_preserves_diagnostics_without_credentials(monkeypatch):
    class Response:
        def __enter__(self):
            return self
        def __exit__(self,*args):
            return False
        def read(self):
            return json.dumps({'error':{'message':'invalid secret-token'},'usage':{'total_tokens':9}}).encode()
    monkeypatch.setattr('urllib.request.urlopen',lambda *args,**kwargs:Response())
    events=[]
    model=OpenAICompatibleChatModel(base_url='http://localhost/v1',model='test',
        api_key='secret-token',temperature=0,timeout_seconds=1,observer=events.append)
    with pytest.raises(ValueError,match='no choices'):
        model.complete([ChatMessage(role='user',content='test')],[])
    diagnostic=next(event for event in events if event['event']=='model_invalid_response')
    assert diagnostic['summary']['usage']['total_tokens']==9
    assert 'secret-token' not in json.dumps(events)
    assert diagnostic['summary']['error']['message']=='invalid [REDACTED]'


def test_http_error_does_not_echo_api_key_into_trial_errors(monkeypatch):
    def reject(*args,**kwargs):
        raise HTTPError('http://localhost',401,'Unauthorized',{},io.BytesIO(b'invalid secret-token'))
    monkeypatch.setattr('urllib.request.urlopen',reject)
    model=OpenAICompatibleChatModel(base_url='http://localhost/v1',model='test',
        api_key='secret-token',temperature=0,timeout_seconds=1)
    with pytest.raises(RuntimeError) as error:
        model.complete([ChatMessage(role='user',content='test')],[])
    assert 'secret-token' not in str(error.value)
    assert '[REDACTED]' in str(error.value)


def test_live_model_configuration_requires_endpoint_and_model_environment(monkeypatch):
    monkeypatch.delenv(FULL_SYSTEM_HARNESS.model.base_url_env, raising=False)
    monkeypatch.delenv(FULL_SYSTEM_HARNESS.model.model_env, raising=False)

    with pytest.raises(ValueError, match="missing"):
        OpenAICompatibleChatModel.from_harness(FULL_SYSTEM_HARNESS.model)


def test_openai_compatible_message_serializes_typed_tool_call():
    message = ChatMessage(
        role="assistant",
        tool_calls=(
            ModelToolCall(
                call_id="call-1",
                name="read_span",
                arguments={"path": "entry.py::entry@1-2"},
            ),
        ),
    )

    payload = OpenAICompatibleChatModel._message_payload(message)

    assert payload["tool_calls"][0]["function"]["name"] == "read_span"
    assert payload["tool_calls"][0]["function"]["arguments"] == (
        '{"path":"entry.py::entry@1-2"}'
    )


def test_deepseek_request_controls_are_loaded_from_environment(monkeypatch):
    harness = FULL_SYSTEM_HARNESS.model
    assert harness.max_tokens_env is not None
    assert harness.thinking_mode_env is not None
    monkeypatch.setenv(harness.base_url_env, "https://api.deepseek.com")
    monkeypatch.setenv(harness.model_env, "deepseek-v4-flash")
    monkeypatch.setenv(harness.api_key_env, "test-key")
    monkeypatch.setenv(harness.max_tokens_env, "1200")
    monkeypatch.setenv(harness.thinking_mode_env, "disabled")

    model = OpenAICompatibleChatModel.from_harness(harness)
    body = model._request_body(
        (ChatMessage(role="user", content="Inspect this candidate."),),
        (),
    )

    assert model._endpoint() == "https://api.deepseek.com/chat/completions"
    assert body["model"] == "deepseek-v4-flash"
    assert body["max_tokens"] == 1200
    assert body["thinking"] == {"type": "disabled"}


@pytest.mark.parametrize(
    ("environment_name", "value", "message"),
    (
        ("max_tokens_env", "0", "positive integer"),
        ("max_tokens_env", "many", "positive integer"),
        ("thinking_mode_env", "sometimes", "enabled or disabled"),
    ),
)
def test_invalid_optional_live_model_environment_is_rejected(
    monkeypatch,
    environment_name,
    value,
    message,
):
    harness = FULL_SYSTEM_HARNESS.model
    monkeypatch.setenv(harness.base_url_env, "https://api.deepseek.com")
    monkeypatch.setenv(harness.model_env, "deepseek-v4-flash")
    for name in (harness.max_tokens_env, harness.thinking_mode_env):
        assert name is not None
        monkeypatch.delenv(name, raising=False)
    optional_name = getattr(harness, environment_name)
    assert optional_name is not None
    monkeypatch.setenv(optional_name, value)

    with pytest.raises(ValueError, match=message):
        OpenAICompatibleChatModel.from_harness(harness)
