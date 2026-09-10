import pytest

from cv_agent.agent_types import ChatMessage, ModelToolCall
from cv_agent.harness import FULL_SYSTEM_HARNESS
from cv_agent.model_runtime import OpenAICompatibleChatModel


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
