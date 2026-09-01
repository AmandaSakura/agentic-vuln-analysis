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

