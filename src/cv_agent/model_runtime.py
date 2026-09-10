from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from typing import Any, Literal, Protocol

from .agent_types import (
    ChatMessage,
    ModelReply,
    ModelToolCall,
    ModelUsage,
)
from .harness import AgentRuntimeMode, ModelRuntimeHarness


class ChatModel(Protocol):
    runtime_mode: AgentRuntimeMode

    def complete(
        self,
        messages: Sequence[ChatMessage],
        tools: Sequence[dict[str, Any]],
    ) -> ModelReply: ...


class ScriptedChatModel:
    runtime_mode = AgentRuntimeMode.SCRIPTED

    def __init__(self, replies: Sequence[
        ModelReply | Callable[[Sequence[ChatMessage], Sequence[dict[str, Any]]], ModelReply]
    ]) -> None:
        self._replies = list(replies)
        self.requests: list[tuple[tuple[ChatMessage, ...], tuple[dict[str, Any], ...]]] = []

    def complete(
        self,
        messages: Sequence[ChatMessage],
        tools: Sequence[dict[str, Any]],
    ) -> ModelReply:
        self.requests.append((tuple(messages), tuple(tools)))
        if not self._replies:
            raise RuntimeError("scripted model has no reply remaining")
        reply = self._replies.pop(0)
        # Project-owned test responders may inspect real tool observations. This
        # transport still has scripted provenance and cannot become claim eligible.
        return reply(messages, tools) if callable(reply) else reply


class OpenAICompatibleChatModel:
    runtime_mode = AgentRuntimeMode.LIVE

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str | None,
        temperature: float,
        timeout_seconds: int,
        max_tokens: int | None = None,
        thinking_mode: Literal["enabled", "disabled"] | None = None,
    ) -> None:
        if not base_url.strip() or not model.strip():
            raise ValueError("live model base URL and model name are required")
        if max_tokens is not None and max_tokens < 1:
            raise ValueError("live model max_tokens must be positive")
        if thinking_mode not in {None, "enabled", "disabled"}:
            raise ValueError("live model thinking mode must be enabled or disabled")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._api_key = api_key
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
        self.max_tokens = max_tokens
        self.thinking_mode = thinking_mode

    @staticmethod
    def _optional_positive_integer_environment(name: str | None) -> int | None:
        if name is None:
            return None
        raw = os.environ.get(name, "").strip()
        if not raw:
            return None
        try:
            value = int(raw)
        except ValueError as error:
            raise ValueError(f"{name} must be a positive integer") from error
        if value < 1:
            raise ValueError(f"{name} must be a positive integer")
        return value

    @staticmethod
    def _optional_thinking_environment(
        name: str | None,
    ) -> Literal["enabled", "disabled"] | None:
        if name is None:
            return None
        raw = os.environ.get(name, "").strip().lower()
        if not raw:
            return None
        if raw not in {"enabled", "disabled"}:
            raise ValueError(f"{name} must be enabled or disabled")
        return raw

    @classmethod
    def from_harness(
        cls,
        harness: ModelRuntimeHarness,
    ) -> OpenAICompatibleChatModel:
        base_url = os.environ.get(harness.base_url_env, "")
        model = os.environ.get(harness.model_env, "")
        api_key = os.environ.get(harness.api_key_env)
        missing = [
            name
            for name, value in (
                (harness.base_url_env, base_url),
                (harness.model_env, model),
            )
            if not value
        ]
        if missing:
            raise ValueError(
                "live model environment is incomplete; missing " + ", ".join(missing)
            )
        return cls(
            base_url=base_url,
            model=model,
            api_key=api_key,
            temperature=harness.temperature,
            timeout_seconds=harness.request_timeout_seconds,
            max_tokens=cls._optional_positive_integer_environment(
                harness.max_tokens_env
            ),
            thinking_mode=cls._optional_thinking_environment(
                harness.thinking_mode_env
            ),
        )

    def _endpoint(self) -> str:
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return f"{self.base_url}/chat/completions"

    @staticmethod
    def _message_payload(message: ChatMessage) -> dict[str, Any]:
        payload: dict[str, Any] = {"role": message.role}
        if message.content is not None:
            payload["content"] = message.content
        if message.name is not None:
            payload["name"] = message.name
        if message.tool_call_id is not None:
            payload["tool_call_id"] = message.tool_call_id
        if message.tool_calls:
            payload["tool_calls"] = [
                {
                    "id": call.call_id,
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": json.dumps(
                            call.arguments,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    },
                }
                for call in message.tool_calls
            ]
        return payload

    @staticmethod
    def _parse_tool_calls(raw_calls: object) -> tuple[ModelToolCall, ...]:
        if not raw_calls:
            return ()
        if not isinstance(raw_calls, list):
            raise ValueError("model tool_calls must be an array")
        parsed: list[ModelToolCall] = []
        for raw in raw_calls:
            if not isinstance(raw, dict) or not isinstance(raw.get("function"), dict):
                raise ValueError("model returned an invalid tool call")
            function = raw["function"]
            arguments_raw = function.get("arguments", "{}")
            if isinstance(arguments_raw, str):
                arguments = json.loads(arguments_raw)
            else:
                arguments = arguments_raw
            if not isinstance(arguments, dict):
                raise ValueError("model tool-call arguments must be an object")
            parsed.append(
                ModelToolCall(
                    call_id=str(raw.get("id", "")),
                    name=str(function.get("name", "")),
                    arguments=arguments,
                )
            )
        return tuple(parsed)

    def _request_body(
        self,
        messages: Sequence[ChatMessage],
        tools: Sequence[dict[str, Any]],
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [self._message_payload(message) for message in messages],
            "temperature": self.temperature,
        }
        if self.max_tokens is not None:
            body["max_tokens"] = self.max_tokens
        if self.thinking_mode is not None:
            body["thinking"] = {"type": self.thinking_mode}
        if tools:
            body["tools"] = list(tools)
            body["tool_choice"] = "auto"
        return body

    def complete(
        self,
        messages: Sequence[ChatMessage],
        tools: Sequence[dict[str, Any]],
    ) -> ModelReply:
        body = self._request_body(messages, tools)
        request = urllib.request.Request(
            self._endpoint(),
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                **(
                    {"Authorization": f"Bearer {self._api_key}"}
                    if self._api_key
                    else {}
                ),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = error.read(4_096).decode("utf-8", errors="replace")
            raise RuntimeError(
                f"model endpoint returned HTTP {error.code}: {detail}"
            ) from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise RuntimeError(f"model endpoint request failed: {error}") from error

        choices = raw.get("choices") if isinstance(raw, dict) else None
        if not isinstance(choices, list) or not choices:
            raise ValueError("model response contains no choices")
        message = choices[0].get("message")
        if not isinstance(message, dict):
            raise ValueError("model response choice contains no message")
        usage_raw = raw.get("usage") if isinstance(raw.get("usage"), dict) else {}
        return ModelReply(
            model_id=str(raw.get("model") or self.model),
            content=(
                str(message["content"])
                if message.get("content") is not None
                else None
            ),
            tool_calls=self._parse_tool_calls(message.get("tool_calls")),
            usage=ModelUsage(
                input_tokens=usage_raw.get("prompt_tokens"),
                output_tokens=usage_raw.get("completion_tokens"),
                total_tokens=usage_raw.get("total_tokens"),
            ),
        )


def trusted_runtime_mode(model: ChatModel) -> AgentRuntimeMode:
    """Derive provenance from project-owned concrete runtimes, not attributes."""

    if type(model) is ScriptedChatModel:
        trusted = AgentRuntimeMode.SCRIPTED
    elif type(model) is OpenAICompatibleChatModel:
        trusted = AgentRuntimeMode.LIVE
    else:
        raise ValueError(
            f"untrusted chat-model runtime implementation: {type(model).__name__}"
        )
    declared = getattr(model, "runtime_mode", None)
    if declared != trusted:
        raise ValueError(
            f"model runtime provenance mismatch: declared {declared}, trusted {trusted}"
        )
    return trusted
