"""Provider-neutral chat messages, tool calls and reported usage."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from cv_agent.domain.types import FrozenModel


class ModelToolCall(FrozenModel):
    call_id: str
    name: str
    arguments: dict[str, Any]

class ChatMessage(FrozenModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str | None = None
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: tuple[ModelToolCall, ...] = ()

class ModelUsage(FrozenModel):
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)

class ModelReply(FrozenModel):
    model_id: str
    content: str | None = None
    tool_calls: tuple[ModelToolCall, ...] = ()
    usage: ModelUsage = Field(default_factory=ModelUsage)

    @model_validator(mode="after")
    def has_content_or_tool(self) -> ModelReply:
        if not self.content and not self.tool_calls:
            raise ValueError("model reply must contain text or a tool call")
        return self
