"""Native TypeSafe choice protocol; transport and admission stay in model.py."""
from __future__ import annotations

import json
import math
import os
from collections.abc import Sequence
from typing import Any, Literal

from pydantic import Field, StrictInt, model_validator

from cv_agent.domain.chat import ChatMessage, ModelReply, ModelUsage
from cv_agent.domain.types import FrozenModel
from cv_agent.harness import FULL_SYSTEM_HARNESS


class JevRoutingConfig(FrozenModel):
    base_url: Literal['https://api.typesafe.ai/v1'] = 'https://api.typesafe.ai/v1'
    model: str = Field(min_length=1)
    timeout_seconds: int = Field(ge=1)
    spec_version: int = 2
    mode: Literal['off', 'shadow', 'active'] = 'shadow'
    min_choice_probability: float = Field(ge=0, le=1, allow_inf_nan=False)
    max_source_observation_tokens: int = Field(
        default=4096, ge=1, lt=FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens,
    )

    def build_model(self, observer):
        from cv_agent.runtime.model import OpenAICompatibleChatModel
        key = None if self.mode == 'off' else os.environ.get('JEV_API_KEY', '').strip()
        if self.mode != 'off' and not key:
            raise ValueError('JEV_API_KEY must be set and nonempty in .env.experiments')
        return OpenAICompatibleChatModel(
            base_url=self.base_url, model=self.model, api_key=key, temperature=0,
            timeout_seconds=self.timeout_seconds, protocol='jev-systemone', observer=observer,
        )


class ChoiceAnswer(FrozenModel):
    type: Literal['choice']
    choice: str
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    probabilities: dict[str, float]

    @model_validator(mode='after')
    def valid_distribution(self):
        values = self.probabilities
        if not values or self.choice not in values:
            raise ValueError('Jev choice must belong to its probability distribution')
        if any(not math.isfinite(p) or not 0 <= p <= 1 for p in values.values()):
            raise ValueError('Jev probabilities must be finite values in [0, 1]')
        if not math.isclose(sum(values.values()), 1.0, abs_tol=0.01):
            raise ValueError('Jev probabilities must sum to approximately one')
        if values[self.choice] < max(values.values()):
            raise ValueError('Jev choice must have the highest probability')
        return self


class JevUsage(FrozenModel):
    input_tokens: StrictInt = Field(ge=0)
    output_tokens: StrictInt = Field(ge=0)


class JevResponse(FrozenModel):
    model: str = Field(min_length=1)
    answers: dict[str, ChoiceAnswer]
    usage: JevUsage


def request_body(model: str, messages: Sequence[ChatMessage], tools: Sequence[dict[str, Any]]) -> dict:
    if tools or len(messages) != 1 or messages[0].role != 'user':
        raise ValueError('Jev requires one structured user message and no chat tools')
    payload = json.loads(messages[0].content or '')
    if not isinstance(payload, dict) or set(payload) != {'state', 'questions'}:
        raise ValueError('Jev request requires state and questions')
    questions = payload['questions']
    if not isinstance(questions, dict) or not questions:
        raise ValueError('Jev requires at least one question')
    for question in questions.values():
        if not isinstance(question, dict) or question.get('type') != 'choice':
            raise ValueError('Jev routing only supports choice questions')
        if not isinstance(question.get('criteria'), dict) or not question['criteria']:
            raise ValueError('Jev choice questions require criteria')
    return {'model': model, **payload}


def parse_answers(raw: object, questions: dict) -> dict[str, ChoiceAnswer]:
    if not isinstance(raw, dict) or set(raw) != set(questions):
        raise ValueError('Jev answers must match all requested question names')
    answers = {key: ChoiceAnswer.model_validate(value) for key, value in raw.items()}
    for name, answer in answers.items():
        if set(answer.probabilities) != set(questions[name]['criteria']):
            raise ValueError('Jev answer choices must match the requested criteria')
    return answers


def parse_response(raw: object, questions: dict) -> ModelReply:
    response = JevResponse.model_validate(raw)
    parse_answers(raw['answers'], questions)
    return ModelReply(
        model_id=response.model,
        content=json.dumps({key: value.model_dump() for key, value in response.answers.items()}),
        usage=ModelUsage(input_tokens=response.usage.input_tokens,
                         output_tokens=response.usage.output_tokens,
                         total_tokens=response.usage.input_tokens + response.usage.output_tokens),
    )
