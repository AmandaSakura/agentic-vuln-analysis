"""Candidate-bound evidence and recorded tool observations."""
from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, StrictBool

from cv_agent.domain.types import FrozenModel
from cv_agent.domain.chat import ModelToolCall


class ValidationStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    UNRESOLVED = "UNRESOLVED"

class ValidationSubject(FrozenModel):
    input_parameters: tuple[str, ...] = ()
    entry_boolean_arguments: dict[str, StrictBool] = Field(default_factory=dict)
    candidate_id: str
    repository_id: str
    entry_path: str
    entry_line: int | None = Field(default=None, ge=1)
    source_digest: str
    analysis_scope: str | None = None

class ToolObservation(FrozenModel):
    tool: str
    status: Literal["ok", "error", "blocked"]
    content: str
    evidence_ids: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)
    citation_id: str | None = None
    validation_status: ValidationStatus | None = None
    subject: ValidationSubject | None = None

class ReActStep(FrozenModel):
    step: int = Field(ge=1)
    model_id: str
    tool_call: ModelToolCall
    observation: ToolObservation
