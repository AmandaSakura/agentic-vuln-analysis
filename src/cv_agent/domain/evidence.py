"""Candidate-bound evidence and recorded tool observations."""
from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, StrictBool

from cv_agent.domain.types import FrozenModel, SnapshotModel
from cv_agent.domain.chat import ModelToolCall


class ValidationStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    UNRESOLVED = "UNRESOLVED"

class ValidationSubject(SnapshotModel):
    # Machine-readable proof obligation; never inferred from identifiers.
    property_id: str | None = None
    input_parameters: tuple[str, ...] = ()
    entry_boolean_arguments: dict[str, StrictBool] = Field(default_factory=dict)
    entry_condition_assumptions: dict[str, StrictBool] = Field(default_factory=dict)
    entry_value_assumptions: dict[str, Any] = Field(default_factory=dict)
    candidate_id: str
    repository_id: str
    entry_path: str
    entry_line: int | None = Field(default=None, ge=1)
    source_digest: str
    analysis_scope: str | None = None


class FixtureProofScope(FrozenModel):
    contract_id: str
    property_id: str
    coverage: Literal["candidate", "local"]
    method: Literal["source_pattern", "bounded_execution", "complete_static_analysis"]
    supported_statuses: tuple[ValidationStatus, ...] = ()


class FixtureCapability(FrozenModel):
    case_id: str
    property_id: str | None = None
    coverage: Literal["candidate", "local"] | None = None
    method: Literal["source_pattern", "bounded_execution", "complete_static_analysis"] | None = None
    supported_statuses: tuple[ValidationStatus, ...] = ()
    subject: ValidationSubject | None = None
    proof_scope: FixtureProofScope | None = None


class ToolObservation(SnapshotModel):
    tool: str
    status: Literal["ok", "error", "blocked"]
    content: str
    evidence_ids: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)
    citation_id: str | None = None
    validation_status: ValidationStatus | None = None
    subject: ValidationSubject | None = None
    fixture_proof: FixtureProofScope | None = None

class ReActStep(FrozenModel):
    step: int = Field(ge=1)
    model_id: str
    tool_call: ModelToolCall
    observation: ToolObservation
