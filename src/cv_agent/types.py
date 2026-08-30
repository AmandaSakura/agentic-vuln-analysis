from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


VerdictLabel = Literal["VULNERABLE", "SAFE", "ABSTAIN"]


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SystemVersion(StrEnum):
    V1_LOCAL_SINGLE = "V1"
    V2_TEXT_SINGLE = "V2"
    V3_GRAPH_SINGLE = "V3"
    V4_GRAPH_MULTI = "V4"
    V5_GRAPH_FAST_SLOW = "V5"


class Candidate(FrozenModel):
    candidate_id: str
    case_id: str
    repository_id: str
    path: str
    line: int = Field(ge=1)
    query: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class CodeDocument(FrozenModel):
    repository_id: str
    path: str
    text: str
    defines: tuple[str, ...] = ()
    calls: tuple[str, ...] = ()


class Evidence(FrozenModel):
    evidence_id: str
    path: str
    text: str
    retrieval: Literal["local", "text", "graph", "hybrid"]
    score: float
    graph_distance: int | None = None


class ReasoningStep(FrozenModel):
    action: str
    observation: str


class ExpertVote(FrozenModel):
    expert: Literal["scan", "taint", "authz"]
    label: VerdictLabel
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: tuple[str, ...] = ()
    rationale: str
    trace: tuple[ReasoningStep, ...] = ()


class Verdict(FrozenModel):
    label: VerdictLabel
    confidence: float = Field(ge=0.0, le=1.0)
    path: Literal["single", "fast", "slow"]
    votes: tuple[ExpertVote, ...]
    rationale: str
    context_token_count: int = Field(default=0, ge=0)


class DetectorCase(FrozenModel):
    case_id: str
    repository_url: str
    commit: str


class VulnGymLabel(FrozenModel):
    case_id: str
    report_id: str
    verify: bool
    entry_point: Any
    critical_operation: Any
    trace: Any


class OwaspLabel(FrozenModel):
    case_id: str
    category: str
    vulnerable: bool
    cwe: int
