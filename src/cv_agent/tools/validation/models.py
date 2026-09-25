"""Inputs and registered fixture contracts for validation tools."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from cv_agent.domain.evidence import ValidationStatus, ValidationSubject
from cv_agent.domain.types import FrozenModel


class PathInput(FrozenModel):
    path: str


class FindReferencesInput(FrozenModel):
    symbol: str


class SourceFlowInput(FrozenModel):
    source_path: str
    sink_path: str | None = None
    max_hops: int = Field(default=4, ge=0, le=8)


class TraceDataflowInput(SourceFlowInput):
    sink_category: Literal[
        "code-execution", "command-execution", "sql", "ldap", "path-access", "outbound-request",
    ] | None = Field(default=None, description="Restrict the trace to this sink category; omit to search all categories.")


class CommandConstructionInput(FrozenModel):
    source_path: str
    max_hops: int = Field(default=2, ge=0, le=4)


class CaseInput(FrozenModel):
    case_id: str


class CompareGuardInput(FrozenModel):
    route_path: str
    max_hops: int = Field(default=4, ge=0, le=8)


class FixtureOutcome(FrozenModel):
    status: ValidationStatus
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class FixtureCase:
    case_id: str
    runner: Callable[[], FixtureOutcome]
    timeout_seconds: float | None = None
    read_roots: tuple[Path, ...] = ()
    subject: ValidationSubject | None = None
    isolated: bool = True
    resource_limited: bool = True

    def __post_init__(self) -> None:
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("fixture timeout must be positive")


@dataclass(frozen=True)
class LoopbackRequest:
    method: str
    path: str
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class LoopbackResponse:
    status: int
    body: bytes = b""
    headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class LoopbackCase:
    case_id: str
    application: Callable[[LoopbackRequest], LoopbackResponse]
    path: str = "/"
    method: str = "GET"
    unauthorized_headers: tuple[tuple[str, str], ...] = ()
    authorized_headers: tuple[tuple[str, str], ...] = (
        ("Authorization", "Bearer project-owned-test-principal"),
    )
    body: bytes = b""
    read_roots: tuple[Path, ...] = ()
    subject: ValidationSubject | None = None
