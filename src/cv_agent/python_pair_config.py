from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .harness import AgentSystemVersion
from .types import FrozenModel


class PythonPairCase(FrozenModel):
    case_id: Annotated[str, Field(pattern=r"^[a-z0-9_]+$")]
    revision_role: Literal["vulnerable", "fixed"]
    commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    checkout: str
    file_path: str
    line_hint: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def validate_paths(self):
        for value in (self.checkout, self.file_path):
            path = PurePosixPath(value)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Pair paths must remain relative to the project root")
        return self


class PythonPair(FrozenModel):
    pair_id: Annotated[str, Field(pattern=r"^[a-z0-9_]+$")]
    fixture_id: Annotated[str, Field(pattern=r"^[a-z0-9_]+$")]
    repository_url: str
    advisory: str
    cve: str
    source_root: str
    exclude_path_parts: tuple[str, ...] = ()
    entry_symbol: str
    source_scope: str
    analysis_scope: str
    cases: tuple[PythonPairCase, ...]

    @model_validator(mode="after")
    def validate_pair(self):
        source_root = PurePosixPath(self.source_root)
        if source_root.is_absolute() or ".." in source_root.parts:
            raise ValueError("source_root must remain relative to the checkout")
        roles = [case.revision_role for case in self.cases]
        if roles != ["vulnerable", "fixed"]:
            raise ValueError("Each pair must declare vulnerable then fixed cases")
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("Duplicate case_id in pair")
        return self


class PythonPairLimits(FrozenModel):
    max_requests: Annotated[int, Field(ge=1)]
    max_seconds: Annotated[int, Field(ge=1)]


class PythonPairExperimentConfig(FrozenModel):
    dataset_name: str
    dataset_role: Literal["paired_development_gate", "paired_development_matrix"]
    claim_eligible: Literal[False]
    model_config_path: str = Field(alias="model_config")
    systems: tuple[AgentSystemVersion, ...]
    concurrency: Literal[1]
    limits: PythonPairLimits
    label_file: str
    pairs: tuple[PythonPair, ...]
    requires_gate_pointer: str | None = None

    @model_validator(mode="after")
    def validate_experiment(self):
        for value in (self.model_config_path, self.label_file):
            path = PurePosixPath(value)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Config paths must remain relative to the project root")
        if self.requires_gate_pointer is not None:
            path = PurePosixPath(self.requires_gate_pointer)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Gate pointer path must remain relative to the project root")
        if self.systems != tuple(AgentSystemVersion):
            raise ValueError("Python pair experiments must run E1 through E5 exactly once")
        cells = len(self.pairs) * 2 * len(self.systems)
        if self.dataset_role == "paired_development_gate" and cells != 10:
            raise ValueError("Gate must contain exactly ten cells")
        if self.dataset_role == "paired_development_matrix" and cells != 20:
            raise ValueError("Matrix must contain exactly twenty cells")
        if self.dataset_role == "paired_development_matrix" and not self.requires_gate_pointer:
            raise ValueError("Matrix requires a gate pointer")
        if len({pair.pair_id for pair in self.pairs}) != len(self.pairs):
            raise ValueError("Duplicate pair_id")
        case_ids = [case.case_id for pair in self.pairs for case in pair.cases]
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("Duplicate case_id")
        return self


class PythonPairLabel(FrozenModel):
    pair_id: str
    revision_role: Literal["vulnerable", "fixed"]
    label: Literal["VULNERABLE", "SAFE"]
    required_validation_status: Literal["CONFIRMED", "REFUTED"]
    required_fixture_status: Literal["EXPLOITED", "BLOCKED"]


class PythonPairLabels(FrozenModel):
    version: Literal[1]
    labels: dict[str, PythonPairLabel]
