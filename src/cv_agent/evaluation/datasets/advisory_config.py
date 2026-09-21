from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, StrictBool, model_validator

from cv_agent.harness import AgentSystemVersion
from cv_agent.evaluation.datasets.heldout_manifest import repository_key
from cv_agent.domain.types import FrozenModel


SUPPORTED_HELDOUT_SOURCE_SUFFIXES = (
    ".py",
    ".ini",
    ".cfg",
    ".toml",
    ".yaml",
    ".yml",
    ".json",
    ".env.example",
    ".env.sample",
)


def is_supported_heldout_source_path(value: str) -> bool:
    lower = value.lower()
    return any(lower.endswith(suffix) for suffix in SUPPORTED_HELDOUT_SOURCE_SUFFIXES)


class PythonHeldoutPairCase(FrozenModel):
    case_id: Annotated[str, Field(pattern=r"^hp[0-9]{3}_[ab]$")]
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
                raise ValueError("Held-out pair paths must remain relative to the project root")
        if not is_supported_heldout_source_path(self.file_path):
            raise ValueError("Held-out Python pair cases must target a supported source file")
        return self


class PythonHeldoutPair(FrozenModel):
    input_parameters: tuple[str, ...] = ()
    entry_boolean_arguments: dict[str, StrictBool] = Field(default_factory=dict)
    pair_id: Annotated[str, Field(pattern=r"^hp[0-9]{3}_[a-z0-9_]+$")]
    entry_id: Annotated[str, Field(pattern=r"^entry-[0-9]+$")]
    repository_url: str
    advisory: str
    source_link: str
    vuln_ids: tuple[str, ...]
    source_root: str
    python_import_root: str | None = None
    exclude_path_parts: tuple[str, ...] = ()
    vulnerability_title: str
    source_scope: str
    analysis_scope: str
    entry_point: dict
    critical_operation: dict
    cases: tuple[PythonHeldoutPairCase, ...]

    @model_validator(mode="after")
    def validate_pair(self):
        repository_key(self.repository_url)
        if self.python_import_root is not None:
            import_root = PurePosixPath(self.python_import_root)
            if import_root.is_absolute() or ".." in import_root.parts:
                raise ValueError("python_import_root must remain relative to the checkout")
        source_root = PurePosixPath(self.source_root)
        if source_root.is_absolute() or ".." in source_root.parts:
            raise ValueError("source_root must remain relative to the checkout")
        roles = [case.revision_role for case in self.cases]
        if roles != ["vulnerable", "fixed"]:
            raise ValueError("Each held-out pair must declare vulnerable then fixed cases")
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("Duplicate case_id in held-out pair")
        vulnerable, fixed = self.cases
        if vulnerable.file_path != fixed.file_path:
            raise ValueError("Held-out fixed case must analyze the same source path")
        if vulnerable.case_id.endswith("_b") or fixed.case_id.endswith("_a"):
            raise ValueError("Held-out model-visible case IDs must be neutral a/b ordering")
        return self


class PythonHeldoutPairCell(FrozenModel):
    case_id: Annotated[str, Field(pattern=r"^hp[0-9]{3}_[ab]$")]
    system: AgentSystemVersion


class PythonHeldoutPairLimits(FrozenModel):
    max_requests: Annotated[int, Field(ge=1)]
    max_seconds: Annotated[int, Field(ge=1)]


class PythonHeldoutPairExperimentConfig(FrozenModel):
    dataset_name: str
    dataset_role: Literal["paired_heldout_advisory"]
    claim_eligible: Literal[False]
    model_config_path: str = Field(alias="model_config")
    systems: tuple[AgentSystemVersion, ...]
    concurrency: Literal[1, 2]
    graph_direction: Literal["forward", "reverse", "both"] = "forward"
    graph_ranking: Literal["lexical", "distance"] = "lexical"
    limits: PythonHeldoutPairLimits
    source_manifest: str
    pairs: tuple[PythonHeldoutPair, ...]
    selected_cells: tuple[PythonHeldoutPairCell, ...] = ()
    expected_abstentions: tuple[PythonHeldoutPairCell, ...] = ()

    @model_validator(mode="after")
    def validate_experiment(self):
        for value in (self.model_config_path, self.source_manifest):
            path = PurePosixPath(value)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Config paths must remain relative to the project root")
        if self.systems != tuple(AgentSystemVersion):
            raise ValueError("Held-out pair experiments must run E1 through E5 exactly once")
        if not self.pairs:
            raise ValueError("At least one held-out pair is required")
        if len({pair.pair_id for pair in self.pairs}) != len(self.pairs):
            raise ValueError("Duplicate held-out pair_id")
        case_ids = [case.case_id for pair in self.pairs for case in pair.cases]
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("Duplicate held-out case_id")
        declared = {
            (case.case_id, system)
            for pair in self.pairs
            for case in pair.cases
            for system in self.systems
        }
        selected = [(cell.case_id, cell.system) for cell in self.selected_cells]
        if len(set(selected)) != len(selected):
            raise ValueError("Duplicate selected held-out cell")
        if any(cell not in declared for cell in selected):
            raise ValueError("Selected held-out cells must be declared cases and systems")
        expected_abstentions = [
            (cell.case_id, cell.system) for cell in self.expected_abstentions
        ]
        if len(set(expected_abstentions)) != len(expected_abstentions):
            raise ValueError("Duplicate expected held-out abstention")
        if any(cell not in declared for cell in expected_abstentions):
            raise ValueError("Expected held-out abstentions must be declared cases and systems")
        if selected and len(selected) > 10:
            raise ValueError("Selected held-out gate cells must contain at most ten cells")
        cells = len(selected) if selected else len(declared)
        if self.limits.max_requests < cells:
            raise ValueError("Request limit must admit at least one request per planned cell")
        return self


def planned_heldout_cells(
    config: PythonHeldoutPairExperimentConfig,
) -> tuple[tuple[PythonHeldoutPair, PythonHeldoutPairCase, AgentSystemVersion], ...]:
    selected = (
        {(cell.case_id, cell.system) for cell in config.selected_cells}
        if config.selected_cells
        else None
    )
    cells: list[tuple[PythonHeldoutPair, PythonHeldoutPairCase, AgentSystemVersion]] = []
    for pair in config.pairs:
        for case in pair.cases:
            for system in config.systems:
                key = (case.case_id, system)
                if selected is None or key in selected:
                    cells.append((pair, case, system))
    return tuple(cells)


def heldout_truth(revision_role: str) -> Literal["VULNERABLE", "SAFE"]:
    if revision_role == "vulnerable":
        return "VULNERABLE"
    if revision_role == "fixed":
        return "SAFE"
    raise ValueError(f"Unknown revision role: {revision_role}")
