from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .agent_tools import ToolRegistry
from .agent_types import AgenticVerdict
from .agentic_workflow import AgenticPipeline
from .datasets import load_owasp_expected_results
from .harness import (
    FULL_SYSTEM_HARNESS,
    AgentRuntimeMode,
    AgentSystemVersion,
    DatasetRole,
    validate_project_harness,
)
from .java_ast import load_java_repository
from .metrics import evaluate_ternary
from .model_runtime import OpenAICompatibleChatModel
from .owasp_rag import _entry_document, _matrix_dict
from .provenance import assess_claim_eligibility, build_run_identity, find_project_root
from .retrieval import RepositoryIndex
from .types import Candidate, CodeDocument, OwaspLabel, VerdictLabel
from .validation_tools import full_agent_tools


@dataclass(frozen=True)
class OwaspAgenticInput:
    index: RepositoryIndex
    candidates: tuple[Candidate, ...]
    labels: Mapping[str, OwaspLabel]
    parse_error_paths: tuple[str, ...]


def _dedupe_requested(values: Sequence[str], name: str) -> tuple[str, ...]:
    if not values:
        raise ValueError(f"at least one {name} is required")
    deduped = tuple(dict.fromkeys(values))
    if len(deduped) != len(values):
        raise ValueError(f"duplicate {name} values are not allowed")
    return deduped


def _line_from_document_path(path: str) -> int:
    try:
        return int(path.rsplit("@", 1)[-1])
    except ValueError as error:
        raise ValueError(f"Java method document path lacks a line suffix: {path}") from error


def load_owasp_agentic_inputs(
    raw_root: Path,
    *,
    case_ids: Sequence[str],
) -> OwaspAgenticInput:
    validate_project_harness()
    requested = _dedupe_requested(case_ids, "OWASP case id")
    benchmark_root = raw_root / "BenchmarkJava"
    source_root = benchmark_root / "src" / "main" / "java"
    if not source_root.is_dir():
        raise ValueError(f"OWASP Java source root not found: {source_root}")

    labels = load_owasp_expected_results(benchmark_root / "expectedresults-1.2beta.csv")
    missing_labels = sorted(set(requested) - set(labels))
    if missing_labels:
        raise ValueError(f"requested OWASP cases lack labels: {missing_labels}")

    repository_id = "OWASP:BenchmarkJava-1.2beta"
    documents, parse_error_paths = load_java_repository(repository_id, source_root)
    documents_by_source: dict[str, list[CodeDocument]] = {}
    for document in documents:
        relative_path = document.path.split("::", 1)[0]
        documents_by_source.setdefault(relative_path, []).append(document)

    candidates: list[Candidate] = []
    missing_entries: list[str] = []
    for case_id in requested:
        relative_path = f"org/owasp/benchmark/testcode/{case_id}.java"
        entry = _entry_document(documents_by_source.get(relative_path, ()), case_id)
        if entry is None:
            missing_entries.append(case_id)
            continue
        candidates.append(
            Candidate(
                candidate_id=f"{case_id}:doGet",
                case_id=case_id,
                repository_id=repository_id,
                path=entry.path,
                line=_line_from_document_path(entry.path),
                query=entry.text,
            )
        )
    if missing_entries:
        raise ValueError(f"requested OWASP cases lack doGet entries: {missing_entries}")
    return OwaspAgenticInput(
        index=RepositoryIndex(documents),
        candidates=tuple(candidates),
        labels=labels,
        parse_error_paths=tuple(parse_error_paths),
    )


def _systems(system_ids: Sequence[str]) -> tuple[AgentSystemVersion, ...]:
    requested = _dedupe_requested(system_ids, "agentic system")
    systems: list[AgentSystemVersion] = []
    for value in requested:
        try:
            systems.append(AgentSystemVersion(value))
        except ValueError as error:
            choices = ", ".join(system.value for system in AgentSystemVersion)
            raise ValueError(f"unknown agentic system {value!r}; choose one of {choices}") from error
    return tuple(systems)


def _live_models(system: AgentSystemVersion) -> dict[str, OpenAICompatibleChatModel]:
    spec = FULL_SYSTEM_HARNESS.system_spec(system)
    roles = set(spec.expert_order)
    if spec.planner_enabled:
        roles.add("planner")
    return {
        role: OpenAICompatibleChatModel.from_harness(FULL_SYSTEM_HARNESS.model)
        for role in sorted(roles)
    }


def _metric_dict(
    labels: Mapping[str, OwaspLabel],
    predictions: Mapping[str, VerdictLabel],
) -> dict[str, int | float | None]:
    truth = {case_id: labels[case_id].vulnerable for case_id in predictions}
    return _matrix_dict(evaluate_ternary(truth, predictions))


def run_agentic_owasp_live(
    raw_root: Path,
    *,
    case_ids: Sequence[str],
    system_ids: Sequence[str],
) -> dict[str, object]:
    inputs = load_owasp_agentic_inputs(raw_root, case_ids=case_ids)
    systems = _systems(system_ids)
    tools = ToolRegistry(
        full_agent_tools(inputs.index),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )

    results: dict[str, object] = {}
    for system in systems:
        predictions: dict[str, VerdictLabel] = {}
        verdicts: dict[str, object] = {}
        pipeline = AgenticPipeline(
            index=inputs.index,
            system=system,
            models=_live_models(system),
            tools=tools,
        )
        for candidate in inputs.candidates:
            verdict: AgenticVerdict = pipeline.run(candidate)
            predictions[candidate.case_id] = verdict.label
            verdicts[candidate.case_id] = verdict.model_dump(mode="json")
        results[system.value] = {
            "confusion": _metric_dict(inputs.labels, predictions),
            "predictions": predictions,
            "verdicts": verdicts,
        }

    benchmark_root = raw_root / "BenchmarkJava"
    run_identity = build_run_identity(
        find_project_root(raw_root),
        {"BenchmarkJava": benchmark_root},
    )
    return {
        "dataset": "OWASP BenchmarkJava 1.2beta selected live cases",
        "dataset_role": DatasetRole.DEVELOPMENT.value,
        "harness_id": FULL_SYSTEM_HARNESS.harness_id,
        "runtime_mode": AgentRuntimeMode.LIVE.value,
        "claim_eligible": False,
        "purpose": (
            "Bounded live-model reproduction runner for explicit OWASP case ids; "
            "development-only and not a reported benchmark result."
        ),
        "case_count": len(inputs.candidates),
        "cases": [
            {
                "case_id": candidate.case_id,
                "category": inputs.labels[candidate.case_id].category,
                "cwe": inputs.labels[candidate.case_id].cwe,
                "vulnerable": inputs.labels[candidate.case_id].vulnerable,
            }
            for candidate in inputs.candidates
        ],
        "parse_error_count": len(inputs.parse_error_paths),
        "parse_error_paths": list(inputs.parse_error_paths),
        "systems": results,
        "run_identity": run_identity,
        "claim_assessment": assess_claim_eligibility(False, run_identity),
    }
