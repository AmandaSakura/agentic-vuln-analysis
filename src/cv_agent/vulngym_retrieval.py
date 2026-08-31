from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from .datasets import load_vulngym_entries
from .harness import (
    VULNGYM_RETRIEVAL_HARNESS,
    validate_project_harness,
    validate_vulngym_result_payload,
)
from .python_ast import PythonDocumentSpan, load_python_repository
from .provenance import (
    GitIdentity,
    assess_claim_eligibility,
    build_run_identity,
    find_project_root,
    git_identity,
)
from .retrieval import RepositoryIndex, context_token_count
from .types import Candidate, Evidence
from .vulngym_subset import select_vulngym_subjects


RETRIEVAL_SYSTEMS = tuple(
    mode.value for mode in VULNGYM_RETRIEVAL_HARNESS.retrieval_modes
)


def _line_start(value: int | str) -> int:
    return int(str(value).split("-", 1)[0])


def _line_bounds(value: int | str) -> tuple[int, int]:
    parts = str(value).split("-", 1)
    start = int(parts[0])
    end = int(parts[1]) if len(parts) == 2 else start
    return start, end


def _hit(
    evidence: list[Evidence],
    target: PythonDocumentSpan,
    target_end_line: int,
) -> bool:
    relative_end = target_end_line - target.start_line
    lines = target.document.text.splitlines(keepends=True)
    if relative_end < 0 or relative_end >= len(lines):
        return False
    required_characters = sum(len(line) for line in lines[: relative_end + 1])
    for item in evidence:
        if item.path != target.document.path:
            continue
        if len(item.text) >= required_characters:
            return True
    return False


def _rate(hit_count: int, total: int) -> float | None:
    return hit_count / total if total else None


def _verified_subject_identity(checkout: Path, expected_commit: str) -> GitIdentity:
    identity = git_identity(checkout)
    if identity.revision != expected_commit:
        raise ValueError(
            f"VulnGym subject checkout has wrong revision: {checkout}: "
            f"expected {expected_commit}, found {identity.revision}"
        )
    return identity


def run_vulngym_retrieval_experiment(data_root: Path) -> dict[str, object]:
    validate_project_harness()
    data_root = data_root.resolve()
    entries_path = data_root / "raw" / "VulnGym" / "data" / "entries.jsonl"
    cases, labels = load_vulngym_entries(entries_path)
    cases_by_id = {case.case_id: case for case in cases}
    selections = select_vulngym_subjects(entries_path)
    subject_roots = {
        selection.slug: data_root / "subjects" / selection.slug / selection.commit
        for selection in selections
    }
    expected_entries = {
        entry_id: {
            "subject_key": selection.slug,
            "repository_url": selection.repository_url,
            "cross_file": labels[entry_id].entry_point["file"]
            != labels[entry_id].critical_operation["file"],
        }
        for selection in selections
        for entry_id in selection.entry_ids
    }
    expected_subject_revisions = {
        selection.slug: selection.commit for selection in selections
    }

    records: list[dict[str, object]] = []
    repository_profiles: list[dict[str, object]] = []
    context_tokens = Counter({system: 0 for system in RETRIEVAL_SYSTEMS})
    max_context_tokens = Counter({system: 0 for system in RETRIEVAL_SYSTEMS})
    for selection in selections:
        checkout = data_root / "subjects" / selection.slug / selection.commit
        if not checkout.is_dir():
            raise ValueError(f"VulnGym subject checkout not found: {checkout}")
        subject_identity = _verified_subject_identity(checkout, selection.commit)
        repository = load_python_repository(selection.slug, checkout)
        if not repository.documents:
            raise ValueError(f"subject has no Python function documents: {checkout}")
        index = RepositoryIndex(repository.documents)
        repository_profiles.append(
            {
                "subject_key": selection.slug,
                "repository_url": selection.repository_url,
                "commit": subject_identity.revision,
                "dirty": subject_identity.dirty,
                "source_file_count": repository.source_file_count,
                "function_document_count": len(repository.documents),
                "parse_error_count": len(repository.parse_error_paths),
            }
        )

        for entry_id in selection.entry_ids:
            detector_case = cases_by_id[entry_id]
            if detector_case.repository_url != selection.repository_url or detector_case.commit != selection.commit:
                raise ValueError(f"selected entry identity mismatch: {entry_id}")
            label = labels[entry_id]
            entry_point = label.entry_point
            critical_operation = label.critical_operation
            entry_span = repository.locate(
                str(entry_point["file"]),
                _line_start(entry_point["line"]),
            )
            critical_span = repository.locate(
                str(critical_operation["file"]),
                _line_start(critical_operation["line"]),
            )
            hits = {system: False for system in RETRIEVAL_SYSTEMS}
            if entry_span is not None and critical_span is not None:
                query = " ".join([*entry_span.document.defines, *entry_span.document.calls])
                candidate = Candidate(
                    candidate_id=f"{entry_id}:oracle-entry",
                    case_id=entry_id,
                    repository_id=selection.slug,
                    path=entry_span.document.path,
                    line=_line_start(entry_point["line"]),
                    query=query,
                    metadata={"seed": "VulnGym verified entry point"},
                )
                evidence_by_system = {
                    mode.value: index.retrieve_context(
                        candidate,
                        mode=mode,
                        budget=VULNGYM_RETRIEVAL_HARNESS.budget,
                    )
                    for mode in VULNGYM_RETRIEVAL_HARNESS.retrieval_modes
                }
                for system, system_evidence in evidence_by_system.items():
                    used = context_token_count(system_evidence)
                    context_tokens[system] += used
                    max_context_tokens[system] = max(max_context_tokens[system], used)
                _, critical_end_line = _line_bounds(critical_operation["line"])
                hits = {
                    system: _hit(evidence, critical_span, critical_end_line)
                    for system, evidence in evidence_by_system.items()
                }
            records.append(
                {
                    "entry_id": entry_id,
                    "repository_url": selection.repository_url,
                    "subject_key": selection.slug,
                    "cross_file": entry_point["file"] != critical_operation["file"],
                    "entry_resolved": entry_span is not None,
                    "critical_resolved": critical_span is not None,
                    "hits": hits,
                }
            )

    cross_file_records = [record for record in records if record["cross_file"]]
    same_file_records = [record for record in records if not record["cross_file"]]

    def summarize(selected_records: list[dict[str, object]]) -> dict[str, object]:
        return {
            system: {
                "hit_count": sum(bool(record["hits"][system]) for record in selected_records),
                "hit_rate": _rate(
                    sum(bool(record["hits"][system]) for record in selected_records),
                    len(selected_records),
                ),
            }
            for system in RETRIEVAL_SYSTEMS
        }

    by_repository: dict[str, list[dict[str, object]]] = defaultdict(list)
    for record in records:
        by_repository[str(record["repository_url"])].append(record)
    overall = summarize(records)
    local_rate = overall["local"]["hit_rate"]
    text_rate = overall["text"]["hit_rate"]
    graph_rate = overall["graph"]["hit_rate"]
    hybrid_rate = overall["hybrid"]["hit_rate"]
    graph_vs_local_gain = None
    graph_vs_text_gain = None
    hybrid_vs_text_gain = None
    if local_rate is not None and graph_rate is not None:
        graph_vs_local_gain = 100.0 * (graph_rate - local_rate)
    if text_rate is not None and graph_rate is not None:
        graph_vs_text_gain = 100.0 * (graph_rate - text_rate)
    if text_rate is not None and hybrid_rate is not None:
        hybrid_vs_text_gain = 100.0 * (hybrid_rate - text_rate)
    run_identity = build_run_identity(
        find_project_root(data_root),
        {
            "VulnGym": data_root / "raw" / "VulnGym",
            **subject_roots,
        },
    )
    result = {
        "dataset": VULNGYM_RETRIEVAL_HARNESS.dataset_name,
        "harness_id": VULNGYM_RETRIEVAL_HARNESS.harness_id,
        "dataset_role": VULNGYM_RETRIEVAL_HARNESS.dataset_role.value,
        "claim_eligible": VULNGYM_RETRIEVAL_HARNESS.claim_eligible,
        "experiment": VULNGYM_RETRIEVAL_HARNESS.experiment_name,
        "candidate_protocol": VULNGYM_RETRIEVAL_HARNESS.candidate_protocol,
        "run_identity": run_identity,
        "claim_assessment": assess_claim_eligibility(
            VULNGYM_RETRIEVAL_HARNESS.claim_eligible,
            run_identity,
        ),
        "limitation": VULNGYM_RETRIEVAL_HARNESS.limitation,
        "entry_count": len(records),
        "cross_file_entry_count": len(cross_file_records),
        "entries": records,
        "resolved_entry_count": sum(bool(record["entry_resolved"]) for record in records),
        "resolved_critical_count": sum(bool(record["critical_resolved"]) for record in records),
        "retrieval_contract": {
            **VULNGYM_RETRIEVAL_HARNESS.budget.model_dump(mode="json"),
            "total_context_tokens": VULNGYM_RETRIEVAL_HARNESS.budget.total_context_tokens,
            "modes": [mode.value for mode in VULNGYM_RETRIEVAL_HARNESS.retrieval_modes],
            "critical_hit_policy": VULNGYM_RETRIEVAL_HARNESS.critical_hit_policy,
        },
        "context_tokenizer": "deterministic word-or-punctuation units",
        "context_token_count": dict(sorted(context_tokens.items())),
        "max_context_token_count_per_entry": dict(sorted(max_context_tokens.items())),
        "repository_profiles": repository_profiles,
        "overall": overall,
        "cross_file": summarize(cross_file_records),
        "same_file": summarize(same_file_records),
        "by_repository": {
            repository_url: summarize(repo_records)
            for repository_url, repo_records in sorted(by_repository.items())
        },
        "graph_vs_local_hit_gain_percentage_points": graph_vs_local_gain,
        "graph_vs_text_hit_gain_percentage_points": graph_vs_text_gain,
        "hybrid_vs_text_hit_gain_percentage_points": hybrid_vs_text_gain,
        "missed_entry_ids": {
            system: sorted(
                str(record["entry_id"])
                for record in records
                if not record["hits"][system]
            )
            for system in RETRIEVAL_SYSTEMS
        },
    }
    validate_vulngym_result_payload(
        result,
        expected_entries=expected_entries,
        expected_subject_revisions=expected_subject_revisions,
    )
    return result
