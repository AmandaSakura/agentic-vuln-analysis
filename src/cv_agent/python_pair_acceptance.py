from __future__ import annotations

import json
from collections import Counter
from pathlib import Path, PurePosixPath

from .agent_types import AgentExpertVote, ValidationSubject
from .benchmark_evaluation import provider_usage
from .experiment_acceptance import transport_issues
from .live_gate import source_fingerprint
from .python_pair_config import PythonPairExperimentConfig, PythonPairLabels
from .python_pair_fixture import build_pair_input, case_identity, require_clean_checkout
from .react_engine import validate_conclusion


_RETRIEVAL_PREFIXES = ("local:", "text:", "graph:", "hybrid:")


def expected_cells(config: PythonPairExperimentConfig) -> dict[tuple[str, str], str]:
    return {
        (case.case_id, system.value): ("VULNERABLE" if case.revision_role == "vulnerable" else "SAFE")
        for pair in config.pairs
        for case in pair.cases
        for system in config.systems
    }


def pair_acceptance_issues(
    rows: list[dict],
    usage: dict,
    config: PythonPairExperimentConfig,
    labels: PythonPairLabels,
    subjects: dict[str, ValidationSubject],
) -> list[str]:
    issues: list[str] = []
    expected = expected_cells(config)
    if Counter((row.get("case_id"), row.get("system")) for row in rows) != Counter(expected.keys()):
        issues.append("Declared case/system cells are missing, duplicated or expanded")
    for row in rows:
        cell = (row.get("case_id"), row.get("system"))
        label = expected.get(cell)
        label_spec = labels.labels.get(row.get("case_id"))
        if row.get("status") != "completed" or label is None or label_spec is None or row.get("predicted_label") != label:
            issues.append(f"{cell}: missing, failed, abstained or incorrect prediction")
            continue
        required_status = label_spec.required_validation_status
        subject = subjects.get(row["case_id"])
        verdict = row.get("verdict") or {}
        matched = False
        for payload in verdict.get("votes", []):
            try:
                vote = AgentExpertVote.model_validate(payload)
                if vote.label != label or vote.validation_status != required_status or vote.runtime_mode != "live":
                    continue
                retrieval_evidence = frozenset(
                    evidence_id for evidence_id in vote.evidence_ids
                    if evidence_id.startswith(_RETRIEVAL_PREFIXES)
                )
                validate_conclusion(vote, list(vote.trace), retrieval_evidence, subject=subject)
            except (TypeError, ValueError):
                continue
            matched = True
        if not matched or verdict.get("label") != label or verdict.get("runtime_mode") != "live":
            issues.append(f"{cell}: no matching candidate-bound executed validator evidence")
    if (
        usage["requests"] <= 0
        or usage["responses"] != usage["requests"]
        or sum(row.get("model_calls", 0) for row in rows) != usage["requests"]
        or any(usage.get(field, 0) != 0 for field in (
            "invalid_responses",
            "requests_without_reported_usage",
            "usage_conflicts",
            "orphaned_responses",
            "duplicate_request_starts",
        ))
    ):
        issues.append("Incomplete, failed or inconsistent request/usage accounting")
    return issues


def _safe_gate_directory(root: Path, pointer_path: Path) -> Path:
    payload = json.loads(pointer_path.read_text())
    relative = PurePosixPath(payload["run_directory"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Python pair gate pointer escapes the project root")
    directory = (root / Path(relative.as_posix())).resolve()
    expected = (root / "artifacts/python_pair_gate").resolve()
    if not directory.is_relative_to(expected):
        raise ValueError("Python pair gate pointer must target artifacts/python_pair_gate")
    return directory


def _pair_descriptor_subset(gate: PythonPairExperimentConfig, matrix: PythonPairExperimentConfig) -> bool:
    matrix_pairs = {pair.pair_id: pair.model_dump(mode="json") for pair in matrix.pairs}
    return all(matrix_pairs.get(pair.pair_id) == pair.model_dump(mode="json") for pair in gate.pairs)


def _revalidate_case_identities(root: Path, config: PythonPairExperimentConfig, stored: dict) -> None:
    for pair in config.pairs:
        for case in pair.cases:
            require_clean_checkout(root / case.checkout, case.commit)
            _, _, source_sha256 = build_pair_input(root, pair, case)
            current = case_identity(root, pair, case, source_sha256)
            if stored.get(case.case_id) != current:
                raise ValueError(f"Gate checkout/source identity is stale for {case.case_id}")


def require_python_pair_gate(root: Path, matrix_config: PythonPairExperimentConfig) -> Path:
    if matrix_config.dataset_role != "paired_development_matrix" or not matrix_config.requires_gate_pointer:
        raise ValueError("Python pair matrix config is required")
    pointer = root / matrix_config.requires_gate_pointer
    if not pointer.is_file():
        raise ValueError("Python pair gate is required before the controlled matrix")
    try:
        directory = _safe_gate_directory(root, pointer)
        metadata = json.loads((directory / "metadata.json").read_text())
        gate_config = PythonPairExperimentConfig.model_validate(metadata["config"])
        labels = PythonPairLabels.model_validate_json((root / gate_config.label_file).read_text())
        if gate_config.dataset_role != "paired_development_gate":
            raise ValueError("Gate artifact has the wrong dataset role")
        if metadata["source_fingerprint"] != source_fingerprint(root):
            raise ValueError("Gate source/config/tests snapshot is stale")
        if metadata["model_config"] != json.loads((root / matrix_config.model_config_path).read_text()):
            raise ValueError("Gate model config does not match matrix model config")
        if gate_config.systems != matrix_config.systems or gate_config.concurrency != matrix_config.concurrency:
            raise ValueError("Gate protocol does not match matrix protocol")
        if not _pair_descriptor_subset(gate_config, matrix_config):
            raise ValueError("Matrix does not include the admitted pair descriptors")
        _revalidate_case_identities(root, gate_config, metadata["case_identities"])
        events = [json.loads(line) for line in (directory / "events.jsonl").read_text().splitlines()]
        if not events or events[-1].get("event") != "run_end" or events[-1].get("interrupted"):
            raise ValueError("Gate run is incomplete or interrupted")
        rows = [event["result"] for event in events if event.get("event") == "trial_result"]
        subjects = {
            case_id: ValidationSubject.model_validate(value)
            for case_id, value in metadata["subjects"].items()
        }
        issues = pair_acceptance_issues(rows, provider_usage(events), gate_config, labels, subjects)
        issues.extend(transport_issues(events, metadata["model_config"]))
        if issues:
            raise ValueError("Python pair gate failed: " + "; ".join(issues))
        return directory
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("Python pair gate artifacts are incomplete or invalid") from error
