"""Prepare the declared advisory candidate/system cells without executing models."""
from pathlib import Path

from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.validation import full_agent_tools
from .advisory_config import PythonHeldoutPairExperimentConfig, planned_heldout_cells
from .advisory_fixtures import advisory_fixture_cases
from .advisory_source import build_pair_input, case_identity, document_symbol, require_clean_checkout


def _fixture_manifest(fixture_cases):
    entries = []
    for case in fixture_cases:
        entries.append({
            "tool": "run_fixture_test",
            "case_id": case.case_id,
            "subject": case.subject.model_dump(mode="json") if case.subject is not None else None,
            "validation_statuses": ["CONFIRMED", "REFUTED"],
            "isolated": case.isolated,
            "resource_limited": case.resource_limited,
            "timeout_seconds": case.timeout_seconds,
            "proof_boundary": (
                "trusted project fixture for this exact candidate/source/property; "
                "development regression evidence only, not an independent generalization claim"
            ),
        })
    return entries


def build_task_plan(root: Path, config: PythonHeldoutPairExperimentConfig, *, fixture_policy: str = "auto"):
    tasks = []
    subjects = {}
    identities = {}
    fixture_registry = {}
    planned_by_case: dict[str, list[tuple]] = {}
    for pair, case, system in planned_heldout_cells(config):
        planned_by_case.setdefault(case.case_id, []).append((pair, case, system))
    for pair in config.pairs:
        preferred_symbol = None
        for case in pair.cases:
            if case.case_id not in planned_by_case:
                continue
            require_clean_checkout(root / case.checkout, case.commit)
            index, candidate, source_sha256 = build_pair_input(
                root,
                pair,
                case,
                preferred_symbol=preferred_symbol if case.revision_role == "fixed" else None,
            )
            if case.revision_role == "vulnerable":
                preferred_symbol = document_symbol(candidate.path)
            subjects[case.case_id] = candidate_subject(index, candidate)
            identities[case.case_id] = case_identity(root, pair, case, source_sha256)
            fixture_cases = (
                advisory_fixture_cases(root, pair, case, index, candidate, source_sha256)
                if fixture_policy != "disabled"
                and config.dataset_role == "paired_heldout_advisory"
                and not config.claim_eligible
                else ()
            )
            if fixture_cases:
                fixture_registry[case.case_id] = _fixture_manifest(fixture_cases)
            registered = tuple(full_agent_tools(index, fixture_cases=fixture_cases))
            for _, _, system in planned_by_case[case.case_id]:
                tasks.append((pair.pair_id, case.revision_role, index, candidate, registered, system))
    return tasks, subjects, identities, fixture_registry


def build_tasks(root: Path, config: PythonHeldoutPairExperimentConfig, *, fixture_policy: str = "auto"):
    tasks, subjects, identities, _ = build_task_plan(root, config, fixture_policy=fixture_policy)
    return tasks, subjects, identities
