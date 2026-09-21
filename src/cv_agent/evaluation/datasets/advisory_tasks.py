"""Prepare the declared advisory candidate/system cells without executing models."""
from pathlib import Path

from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.validation import full_agent_tools
from .advisory_config import PythonHeldoutPairExperimentConfig, planned_heldout_cells
from .advisory_source import build_pair_input, case_identity, document_symbol, require_clean_checkout


def build_tasks(root: Path, config: PythonHeldoutPairExperimentConfig):
    tasks = []
    subjects = {}
    identities = {}
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
            registered = tuple(full_agent_tools(index))
            for _, _, system in planned_by_case[case.case_id]:
                tasks.append((pair.pair_id, case.revision_role, index, candidate, registered, system))
    return tasks, subjects, identities
