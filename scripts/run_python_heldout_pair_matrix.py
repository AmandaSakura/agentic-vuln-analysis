"""Run the frozen Python held-out advisory pair matrix."""
from __future__ import annotations

import json
import os
import signal
from pathlib import Path
from uuid import uuid4

from run_development_benchmark import (
    BudgetExceeded,
    LockedBudget,
    LockedJournal,
    execute_trials,
    run_candidate,
    snapshot_sources,
    utc_now,
)
from run_micro_benchmark import project_root
from cv_agent.agent_tools import candidate_subject
from cv_agent.benchmark_evaluation import metrics, paired, provider_usage, replay_fast_prefix
from cv_agent.experiment_model import load_experiment_model
from cv_agent.experiment_acceptance import transport_issues
from cv_agent.harness import AgentSystemVersion
from cv_agent.live_gate import require_passing_tests, source_fingerprint
from cv_agent.python_heldout_pair_acceptance import heldout_pair_acceptance_issues
from cv_agent.python_heldout_pair_config import (
    PythonHeldoutPairExperimentConfig,
    heldout_truth,
    planned_heldout_cells,
)
from cv_agent.python_heldout_pair_source import (
    build_pair_input,
    case_identity,
    document_symbol,
    require_clean_checkout,
)
from cv_agent.validation_tools import full_agent_tools


def save_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def load_config(root: Path) -> PythonHeldoutPairExperimentConfig:
    return PythonHeldoutPairExperimentConfig.model_validate_json(
        (root / "configs/python_heldout_pairs_v4.json").read_text()
    )


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


def rows_with_truth(rows: list[dict], config: PythonHeldoutPairExperimentConfig) -> list[dict]:
    observed: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        observed.setdefault((row["case_id"], row["system"]), []).append(row)
    enriched = []
    planned_keys = set()
    for pair, case, system in planned_heldout_cells(config):
        key = (case.case_id, system.value)
        planned_keys.add(key)
        matching_rows = observed.get(key) or [
            {
                "case_id": case.case_id,
                "system": system.value,
                "status": "not_run",
                "predicted_label": None,
                "model_calls": 0,
                "tool_calls": 0,
                "latency_sec": 0,
                "verdict": None,
                "pair_id": pair.pair_id,
                "revision_role": case.revision_role,
            }
        ]
        for row in matching_rows:
            enriched.append(
                {
                    **row,
                    "ground_truth": heldout_truth(case.revision_role),
                    "category": pair.advisory,
                    "entry_id": pair.entry_id,
                    "planned_cell": True,
                }
            )
    enriched.extend(
        {**row, "planned_cell": False} for row in rows
        if (row["case_id"], row["system"]) not in planned_keys
    )
    return enriched


def summarize_pair_run(
    run_dir: Path,
    config: PythonHeldoutPairExperimentConfig,
    rows: list[dict],
    usage: dict,
) -> dict:
    all_rows = rows_with_truth(rows, config)
    grouped: dict[tuple[str, str], list[dict]] = {}
    for row in all_rows:
        if row["planned_cell"]:
            grouped.setdefault((row["case_id"], row["system"]), []).append(row)
    enriched = []
    duplicates = []
    for (case_id, system), matches in grouped.items():
        if len(matches) == 1:
            enriched.append(matches[0])
            continue
        duplicates.append({"case_id": case_id, "system": system, "rows": len(matches)})
        # An invalid duplicate cell occupies one denominator slot. Its raw
        # records remain in results.json, but none can win by overwrite order.
        enriched.append({
            **matches[0], "status": "failed", "predicted_label": None, "verdict": None,
            "model_calls": sum(row["model_calls"] for row in matches),
            "tool_calls": sum(row["tool_calls"] for row in matches),
            "latency_sec": sum(row["latency_sec"] for row in matches),
        })
    systems = [system.value for system in config.systems]
    summary = {
        "claim_eligible": False,
        "dataset_role": config.dataset_role,
        "unexpected_rows": [row for row in all_rows if not row["planned_cell"]],
        "duplicate_cells": duplicates,
        "systems": {
            system: metrics([row for row in enriched if row["system"] == system])
            for system in systems
        },
        "advisories": {
            advisory: {
                system: metrics(
                    [
                        row
                        for row in enriched
                        if row["system"] == system and row["category"] == advisory
                    ]
                )
                for system in systems
            }
            for advisory in sorted({row["category"] for row in enriched})
        },
        "paired": {
            f"{left}_vs_{right}": paired(enriched, left, right)
            for left, right in (("E2", "E3"), ("E3", "E4"), ("E4", "E5"))
        },
        "usage": usage,
        "full_review_prefix_replays": {
            row["case_id"]: replay_fast_prefix(row["verdict"])
            for row in enriched
            if row["system"] == "E4" and row.get("verdict") is not None
        },
    }
    save_json(run_dir / "summary.json", summary)
    return summary


def run(root: Path = project_root, output: Path | None = None) -> Path:
    config = load_config(root)
    manifest = json.loads((root / config.source_manifest).read_text())
    run_dir = output or root / "artifacts/python_heldout_pair_matrix_v4" / uuid4().hex
    run_dir.mkdir(parents=True, exist_ok=False)
    tasks, subjects, identities = build_tasks(root, config)
    require_passing_tests()
    model_config, api_key = load_experiment_model(root, config.model_config_path)
    save_json(
        run_dir / "metadata.json",
        {
            "started_at": utc_now(),
            "config": config.model_dump(mode="json", by_alias=True),
            "source_manifest": manifest,
            "model_config": model_config,
            "source_fingerprint": source_fingerprint(root),
            "source_sha256": snapshot_sources(run_dir),
            "subjects": {case: subject.model_dump(mode="json") for case, subject in subjects.items()},
            "case_identities": identities,
            "claim_eligible": False,
        },
    )
    rows: list[dict] = []
    save_json(run_dir / "results.json", rows_with_truth(rows, config))
    journal = LockedJournal(run_dir / "events.jsonl")
    journal.write({"event": "run_start"})
    budget = LockedBudget(config.limits.max_requests, config.limits.max_seconds)
    print(f"Run directory: {run_dir}", flush=True)
    print(f"Planned cells: {len(tasks)}; concurrency: {config.concurrency}", flush=True)

    def worker(task):
        pair_id, revision_role, index, candidate, registered, system = task
        row = run_candidate(
            index,
            candidate,
            AgentSystemVersion(system),
            journal,
            budget,
            model_config=model_config,
            api_key=api_key,
            graph_direction=config.graph_direction,
            graph_ranking=config.graph_ranking,
            registered_tools=registered,
        )
        row["pair_id"] = pair_id
        row["revision_role"] = revision_role
        return row

    def progress(row):
        rows.append(row)
        save_json(run_dir / "results.json", rows_with_truth(rows, config))
        events = [json.loads(line) for line in journal.path.read_text().splitlines()]
        usage = provider_usage(events)
        save_json(run_dir / "usage.json", usage)
        summarize_pair_run(run_dir, config, rows, usage)
        print(
            f"{len(rows)}/{len(tasks)} {row['case_id']} {row['system']}: "
            f"{row['status']} {row['predicted_label']}",
            flush=True,
        )
        if row["status"] in {"interrupted", "not_run"}:
            budget.stop()

    def interrupt(signum, frame):
        raise KeyboardInterrupt("Experiment stop requested")

    interrupted = False
    previous_handler = signal.signal(signal.SIGTERM, interrupt)
    try:
        execute_trials(tasks, worker, budget, progress, config.concurrency)
    except BudgetExceeded as error:
        journal.write({"event": "budget_stop", "error": str(error)})
    except KeyboardInterrupt:
        interrupted = True
        budget.stop()
        raise
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
        events = [json.loads(line) for line in journal.path.read_text().splitlines()]
        usage = provider_usage(events)
        save_json(run_dir / "usage.json", usage)
        summarize_pair_run(run_dir, config, rows, usage)
        issues = heldout_pair_acceptance_issues(rows, usage, config)
        issues.extend(transport_issues(events, model_config))
        if interrupted or budget.cancelled.is_set():
            issues.append("Experiment interrupted")
        decision = {"passed": not issues, "issues": issues, "automatic_expansion": False}
        save_json(run_dir / "acceptance.json", decision)
        journal.write({"event": "run_end", "interrupted": interrupted or budget.cancelled.is_set()})
    print(json.dumps(decision), flush=True)
    return run_dir


if __name__ == "__main__":
    run()
