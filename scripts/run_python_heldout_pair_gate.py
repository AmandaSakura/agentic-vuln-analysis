"""Run the fixed 10-cell Python held-out advisory pair gate."""
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
from run_python_heldout_pair_matrix import (
    build_tasks,
    rows_with_truth,
    save_json,
    summarize_pair_run,
)
from cv_agent.benchmark_evaluation import provider_usage
from cv_agent.experiment_model import load_experiment_model
from cv_agent.experiment_acceptance import transport_issues
from cv_agent.harness import AgentSystemVersion
from cv_agent.live_gate import require_passing_tests, source_fingerprint
from cv_agent.python_heldout_pair_acceptance import heldout_pair_acceptance_issues
from cv_agent.python_heldout_pair_config import PythonHeldoutPairExperimentConfig


CONFIG_PATH = "configs/python_heldout_pair_gate_v4.json"
RUN_ROOT = "artifacts/python_heldout_pair_gate_v4"
LATEST_POINTER = "artifacts/python_heldout_pair_gate_v4.json"


def write_latest_pointer(root: Path, run_dir: Path) -> None:
    pointer = root / LATEST_POINTER
    pointer.parent.mkdir(parents=True, exist_ok=True)
    save_json(pointer, {"run_directory": run_dir.relative_to(root).as_posix()})


def load_config(root: Path) -> PythonHeldoutPairExperimentConfig:
    return PythonHeldoutPairExperimentConfig.model_validate_json((root / CONFIG_PATH).read_text())


def run(root: Path = project_root, output: Path | None = None) -> Path:
    config = load_config(root)
    manifest = json.loads((root / config.source_manifest).read_text())
    run_dir = output or root / RUN_ROOT / uuid4().hex
    run_dir.mkdir(parents=True, exist_ok=False)
    write_latest_pointer(root, run_dir)
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
