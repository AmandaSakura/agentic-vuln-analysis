"""Shared lifecycle for advisory gate and matrix runs."""
from __future__ import annotations

import json
from pathlib import Path
import signal
from uuid import uuid4

from cv_agent.harness import AgentSystemVersion
from cv_agent.runtime.admission import require_passing_tests, source_fingerprint
from cv_agent.runtime.budget import BudgetExceeded, LockedBudget, execute_trials
from cv_agent.evaluation.execution import run_candidate
from cv_agent.runtime.journal import LockedJournal, utc_now
from cv_agent.runtime.provider import load_experiment_model
from cv_agent.runtime.snapshots import snapshot_sources
from .datasets.advisory_config import PythonHeldoutPairExperimentConfig
from .datasets.advisory_tasks import build_tasks
from .metrics import provider_usage
from .protocols.advisory import heldout_pair_acceptance_issues
from .protocols.development import transport_issues
from .results import rows_with_truth, save_json, summarize_pair_run


def run_advisory_experiment(
    root: Path,
    output: Path | None,
    config: PythonHeldoutPairExperimentConfig,
    *,
    run_root: str,
    latest_pointer: str | None = None,
    prepare=None,
    execute=None,
) -> Path:
    """Run the advisory protocol; preparation and execution can be supplied offline."""
    prepare_tasks = build_tasks if prepare is None else prepare
    execute_candidate = run_candidate if execute is None else execute
    manifest = json.loads((root / config.source_manifest).read_text())
    run_dir = output or root / run_root / uuid4().hex
    run_dir.mkdir(parents=True, exist_ok=False)
    if latest_pointer is not None:
        save_json(root / latest_pointer, {"run_directory": run_dir.relative_to(root).as_posix()})
    tasks, subjects, identities = prepare_tasks(root, config)
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
            "source_sha256": snapshot_sources(root, run_dir),
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
        row = execute_candidate(
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
