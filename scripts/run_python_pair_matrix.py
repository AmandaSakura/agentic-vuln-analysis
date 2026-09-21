"""Run the fixed 20-cell Python paired development matrix."""
from __future__ import annotations

import json
import os
import signal
from pathlib import Path
from uuid import uuid4

from reproduce_jinja_attr_pair import reproduce_pair as reproduce_jinja_pair
from reproduce_langchain_template_pair import reproduce_pair as reproduce_langchain_pair
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
from run_python_pair_gate import (
    build_tasks,
    load_reproduction_matrix,
    rows_with_truth,
    save_json,
    summarize_pair_run,
)
from cv_agent.agent_tools import candidate_subject
from cv_agent.benchmark_evaluation import provider_usage
from cv_agent.experiment_acceptance import transport_issues
from cv_agent.harness import AgentSystemVersion
from cv_agent.live_gate import require_passing_tests, source_fingerprint
from cv_agent.python_pair_acceptance import pair_acceptance_issues, require_python_pair_gate
from cv_agent.python_pair_config import PythonPairExperimentConfig, PythonPairLabels


def reproduce_required_pairs(root: Path, run_dir: Path, config: PythonPairExperimentConfig) -> dict[str, dict]:
    reproductions: dict[str, dict] = {}
    for pair in config.pairs:
        if pair.pair_id == "langchain_template_traversal":
            output = run_dir / "pair_preflight/langchain"
            result = reproduce_langchain_pair(output)
        elif pair.pair_id == "jinja_attr_format_escape":
            output = run_dir / "pair_preflight/jinja"
            result = reproduce_jinja_pair(output)
        else:
            raise ValueError(f"Unknown pair id: {pair.pair_id}")
        if not result["summary"]["verified_differential_security"]:
            raise ValueError(f"{pair.pair_id} preflight failed")
        reproductions[pair.pair_id] = load_reproduction_matrix(output)
    return reproductions


def run(root: Path = project_root, output: Path | None = None) -> Path:
    config = PythonPairExperimentConfig.model_validate_json((root / "configs/python_pair_matrix.json").read_text())
    require_python_pair_gate(root, config)
    require_passing_tests()
    if not os.environ.get("ANTIGRAVITY_API_KEY"):
        raise ValueError("ANTIGRAVITY_API_KEY is required")
    run_dir = output or root / "artifacts/python_pair_matrix" / uuid4().hex
    run_dir.mkdir(parents=True, exist_ok=False)
    labels = PythonPairLabels.model_validate_json((root / config.label_file).read_text())
    model_config = json.loads((root / config.model_config_path).read_text())
    reproductions = reproduce_required_pairs(root, run_dir, config)
    tasks, subjects, identities = build_tasks(root, config, reproductions)
    save_json(run_dir / "metadata.json", {
        "started_at": utc_now(),
        "config": config.model_dump(mode="json", by_alias=True),
        "model_config": model_config,
        "source_fingerprint": source_fingerprint(root),
        "source_sha256": snapshot_sources(run_dir),
        "subjects": {case: subject.model_dump(mode="json") for case, subject in subjects.items()},
        "case_identities": identities,
        "claim_eligible": False,
        "gate_directory": str(require_python_pair_gate(root, config).relative_to(root)),
    })
    rows: list[dict] = []
    save_json(run_dir / "results.json", rows)
    journal = LockedJournal(run_dir / "events.jsonl")
    journal.write({"event": "run_start"})
    budget = LockedBudget(config.limits.max_requests, config.limits.max_seconds)
    print(f"Run directory: {run_dir}", flush=True)

    def worker(task):
        pair_id, revision_role, index, candidate, registered, system = task
        row = run_candidate(index, candidate, AgentSystemVersion(system), journal, budget,
                            model_config=model_config, registered_tools=registered)
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
        print(f"{len(rows)}/{len(tasks)} {row['case_id']} {row['system']}: {row['status']} {row['predicted_label']}", flush=True)
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
        issues = pair_acceptance_issues(rows, usage, config, labels, subjects)
        issues.extend(transport_issues(events, model_config))
        if interrupted or budget.cancelled.is_set():
            issues.append("Experiment interrupted")
        decision = {"passed": not issues, "issues": issues}
        save_json(run_dir / "acceptance.json", decision)
        journal.write({"event": "run_end", "interrupted": interrupted or budget.cancelled.is_set()})
    print(json.dumps(decision), flush=True)
    return run_dir


if __name__ == "__main__":
    run()
