"""Run the fixed 10-cell Python paired development gate."""
from __future__ import annotations

import json
import os
import signal
from pathlib import Path
from uuid import uuid4

from cv_agent.evaluation.runners.reproduce_langchain_template_pair import reproduce_pair as reproduce_langchain_pair
from cv_agent.runtime.budget import BudgetExceeded, LockedBudget, execute_trials
from cv_agent.runtime.journal import LockedJournal, utc_now
from cv_agent.evaluation.runners.run_development_benchmark import run_candidate
from cv_agent.runtime.snapshots import snapshot_sources
from cv_agent.runtime.paths import PROJECT_ROOT as project_root
from cv_agent.tools.identity import candidate_subject
from cv_agent.evaluation.metrics import metrics, paired, provider_usage, replay_fast_prefix
from cv_agent.evaluation.protocols.development import transport_issues
from cv_agent.harness import AgentSystemVersion
from cv_agent.runtime.admission import require_passing_tests, source_fingerprint
from cv_agent.evaluation.protocols.python_pair import pair_acceptance_issues
from cv_agent.evaluation.datasets.python_pair_config import PythonPairExperimentConfig, PythonPairLabels
from cv_agent.evaluation.datasets.python_pair_fixture import build_pair_input, case_identity, pair_fixture_tool, require_clean_checkout
from cv_agent.tools.validation import full_agent_tools


def save_json(path: Path, value) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def write_latest_pointer(root: Path, run_dir: Path) -> None:
    pointer = root / "artifacts/python_pair_gate.json"
    pointer.parent.mkdir(parents=True, exist_ok=True)
    relative = run_dir.relative_to(root).as_posix()
    save_json(pointer, {"run_directory": relative})


def load_reproduction_matrix(path: Path) -> dict:
    return json.loads((path / "results.json").read_text())["matrix"]


def reproduce_required_pairs(root: Path, run_dir: Path, config: PythonPairExperimentConfig) -> dict[str, dict]:
    reproductions: dict[str, dict] = {}
    for pair in config.pairs:
        if pair.pair_id != "langchain_template_traversal":
            raise ValueError("The gate admits only the LangChain pair")
        output = run_dir / "pair_preflight/langchain"
        result = reproduce_langchain_pair(output)
        if not result["summary"]["verified_differential_security"]:
            raise ValueError("LangChain pair preflight failed")
        reproductions[pair.pair_id] = load_reproduction_matrix(output)
    return reproductions


def observations_for(reproductions: dict[str, dict], pair_id: str, revision_role: str) -> dict:
    return reproductions[pair_id][revision_role]


def build_tasks(root: Path, config: PythonPairExperimentConfig, reproductions: dict[str, dict]):
    tasks = []
    subjects = {}
    identities = {}
    for pair in config.pairs:
        for case in pair.cases:
            require_clean_checkout(root / case.checkout, case.commit)
            index, candidate, source_sha256 = build_pair_input(root, pair, case)
            subjects[case.case_id] = candidate_subject(index, candidate)
            identities[case.case_id] = case_identity(root, pair, case, source_sha256)
            fixture = pair_fixture_tool(
                root,
                pair,
                case,
                index,
                candidate,
                observations_for(reproductions, pair.pair_id, case.revision_role),
            )
            registered = tuple(tool for tool in full_agent_tools(index) if tool.name != fixture.name) + (fixture,)
            for system in config.systems:
                tasks.append((pair.pair_id, case.revision_role, index, candidate, registered, system))
    return tasks, subjects, identities


def rows_with_truth(rows: list[dict], config: PythonPairExperimentConfig) -> list[dict]:
    labels = {
        case.case_id: "VULNERABLE" if case.revision_role == "vulnerable" else "SAFE"
        for pair in config.pairs
        for case in pair.cases
    }
    categories = {
        case.case_id: pair.pair_id
        for pair in config.pairs
        for case in pair.cases
    }
    observed = {(row["case_id"], row["system"]): row for row in rows}
    enriched = []
    for pair in config.pairs:
        for case in pair.cases:
            for system in config.systems:
                key = (case.case_id, system.value)
                row = observed.get(key, {
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
                })
                enriched.append({
                    **row,
                    "ground_truth": labels[case.case_id],
                    "category": categories[case.case_id],
                })
    return enriched


def summarize_pair_run(run_dir: Path, config: PythonPairExperimentConfig, rows: list[dict], usage: dict) -> dict:
    enriched = rows_with_truth(rows, config)
    systems = [system.value for system in config.systems]
    summary = {
        "claim_eligible": False,
        "dataset_role": config.dataset_role,
        "systems": {
            system: metrics([row for row in enriched if row["system"] == system])
            for system in systems
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
    config = PythonPairExperimentConfig.model_validate_json((root / "configs/experiments/python_pair_gate.json").read_text())
    run_dir = output or root / "artifacts/python_pair_gate" / uuid4().hex
    run_dir.mkdir(parents=True, exist_ok=False)
    write_latest_pointer(root, run_dir)
    require_passing_tests()
    if not os.environ.get("ANTIGRAVITY_API_KEY"):
        raise ValueError("ANTIGRAVITY_API_KEY is required")
    labels = PythonPairLabels.model_validate_json((root / config.label_file).read_text())
    model_config = json.loads((root / config.model_config_path).read_text())
    reproductions = reproduce_required_pairs(root, run_dir, config)
    tasks, subjects, identities = build_tasks(root, config, reproductions)
    save_json(run_dir / "metadata.json", {
        "started_at": utc_now(),
        "config": config.model_dump(mode="json", by_alias=True),
        "model_config": model_config,
        "source_fingerprint": source_fingerprint(root),
        "source_sha256": snapshot_sources(root, run_dir),
        "subjects": {case: subject.model_dump(mode="json") for case, subject in subjects.items()},
        "case_identities": identities,
        "claim_eligible": False,
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
        if row["status"] != "completed":
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
        decision = {"passed": not issues, "issues": issues, "automatic_expansion": False}
        save_json(run_dir / "acceptance.json", decision)
        journal.write({"event": "run_end", "interrupted": interrupted or budget.cancelled.is_set()})
    print(json.dumps(decision), flush=True)
    return run_dir


if __name__ == "__main__":
    run()
