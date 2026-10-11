"""Prepare or run a bounded scenario-source comparison with one model and arm."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import Field, model_validator

from cv_agent.domain.types import Candidate, FrozenModel
from cv_agent.evaluation.datasets.advisory_source import (
    NeutralDetectorSourceCase, build_pair_input, case_identity, require_clean_checkout,
)
from cv_agent.evaluation.datasets.composition import load_advisory_config
from cv_agent.runtime.witness.isolation_policy import IsolationReadGrant
from cv_agent.evaluation.diagnostics.witness_scenario_preflight import preflight_cells
from cv_agent.evaluation.diagnostics.audit_witness_scenario_requests import audit as audit_requests
from cv_agent.evaluation.execution import run_candidate
from cv_agent.evaluation.experiment_guard import (
    ExperimentGuard, ExperimentGuardPolicy, ExperimentHardStop,
    GuardedExperimentBudget, require_committed_clean,
)
from cv_agent.evaluation.metrics import provider_usage
from cv_agent.evaluation.results import save_json
from cv_agent.harness import AgentSystemVersion
from cv_agent.retrieval import RepositoryIndex
from cv_agent.runtime.admission import require_passing_tests
from cv_agent.runtime.journal import Journal
from cv_agent.runtime.paths import PROJECT_ROOT
from cv_agent.runtime.provider import load_experiment_model
from cv_agent.runtime.snapshots import snapshot_sources
from cv_agent.runtime.witness_resources import WitnessResourceProfile
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.validation.registry import full_agent_tools
from cv_agent.tools.validation.witness_manifest import WitnessExecutionContext
from cv_agent.tools.validation.witness_scenario import WitnessScenarioHypothesis


CONFIG_PATH = "configs/experiments/witness_scenario_2x2.json"
ORIGINS = ("dataset_provided", "model_proposed")


class ScenarioCase(FrozenModel):
    case_id: str
    python_executable: str


class ScenarioMatrixConfig(FrozenModel):
    dataset_role: Literal["development"]
    claim_eligible: Literal[False]
    dataset: str
    selection_profile: str
    model_config_path: str = Field(alias="model_config")
    system: Literal["E1"]
    max_requests: int = Field(ge=4, le=60)
    max_seconds: int = Field(ge=1)
    phase_id: str = Field(min_length=1)
    origins: tuple[Literal["dataset_provided", "model_proposed"], ...] = ORIGINS
    expected_returned_model: str = Field(min_length=1)
    authorization_ledger: str
    cumulative_request_limit: int = Field(ge=1)
    cumulative_token_limit: int = Field(ge=1)
    output_token_limit: int = Field(ge=1)
    framing_token_allowance: int = Field(ge=1)
    continue_on_cell_failure: bool = False
    response_mode: Literal["full", "compact"] = "full"
    resource_profile: str
    read_grants: str
    advisory_text: str = Field(min_length=1)
    advisory_text_origin: Literal["dataset_advisory_summary"]
    advisory_text_note: str = Field(min_length=1)
    dataset_scenario: WitnessScenarioHypothesis | None = None
    cases: tuple[ScenarioCase, ...] = Field(min_length=2, max_length=4)

    @model_validator(mode="after")
    def unique_cases(self):
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("The scenario experiment requires distinct snapshots")
        if not self.origins or len(set(self.origins)) != len(self.origins):
            raise ValueError("Scenario origins must be a nonempty unique sequence")
        if "dataset_provided" in self.origins and self.dataset_scenario is None:
            raise ValueError("Dataset-provided cells require classified dataset assumptions")
        return self


@dataclass(frozen=True)
class ScenarioCell:
    evaluation_case_id: str
    scenario_origin: str
    index: RepositoryIndex
    candidate: Candidate
    context: WitnessExecutionContext
    registered_tools: tuple
    identity: dict[str, Any]
    fixed: bool


def load_config(root: Path = PROJECT_ROOT, configuration: Path | None = None) -> ScenarioMatrixConfig:
    path = root / CONFIG_PATH if configuration is None else root / configuration
    return ScenarioMatrixConfig.model_validate_json(path.read_text())


def prepare_cells(root: Path, config: ScenarioMatrixConfig, *,
                  runtime_root: Path, nonce: str) -> tuple[ScenarioCell, ...]:
    """No credentials, model requests, worker execution or filesystem writes."""
    advisory = load_advisory_config(root, config.selection_profile, dataset_path=config.dataset)
    if advisory.claim_eligible:
        raise ValueError("Scenario discovery comparison requires development data")
    grants = tuple(IsolationReadGrant.model_validate(item)
                   for item in json.loads((root / config.read_grants).read_text()))
    resources = WitnessResourceProfile.model_validate_json((root / config.resource_profile).read_text())
    selected = []
    for setting in config.cases:
        matches = [(pair, case) for pair in advisory.pairs for case in pair.cases
                   if case.case_id == setting.case_id]
        if len(matches) != 1:
            raise ValueError("Each selected snapshot must identify one advisory candidate")
        pair, case = matches[0]
        if pair.property_id != "command-execution":
            raise ValueError("The current bounded witness supports command-execution")
        require_clean_checkout(root / case.checkout, case.commit)
        selected.append((pair, case, setting))
    pairs = {}
    for pair, case, setting in selected:
        pairs.setdefault(pair.pair_id, []).append(case)
    for cases in pairs.values():
        if len(cases) != 2:
            raise ValueError("Exactly two snapshots must be selected for each advisory pair")
        if {case.revision_role for case in cases} != {"vulnerable", "fixed"}:
            raise ValueError("Each selected pair requires vulnerable and fixed revision roles")
    cells = []
    for origin in config.origins:
        for pair, case, setting in selected:
            # Evaluation identities and revision labels remain private to the
            # journal. Source paths are the same repository-relative paths on
            # both versions; no a/b aliases or commit directories reach prompts.
            neutral = NeutralDetectorSourceCase.from_case(case)
            index, candidate, hashes = build_pair_input(
                root, pair, neutral,
                include_scenario_assumptions=origin == "dataset_provided",
                advisory_text=config.advisory_text,
                include_scoped_operation=False,
            )
            subject = candidate_subject(index, candidate)
            if (origin == "dataset_provided"
                    and config.dataset_scenario.execution_subject(subject) != subject):
                raise ValueError("Dataset classifications must match the supplied subject assumptions")
            context = WitnessExecutionContext(
                checkout_root=(root / case.checkout).resolve(),
                python_executable=root / setting.python_executable,
                import_root=pair.python_import_root or ".", resource_profile=resources,
                read_grants=grants, runtime_root=runtime_root,
                dataset_scenario=config.dataset_scenario if origin == "dataset_provided" else None,
                response_mode=config.response_mode,
            )
            registered = tuple(full_agent_tools(index,
                witness_contexts={candidate.repository_id: context},
                witness_nonce_factory=lambda: nonce))
            cells.append(ScenarioCell(setting.case_id, origin, index, candidate, context,
                                      registered, case_identity(root, pair, case, hashes),
                                      case.revision_role == "fixed"))
    return tuple(cells)


def preparation_record(root: Path, config: ScenarioMatrixConfig,
                       cells: tuple[ScenarioCell, ...]) -> dict[str, Any]:
    return {
        "dataset_role": config.dataset_role, "claim_eligible": False,
        "system": config.system, "max_requests": config.max_requests,
        "max_seconds": config.max_seconds, "live_model_requests": 0,
        "phase_id": config.phase_id, "origins": config.origins,
        "response_mode": config.response_mode,
        "expected_returned_model": config.expected_returned_model,
        "cumulative_request_limit": config.cumulative_request_limit,
        "cumulative_token_limit": config.cumulative_token_limit,
        "declared_model_config": json.loads((root / config.model_config_path).read_text()),
        "advisory_text": config.advisory_text,
        "advisory_text_origin": config.advisory_text_origin,
        "advisory_text_note": config.advisory_text_note,
        "cells": [{
            "evaluation_case_id": cell.evaluation_case_id,
            "scenario_origin": cell.scenario_origin,
            "candidate": cell.candidate.model_dump(mode="json"),
            "subject": candidate_subject(cell.index, cell.candidate).model_dump(mode="json"),
            "case_identity": cell.identity,
        } for cell in cells],
        "resource_profile": cells[0].context.resource_profile.model_dump(mode="json"),
        "read_policy_sha256": hashlib.sha256((root / config.read_grants).read_bytes()).hexdigest(),
        "request_preflight": preflight_cells(cells, config),
        "note": "Development snapshots are compared within each advisory pair and declared scenario origin. "
                "Advisory and entry hints remain supplied; this is not repository-only held-out discovery.",
    }


class CellJournal:
    def __init__(self, journal: Journal, cell: ScenarioCell, guard: ExperimentGuard):
        self.journal, self.cell, self.guard = journal, cell, guard

    def write(self, event):
        enriched = {"evaluation_case_id": self.cell.evaluation_case_id,
                    "scenario_origin": self.cell.scenario_origin, **event}
        self.journal.write(enriched)
        self.guard.after_event(enriched)


def _witness_records(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records = []
    for event in events:
        observation = event.get("observation", {})
        if event["event"] != "tool_result" or observation.get("tool") != "run_bounded_execution_witness":
            continue
        try:
            payload = json.loads(observation["content"])
        except json.JSONDecodeError:
            payload = None
        records.append({
            "evaluation_case_id": event["evaluation_case_id"],
            "scenario_origin": event["scenario_origin"],
            "validation_status": observation.get("validation_status"),
            "status": observation["status"], "metadata": observation.get("metadata", {}),
            "payload": payload,
        })
    return records


def summarize(output: Path, rows: list[dict[str, Any]], events: list[dict[str, Any]],
              config: ScenarioMatrixConfig, guard: ExperimentGuard | None = None) -> dict[str, Any]:
    records = _witness_records(events)
    summary = {"dataset_role": "development", "claim_eligible": False,
               "system": config.system, "max_requests": config.max_requests,
               "usage": provider_usage(events), "conditions": {},
               "witness_records": records,
               "note": "Results and usage are separated by scenario origin; "
                       "literal observations remain UNRESOLVED. No held-out or pooled recall claim."}
    if guard is not None:
        summary["hard_stop"] = guard.hard_stop
        summary["authorization_accounting"] = {
            "ledger_path": str(guard.ledger_path), "source_commit": guard.commit,
            "cumulative_requests": len(guard.ledger["requests"]),
            "cumulative_reported_tokens": guard.reported_tokens,
            "cumulative_accounted_tokens": guard.accounted_tokens,
            "request_limit": config.cumulative_request_limit,
            "token_limit": config.cumulative_token_limit,
        }
    for origin in config.origins:
        selected = [row for row in rows if row["scenario_origin"] == origin]
        observed = [record for record in records if record["scenario_origin"] == origin]
        confirmed = {record["evaluation_case_id"] for record in observed
                     if record["status"] == "ok" and record["validation_status"] == "CONFIRMED"
                     and record["metadata"].get("witness_attempted") is True
                     and not record["metadata"].get("observation_truncated")
                     and not record["metadata"].get("model_payload_suppressed")}
        summary["conditions"][origin] = {
            "cells": len(selected), "confirmed_cells": sorted(confirmed),
            "cell_outcomes": [{"evaluation_case_id": row["evaluation_case_id"],
                               "status": row["status"], "predicted_label": row["predicted_label"]}
                              for row in selected],
            "usage": provider_usage([event for event in events if event.get("scenario_origin") == origin]),
        }
    save_json(output / "results.json", rows)
    save_json(output / "usage.json", summary["usage"])
    save_json(output / "summary.json", summary)
    return summary


def run(root: Path = PROJECT_ROOT, output: Path | None = None, *, configuration: Path | None = None) -> Path:
    """Live entrypoint; admission and credentials are never used by preparation."""
    config = load_config(root) if configuration is None else load_config(root, configuration)
    output = output or root / "artifacts/witness_scenario_matrix" / uuid4().hex
    cells = prepare_cells(root, config, runtime_root=(output / "shared-runtime").resolve(), nonce=uuid4().hex)
    require_committed_clean(root)
    require_passing_tests()
    model_config, api_key = load_experiment_model(root, config.model_config_path)
    if (model_config.get("model") != config.expected_returned_model
            or model_config.get("max_tokens") != config.output_token_limit):
        raise ValueError("Resolved model identity and output ceiling must match the approved guard configuration")
    output.mkdir(parents=True, exist_ok=False)
    journal = Journal(output / "events.jsonl")
    guard = ExperimentGuard(root=root, ledger_path=root / config.authorization_ledger,
        phase_id=config.phase_id, phase_request_limit=config.max_requests,
        run_id=str(output.resolve()), journal=journal,
        preflight=lambda: require_committed_clean(root),
        policy=ExperimentGuardPolicy(expected_model_id=config.expected_returned_model,
            cumulative_request_limit=config.cumulative_request_limit,
            cumulative_token_limit=config.cumulative_token_limit,
            output_token_limit=config.output_token_limit,
            framing_token_allowance=config.framing_token_allowance))
    save_json(output / "metadata.json", {
        "config": config.model_dump(mode="json", by_alias=True),
        "preparation": preparation_record(root, config, cells), "model_config": model_config,
        "source_sha256": snapshot_sources(root, output),
        "source_commit": guard.commit, "authorization_ledger": str(guard.ledger_path),
    })
    rows = [{"evaluation_case_id": cell.evaluation_case_id, "scenario_origin": cell.scenario_origin,
             "system": config.system, "status": "not_run", "predicted_label": None,
             "verdict": None, "model_calls": 0, "tool_calls": 0, "latency_sec": 0}
            for cell in cells]
    budget = GuardedExperimentBudget(config.max_requests, config.max_seconds, guard)
    journal.write({"event": "run_start", "max_requests": config.max_requests,
                   "dataset_role": "development", "claim_eligible": False})
    summarize(output, rows, [], config, guard)
    try:
        for position, cell in enumerate(cells):
            guard.bind_cell(json.dumps([cell.scenario_origin, cell.evaluation_case_id]), fixed=cell.fixed)
            try:
                result = run_candidate(cell.index, cell.candidate, AgentSystemVersion.E1_LOCAL_SINGLE,
                                       CellJournal(journal, cell, guard), budget, model_config=model_config,
                                       api_key=api_key, registered_tools=cell.registered_tools)
            except KeyboardInterrupt:
                # run_candidate durably journals its interruption before
                # re-raising. Preserve that result in the reviewable matrix.
                events = [json.loads(line) for line in journal.path.read_text().splitlines()]
                result = next(event["result"] for event in reversed(events)
                              if event["event"] == "trial_result"
                              and event.get("scenario_origin") == cell.scenario_origin
                              and event.get("evaluation_case_id") == cell.evaluation_case_id)
                rows[position].update(result)
                raise
            rows[position].update(result)
            events = [json.loads(line) for line in journal.path.read_text().splitlines()]
            summarize(output, rows, events, config, guard)
            print(f"{position + 1}/{len(cells)} {cell.scenario_origin} {cell.evaluation_case_id}: {result['status']}", flush=True)
            if guard.hard_stop is not None:
                raise ExperimentHardStop(guard.hard_stop["code"], guard.hard_stop["reason"])
            guard.finish_cell()
            if result["status"] in {"failed", "interrupted", "not_run"}:
                if not config.continue_on_cell_failure:
                    raise RuntimeError(f"Scenario comparison stopped: {result.get('error', result['status'])}")
    finally:
        budget.stop()
        journal.write({"event": "run_end", "admitted_requests": budget.used})
        events = [json.loads(line) for line in journal.path.read_text().splitlines()]
        summarize(output, rows, events, config, guard)
        save_json(output / "request_audit.json", audit_requests(output))
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Make the approved bounded model experiment")
    parser.add_argument("--configuration", type=Path, help="Explicit phase configuration; defaults to the initial comparison")
    args = parser.parse_args()
    if args.live:
        print(run(configuration=args.configuration))
    else:
        config = load_config(configuration=args.configuration)
        cells = prepare_cells(PROJECT_ROOT, config,
                              runtime_root=PROJECT_ROOT / "artifacts/witness_scenario_preview/shared-runtime",
                              nonce="PREPARATIONONLY123456")
        record = preparation_record(PROJECT_ROOT, config, cells)
        for cell in record["cells"]:
            identity = cell["case_identity"]
            identity["source_file_count"] = len(identity.pop("source_sha256"))
        print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
