"""Record hp003 command-proof gaps on both source snapshots without model calls.

Run once with ``baseline`` to import the preserved six-cell observations, then
with a descriptive stage name after each offline code change. No credentials are
loaded and this module never constructs a live model transport.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.domain.types import FrozenModel
from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairCell
from cv_agent.evaluation.datasets.advisory_tasks import build_tasks
from cv_agent.evaluation.datasets.composition import load_advisory_config
from cv_agent.evaluation.runners.run_jev_v3_comparison import JevV3ComparisonConfig
from cv_agent.harness import AgentSystemVersion, FULL_SYSTEM_HARNESS
from cv_agent.runtime.admission import source_fingerprint
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.runtime.paths import PROJECT_ROOT
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation.commands import command_construction
from cv_agent.tools.validation.models import CommandConstructionInput


BASELINE_RUN = PROJECT_ROOT / "artifacts/jev_v3_comparison/545892d6559f439a94ef307cc021cac3"
OUTPUT = PROJECT_ROOT / "artifacts/hp003_offline_gap_progression/gaps.json"
CONFIG = PROJECT_ROOT / "configs/experiments/jev_v3_hp003_comparison.json"


def _fingerprint_from_saved_hashes(hashes: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for name, content_hash in sorted(hashes.items()):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(bytes.fromhex(content_hash))
    return digest.hexdigest()


def _summary(content: str) -> dict:
    data = json.loads(content)
    return {
        "command_construction_status": data["command_construction_status"],
        "analysis_gaps": data.get("analysis_gaps", []),
        "issues": data.get("issues", []),
        "unresolved_calls": data.get("unresolved_calls", []),
        "sink_facts": data.get("sink_facts", []),
    }


def capture_baseline() -> dict:
    metadata = json.loads((BASELINE_RUN / "metadata.json").read_text())
    rows = json.loads((BASELINE_RUN / "results.json").read_text())
    events = [json.loads(line) for line in (BASELINE_RUN / "events.jsonl").read_text().splitlines()]
    cases = {}
    for row in rows:
        if row["system"] != "E4_RULE_V1":
            continue
        case_id = row["case_id"]
        checks = [
            step["observation"]
            for task in row["verdict"]["task_executions"]
            for step in task["vote"]["trace"]
            if step["observation"]["tool"] == "inspect_command_construction"
            and step["observation"]["status"] == "ok"
            and not step["observation"].get("metadata", {}).get("observation_truncated")
        ]
        starts = [
            event for event in events
            if event.get("event") == "tool_start"
            and event.get("case_id") == case_id
            and event.get("system") == "E4_RULE_V1"
            and event["call"]["name"] == "inspect_command_construction"
        ]
        if not checks or not starts:
            raise ValueError(f"Saved rule cell lacks an intact command check: {case_id}")
        admitted = starts[0]["admitted_paths"]
        if any(item["admitted_paths"] != admitted for item in starts):
            raise ValueError(f"Rule cell used inconsistent admitted paths: {case_id}")
        cases[case_id] = {
            **_summary(checks[0]["content"]),
            "candidate_subject": metadata["subjects"][case_id],
            "admitted_paths": admitted,
            "context_token_count": row["verdict"]["retrieval_context_token_count"],
            "admission_records": [],
        }
    if set(cases) != {"hp003_a", "hp003_b"}:
        raise ValueError("Baseline must contain both hp003 snapshots")
    return {
        "stage": "baseline",
        "origin": str(BASELINE_RUN.relative_to(PROJECT_ROOT)),
        "source_fingerprint": _fingerprint_from_saved_hashes(metadata["source_sha256"]),
        "cases": cases,
    }


def _jsonable(value):
    if isinstance(value, FrozenModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def capture_offline(stage: str) -> dict:
    config = JevV3ComparisonConfig.model_validate_json(CONFIG.read_text())
    advisory = load_advisory_config(PROJECT_ROOT, config.advisory_profile)
    payload = advisory.model_dump(mode="json", by_alias=True)
    payload["selected_cells"] = [
        PythonHeldoutPairCell(
            case_id=case_id,
            system=AgentSystemVersion.E4_GRAPH_MULTI,
        ).model_dump(mode="json")
        for case_id in config.case_ids
    ]
    payload["expected_abstentions"] = []
    advisory = type(advisory).model_validate(payload)
    tasks, _, _ = build_tasks(PROJECT_ROOT, advisory, fixture_policy="disabled")
    cases = {}
    for _, _, index, candidate, registered, _ in tasks:
        models = {role: ScriptedChatModel([]) for role in ("planner", "scan", "taint", "authz")}
        pipeline = AgenticPipeline(
            index=index,
            system=AgentSystemVersion.E4_GRAPH_MULTI,
            models=models,
            tools=ToolRegistry(
                registered,
                max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
            ),
            graph_direction=advisory.graph_direction,
            graph_ranking=advisory.graph_ranking,
        )
        retrieved = pipeline._retrieve({"candidate": candidate})
        admitted = frozenset(item.path for item in retrieved["evidence"])
        subject = candidate_subject(index, candidate)
        observation = command_construction(
            index,
            CommandConstructionInput(source_path=candidate.path, max_hops=2),
            ToolExecutionScope(
                admitted_paths=admitted,
                candidate_path=candidate.path,
                subject=subject,
                max_observation_tokens=100_000,
            ),
        )
        if observation.status != "ok":
            raise ValueError(f"Offline command check failed: {candidate.case_id}: {observation.content}")
        cases[candidate.case_id] = {
            **_summary(observation.content),
            "candidate_subject": subject.model_dump(mode="json"),
            "admitted_paths": sorted(admitted),
            "context_token_count": retrieved["context_token_count"],
            "admission_records": _jsonable(retrieved.get("admission_records", [])),
            "admission_subject_digest": retrieved.get("admission_subject_digest"),
            "admitted_document_sha256": {
                path: hashlib.sha256(index.document(path).text.encode()).hexdigest()
                for path in sorted(admitted)
            },
        }
        if any(model.requests for model in models.values()):
            raise AssertionError("Gap diagnostic must not call any model")
    if set(cases) != {"hp003_a", "hp003_b"}:
        raise ValueError("Offline capture must contain both hp003 snapshots")
    return {"stage": stage, "origin": "offline_tool", "source_fingerprint": source_fingerprint(PROJECT_ROOT), "cases": cases}


def save_stage(stage: str) -> dict:
    result = capture_baseline() if stage == "baseline" else capture_offline(stage)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    history = json.loads(OUTPUT.read_text()) if OUTPUT.exists() else {"stages": []}
    if any(item["stage"] == stage for item in history["stages"]):
        raise ValueError(f"Stage already recorded: {stage}")
    history["stages"].append(result)
    OUTPUT.write_text(json.dumps(history, indent=2, ensure_ascii=False) + "\n")
    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m cv_agent.evaluation.diagnostics.hp003_gap_progression STAGE")
    output = save_stage(sys.argv[1])
    for case_id, case in sorted(output["cases"].items()):
        print(
            output["stage"], case_id, case["command_construction_status"],
            [(gap["call"], gap["kind"]) for gap in case["analysis_gaps"]],
        )
