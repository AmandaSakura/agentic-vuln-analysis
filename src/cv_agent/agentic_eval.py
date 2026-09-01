from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass

from .agent_tools import ToolRegistry, repository_tools
from .agent_types import ModelReply, ModelToolCall
from .agentic_workflow import AgenticPipeline
from .harness import FULL_SYSTEM_HARNESS, AgentSystemVersion
from .metrics import TernaryEvaluation, evaluate_ternary
from .model_runtime import ScriptedChatModel
from .retrieval import RepositoryIndex
from .synthetic import cross_file_fixture, guarded_delete_fixture
from .types import Candidate, VerdictLabel


@dataclass(frozen=True)
class ScriptedAgenticCase:
    case_id: str
    label: bool
    index: RepositoryIndex
    candidate: Candidate
    scan_label: VerdictLabel
    taint_label: VerdictLabel
    authz_label: VerdictLabel
    scan_path: str
    taint_path: str
    authz_path: str
    rationale: str


def _tool_reply(role: str, name: str, arguments: dict[str, object]) -> ModelReply:
    return ModelReply(
        model_id=f"scripted-{role}",
        tool_calls=(
            ModelToolCall(
                call_id=f"{role}-tool-1",
                name=name,
                arguments=arguments,
            ),
        ),
    )


def _conclusion(
    expert: str,
    label: VerdictLabel,
    validation_status: str,
    evidence_ids: list[str],
    rationale: str,
) -> ModelReply:
    return ModelReply(
        model_id=f"scripted-{expert}",
        content=json.dumps(
            {
                "expert": expert,
                "label": label,
                "confidence": 0.9,
                "validation_status": validation_status,
                "evidence_ids": evidence_ids,
                "rationale": rationale,
            },
            sort_keys=True,
        ),
    )


def _planner_reply(candidate: Candidate) -> ModelReply:
    plan = {
        "candidate_id": candidate.candidate_id,
        "vulnerability_hypotheses": ["scripted diagnostic candidate"],
        "subtasks": [
            {
                "task_id": "scan-sensitive-operation",
                "objective": "Locate the suspicious operation in retrieved code.",
                "expert": "scan",
                "allowed_validator": "run_static_check",
                "dependencies": [],
                "success_condition": "The scan expert has inspected one retrieved span.",
            },
            {
                "task_id": "trace-or-refute-taint",
                "objective": "Check whether untrusted input reaches the operation.",
                "expert": "taint",
                "allowed_validator": "compare_vulnerable_and_fixed",
                "dependencies": ["scan-sensitive-operation"],
                "success_condition": "The taint expert confirms or refutes dataflow.",
            },
            {
                "task_id": "check-authorization-guard",
                "objective": "Check whether an authorization guard protects the operation.",
                "expert": "authz",
                "allowed_validator": "run_loopback_http_case",
                "dependencies": ["trace-or-refute-taint"],
                "success_condition": "The authz expert confirms or refutes guard coverage.",
            },
        ],
        "rationale": "Split scan, taint, and authorization questions before adjudication.",
    }
    return ModelReply(model_id="scripted-planner", content=json.dumps(plan, sort_keys=True))


def _status_for(label: VerdictLabel) -> str:
    if label == "VULNERABLE":
        return "CONFIRMED"
    if label == "SAFE":
        return "REFUTED"
    return "UNRESOLVED"


def _case_models(
    case: ScriptedAgenticCase,
    system: AgentSystemVersion,
) -> dict[str, ScriptedChatModel]:
    scan_path = case.scan_path
    scan_label = case.scan_label
    if system == AgentSystemVersion.E1_LOCAL_SINGLE and case.label:
        scan_path = case.candidate.path
        scan_label = "ABSTAIN"
    models = {
        "scan": ScriptedChatModel(
            [
                _tool_reply("scan", "read_span", {"path": scan_path}),
                _conclusion(
                    "scan",
                    scan_label,
                    _status_for(scan_label),
                    [f"span:{scan_path}"],
                    f"scan scripted diagnostic: {case.rationale}",
                ),
            ]
        )
    }
    if system in {
        AgentSystemVersion.E4_GRAPH_MULTI,
        AgentSystemVersion.E5_GRAPH_FAST,
    }:
        models.update(
            {
                "planner": ScriptedChatModel(
                    [
                        _tool_reply(
                            "planner",
                            "get_callees",
                            {"path": case.candidate.path},
                        ),
                        _planner_reply(case.candidate),
                    ]
                ),
                "taint": ScriptedChatModel(
                    [
                        _tool_reply("taint", "read_span", {"path": case.taint_path}),
                        _conclusion(
                            "taint",
                            case.taint_label,
                            _status_for(case.taint_label),
                            [f"span:{case.taint_path}"],
                            f"taint scripted diagnostic: {case.rationale}",
                        ),
                    ]
                ),
                "authz": ScriptedChatModel(
                    [
                        _tool_reply("authz", "read_span", {"path": case.authz_path}),
                        _conclusion(
                            "authz",
                            case.authz_label,
                            _status_for(case.authz_label),
                            [f"span:{case.authz_path}"],
                            f"authz scripted diagnostic: {case.rationale}",
                        ),
                    ]
                ),
            }
        )
    return models


def _matrix_payload(matrix: TernaryEvaluation) -> dict[str, object]:
    return {
        "tp": matrix.true_positive,
        "fp": matrix.false_positive,
        "tn": matrix.true_negative,
        "fn": matrix.false_negative,
        "abstain_positive": matrix.abstain_positive,
        "abstain_negative": matrix.abstain_negative,
        "strict_recall": matrix.strict_recall,
        "covered_recall": matrix.covered_recall,
        "population_false_positive_rate": matrix.population_false_positive_rate,
        "covered_false_positive_rate": matrix.covered_false_positive_rate,
        "precision": matrix.precision,
        "coverage": matrix.coverage,
        "abstain_rate": matrix.abstain_rate,
    }


def _fixtures() -> tuple[ScriptedAgenticCase, ...]:
    positive_index, positive_candidate = cross_file_fixture()
    negative_index, negative_candidate = guarded_delete_fixture()
    return (
        ScriptedAgenticCase(
            case_id=positive_candidate.case_id,
            label=True,
            index=positive_index,
            candidate=positive_candidate,
            scan_label="VULNERABLE",
            taint_label="VULNERABLE",
            authz_label="ABSTAIN",
            scan_path="service.py",
            taint_path="controller.py",
            authz_path="controller.py",
            rationale="cross-file request-to-subprocess command execution",
        ),
        ScriptedAgenticCase(
            case_id=negative_candidate.case_id,
            label=False,
            index=negative_index,
            candidate=negative_candidate,
            scan_label="VULNERABLE",
            taint_label="SAFE",
            authz_label="SAFE",
            scan_path="admin.py",
            taint_path="admin.py",
            authz_path="admin.py",
            rationale="delete operation is protected by require_permission",
        ),
    )


def _relative_reduction(
    baseline: float | None,
    current: float | None,
) -> float | None:
    if baseline is None or current is None or baseline == 0:
        return None
    return (baseline - current) / baseline


def run_agentic_scripted_eval() -> dict[str, object]:
    cases = _fixtures()
    labels: Mapping[str, bool] = {case.case_id: case.label for case in cases}
    systems = (
        AgentSystemVersion.E1_LOCAL_SINGLE,
        AgentSystemVersion.E3_GRAPH_SINGLE,
        AgentSystemVersion.E4_GRAPH_MULTI,
        AgentSystemVersion.E5_GRAPH_FAST,
    )
    results: dict[str, dict[str, object]] = {}
    for system in systems:
        predictions: dict[str, VerdictLabel] = {}
        traces: dict[str, dict[str, object]] = {}
        for case in cases:
            models = _case_models(case, system)
            tools = ToolRegistry(
                repository_tools(case.index),
                max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
            )
            verdict = AgenticPipeline(
                index=case.index,
                system=system,
                models=models,
                tools=tools,
            ).run(case.candidate)
            predictions[case.case_id] = verdict.label
            traces[case.case_id] = {
                "label": verdict.label,
                "confidence": verdict.confidence,
                "path": verdict.path,
                "votes": [
                    {
                        "expert": vote.expert,
                        "label": vote.label,
                        "validation_status": vote.validation_status,
                        "tool_calls": vote.tool_calls,
                    }
                    for vote in verdict.votes
                ],
                "planner_subtask_count": (
                    len(verdict.planner.plan.subtasks)
                    if verdict.planner is not None
                    else 0
                ),
                "model_calls": verdict.model_calls,
                "tool_calls": verdict.tool_calls,
                "context_token_count": verdict.context_token_count,
            }
        matrix = evaluate_ternary(labels, predictions)
        results[system.value] = {
            "predictions": predictions,
            "confusion": _matrix_payload(matrix),
            "traces": traces,
        }

    baseline_fpr = results[AgentSystemVersion.E3_GRAPH_SINGLE.value]["confusion"][
        "population_false_positive_rate"
    ]
    for system, result in results.items():
        current_fpr = result["confusion"]["population_false_positive_rate"]
        result["false_positive_delta_vs_graph_single_percentage_points"] = (
            None
            if baseline_fpr is None or current_fpr is None
            else 100.0 * (current_fpr - baseline_fpr)
        )
        result["relative_false_positive_reduction_vs_graph_single"] = (
            _relative_reduction(baseline_fpr, current_fpr)
        )

    return {
        "harness_id": FULL_SYSTEM_HARNESS.harness_id,
        "runtime_mode": "scripted",
        "claim_eligible": False,
        "dataset": "controlled-agentic-two-case-diagnostic",
        "purpose": (
            "Validate LangGraph/ReAct/quorum wiring and directional false-positive "
            "behavior only; not a reported benchmark result."
        ),
        "cases": [
            {
                "case_id": case.case_id,
                "label": "positive" if case.label else "negative",
                "rationale": case.rationale,
            }
            for case in cases
        ],
        "systems": results,
    }
