"""Audit recorded model requests, scenario proposals and factual failure causes."""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime
import json
from pathlib import Path
from typing import Any

from cv_agent.evaluation.metrics import provider_usage


WITNESS = "run_bounded_execution_witness"
_INFRASTRUCTURE_GAPS = frozenset({
    "worker_timeout", "worker_launch_error", "worker_result_too_large",
    "isolation_selftest_failed", "bash_replay_timeout", "bash_replay_timeout_after_output",
    "bash_replay_output_too_large",
})


def _cell(event: dict[str, Any]) -> tuple[str, str, str]:
    return (event.get("evaluation_case_id", event.get("case_id", "")),
            event.get("scenario_origin", ""), event.get("system", ""))


def _payload(observation: dict[str, Any]) -> dict[str, Any] | None:
    try:
        parsed = json.loads(observation.get("content", ""))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _elapsed(start: dict[str, Any], end: dict[str, Any]) -> float | None:
    if not start.get("time") or not end.get("time"):
        return None
    return (datetime.fromisoformat(end["time"]) - datetime.fromisoformat(start["time"])).total_seconds()


def failure_diagnostics(row: dict[str, Any], timeline: list[dict[str, Any]]) -> dict[str, Any]:
    witnesses = [item for item in timeline if item["tool"] == WITNESS]
    confirmed = any(item["observation"].get("status") == "ok"
                    and item["observation"].get("validation_status") == "CONFIRMED"
                    for item in witnesses)
    producer_confirmed = any(item["observation"].get("metadata", {}).get("witness_result_status") == "CONFIRMED"
                             for item in witnesses)
    success = confirmed and row.get("predicted_label") == "VULNERABLE"
    if row.get("status") == "not_run" and not row.get("error") and not timeline:
        return {"qualified_success": False, "primary": None, "contributors": [],
                "witness_tool_calls": 0, "executed_witness_attempts": 0,
                "schema_rejections": 0, "gaps": [], "infrastructure_gaps": [],
                "note": "This cell was not executed; no failure category is assigned."}
    schema_rejections = sum(item["schema_rejected"] for item in witnesses)
    gaps = list(dict.fromkeys(gap for item in witnesses
                             for gap in (item.get("payload") or {}).get("gaps", [])))
    infrastructure = [gap for gap in gaps if gap in _INFRASTRUCTURE_GAPS
                      or gap.startswith(("isolation_read_denied:", "isolation_read_grant_stale:"))]
    runtime_unresolved = sum(
        item["observation"].get("metadata", {}).get("witness_attempted") is True
        and (item["observation"].get("validation_status") == "UNRESOLVED"
             or item["observation"].get("metadata", {}).get("witness_result_status") == "UNRESOLVED")
        for item in witnesses)
    preparation_responses = sum(item["observation"].get("status") == "ok"
        and item["observation"].get("metadata", {}).get("witness_attempted") is False
        for item in witnesses)
    attempted = sum(item["observation"].get("metadata", {}).get("witness_attempted") is True
                    for item in witnesses)
    error = row.get("error", "") or ""
    votes = (row.get("verdict") or {}).get("votes", [])
    exhausted = (error.startswith("S3:") or "model-step budget" in error
                 or any(item["observation"].get("metadata", {}).get("budget_exhausted") for item in timeline)
                 or any("budget exhaust" in vote.get("rationale", "").casefold() for vote in votes))
    contributors = []
    if not success:
        if confirmed or producer_confirmed:
            contributors.append("F5")
        if infrastructure:
            contributors.append("F4")
        if schema_rejections >= 2:
            contributors.append("F2")
        if runtime_unresolved and not infrastructure:
            contributors.append("F3")
        if not attempted:
            contributors.append("F1")
        if exhausted:
            contributors.append("F6")
    primary = contributors[0] if contributors else None
    if error.startswith("S3:") and "F6" in contributors:
        primary = "F6"
    return {
        "qualified_success": success, "primary": primary, "contributors": contributors,
        "delivered_confirmation": confirmed, "producer_confirmation": producer_confirmed,
        "witness_tool_calls": len(witnesses), "executed_witness_attempts": attempted,
        "preparation_responses": preparation_responses,
        "runtime_unresolved_observations": runtime_unresolved,
        "schema_rejections": schema_rejections, "gaps": gaps,
        "infrastructure_gaps": infrastructure,
        "note": "Failure codes summarize recorded facts and can overlap. "
                "Accepting scenario preparation does not establish runtime scenario failure. "
                "Unsupported or wrong premises are not classified as resource failures. "
                "The phase report must review these facts before authorizing a repair.",
    }


def audit_events(events: list[dict[str, Any]], results: list[dict[str, Any]]) -> dict[str, Any]:
    requests: dict[str, dict[str, Any]] = {}
    declared_calls = []
    pending_tools: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    timeline = []
    proposals = []
    unowned_tools = []
    for index, event in enumerate(events):
        kind = event.get("event")
        request_id = event.get("request_id")
        cell = _cell(event)
        if kind == "model_start":
            if not request_id or request_id in requests:
                raise ValueError("Request audit requires unique explicit request IDs")
            requests[request_id] = {
                "request_id": request_id, "evaluation_case_id": cell[0],
                "scenario_origin": cell[1], "system": cell[2], "role": event.get("role"),
                "start_event_index": index, "start_time": event.get("time"),
                "response_received": False, "parsed_reply": False, "invalid_response": False,
                "returned_model_ids": [], "reported_usage": [], "response_metadata": [],
                "errors": [], "tool_outcomes": [],
            }
        elif kind in {"model_response_received", "model_reply", "model_invalid_response", "model_error"}:
            if request_id not in requests:
                continue
            request = requests[request_id]
            if kind == "model_response_received":
                summary = event.get("summary", {})
                request["response_received"] = True
                request["response_metadata"].append(summary)
                if isinstance(summary.get("usage"), dict):
                    request["reported_usage"].append(summary["usage"])
                if summary.get("model") is not None:
                    request["returned_model_ids"].append(summary["model"])
            elif kind == "model_reply":
                request["parsed_reply"] = True
                reply = event["reply"]
                request["parsed_reply_metadata"] = {key: reply.get(key) for key in ("model_id", "usage")}
                for ordinal, call in enumerate(reply.get("tool_calls", [])):
                    declared_calls.append({"cell": cell, "role": event.get("role"),
                                           "request_id": request_id, "ordinal": ordinal,
                                           "call": call, "executed": False})
            elif kind == "model_invalid_response":
                request["invalid_response"] = True
            else:
                request["errors"].append({"error_type": event.get("error_type"), "error": event.get("error")})
        elif kind == "tool_start":
            call = event["call"]
            owner = next((declared for declared in reversed(declared_calls)
                          if declared["cell"] == cell and not declared["executed"]
                          and (event.get("role") is None or declared["role"] == event.get("role"))
                          and declared["call"] == call), None)
            if owner is not None:
                owner["executed"] = True
            start = {"event": event, "event_index": index,
                     "request_id": owner["request_id"] if owner else None,
                     "role": owner["role"] if owner else event.get("role")}
            pending_tools[(cell, event.get("citation_id"))].append(start)
            if call["name"] == WITNESS and "scenario_hypothesis" in call.get("arguments", {}):
                proposals.append({"evaluation_case_id": cell[0], "scenario_origin": cell[1],
                                  "request_id": start["request_id"], "event_index": index,
                                  "scenario_hypothesis": call["arguments"]["scenario_hypothesis"]})
        elif kind == "tool_result":
            observation = event["observation"]
            starts = pending_tools[(cell, observation.get("citation_id"))]
            start = starts.pop(0) if starts else None
            item = {
                "evaluation_case_id": cell[0], "scenario_origin": cell[1], "system": cell[2],
                "tool": observation["tool"], "request_id": start["request_id"] if start else None,
                "role": start["role"] if start else event.get("role"),
                "start_event_index": start["event_index"] if start else None,
                "result_event_index": index, "elapsed_seconds": _elapsed(start["event"], event) if start else None,
                "call": start["event"]["call"] if start else None,
                "observation": observation, "payload": _payload(observation),
                "schema_rejected": observation.get("status") == "error"
                                   and observation.get("content", "").startswith("invalid tool arguments:"),
            }
            timeline.append(item)
            if item["request_id"] in requests:
                requests[item["request_id"]]["tool_outcomes"].append(item)
            else:
                unowned_tools.append(item)
    by_cell = {}
    cells = list(dict.fromkeys([*(_cell(event) for event in events if event.get("evaluation_case_id")),
                               *(_cell(row) for row in results)]))
    for cell in cells:
        cell_events = [event for event in events if _cell(event) == cell]
        cell_timeline = [item for item in timeline if _cell(item) == cell]
        row = next((row for row in results if _cell(row) == cell), None)
        by_cell[json.dumps(cell)] = {
            "evaluation_case_id": cell[0], "scenario_origin": cell[1], "system": cell[2],
            "usage": provider_usage(cell_events), "tool_sequence": [item["tool"] for item in cell_timeline],
            "witness_attempts": sum(item["tool"] == WITNESS
                                    and item["observation"].get("metadata", {}).get("witness_attempted") is True
                                    for item in cell_timeline),
            "witness_elapsed_seconds": sum(item["elapsed_seconds"] or 0 for item in cell_timeline if item["tool"] == WITNESS),
            "witness_elapsed_missing": sum(item["elapsed_seconds"] is None for item in cell_timeline if item["tool"] == WITNESS),
            "cell_elapsed_seconds": row.get("latency_sec") if row else None,
            "failure_diagnostics": failure_diagnostics(row, cell_timeline) if row else None,
        }
    usage = provider_usage(events)
    return {
        "dataset_role": "development", "claim_eligible": False,
        "request_count": len(requests), "reported_total_tokens": usage["reported_total_tokens"],
        "usage": usage, "requests": list(requests.values()), "by_cell": by_cell,
        "scenario_proposals": proposals, "tool_timeline": timeline,
        "unattributed_tools": unowned_tools,
        "unpaired_tool_starts": [start for starts in pending_tools.values() for start in starts],
        "hard_stops": [event for event in events if event.get("event") == "experiment_hard_stop"],
    }


def audit(run_directory: Path) -> dict[str, Any]:
    events = [json.loads(line) for line in (run_directory / "events.jsonl").read_text().splitlines()]
    return audit_events(events, json.loads((run_directory / "results.json").read_text()))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    args = parser.parse_args()
    result = audit(args.run_directory)
    with (args.run_directory / "request_audit.json").open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({key: result[key] for key in ("request_count", "reported_total_tokens", "usage")}, indent=2))


if __name__ == "__main__":
    main()
