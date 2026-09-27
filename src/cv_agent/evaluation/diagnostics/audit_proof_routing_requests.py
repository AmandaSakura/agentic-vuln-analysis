"""Reconcile a saved comparison's requests and tool outcomes without model calls.

Usage: uv run --no-sync python -m cv_agent.evaluation.diagnostics.audit_proof_routing_requests RUN_DIR
Writes request_audit.json inside RUN_DIR. Prompts and model completions are excluded.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path


def _purpose(event: dict) -> str:
    messages = event.get("messages") or []
    if not messages or messages[-1].get("role") != "user":
        return "continuation"
    prompt = messages[-1].get("content") or ""
    if prompt.startswith("The previous final object failed"):
        return "schema_or_evidence_correction"
    if prompt.startswith("The tool-call budget is now closed"):
        return "observation_budget_finalization"
    if prompt.startswith("This is the final model step"):
        return "step_limit_finalization"
    if prompt.startswith("A material conclusion requires at least one successful"):
        return "no_successful_observation_correction"
    if prompt.startswith("Remaining tool-observation budget"):
        return "initial_task_request"
    if event.get("role") == "routing":
        return "routing_decision"
    if event.get("role") == "planner":
        return "planner_request"
    return "continuation"


def _task_ids(event: dict) -> tuple[str, ...]:
    for message in event.get("messages") or []:
        if message.get("role") != "user":
            continue
        content = message.get("content") or ""
        match = re.search(r"Assigned validation subtasks: (\[[^\n]*\])", content)
        if match:
            return tuple(task["task_id"] for task in json.loads(match.group(1)))
    return ()


def _tool_category(observation: dict) -> str:
    metadata = observation.get("metadata") or {}
    if metadata.get("budget_exhausted"):
        return "budget_rejected"
    content = observation.get("content") or ""
    if observation.get("status") == "blocked" and any(
        word in content.casefold() for word in ("repeat", "duplicate", "identical")
    ):
        return "repeat_rejected"
    if metadata.get("model_payload_suppressed"):
        return "suppressed"
    if metadata.get("observation_truncated"):
        return "truncated"
    if observation.get("status") == "ok":
        return "ok_untruncated"
    return "other_rejected"


def audit(run_dir: Path) -> dict:
    events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text().splitlines()]
    starts: dict[str, dict] = {}
    responses: dict[str, dict] = {}
    replies: dict[str, dict] = {}
    steps: Counter = Counter()
    for event in events:
        kind = event.get("event")
        request_id = event.get("request_id")
        if kind == "model_start":
            if request_id in starts:
                raise ValueError(f"Duplicate request ID: {request_id}")
            task_ids = _task_ids(event)
            key = (event["case_id"], event["system"], event["role"], task_ids)
            steps[key] += 1
            starts[request_id] = {
                "request_id": request_id,
                "case_id": event["case_id"],
                "system": event["system"],
                "role": event["role"],
                "task_ids": task_ids,
                "step": steps[key],
                "purpose": _purpose(event),
                "tool_outcomes": [],
            }
        elif kind == "model_response_received":
            responses[request_id] = event
        elif kind == "model_reply":
            replies[request_id] = event

    call_owner: dict[tuple[str, str, str], str] = {}
    for request_id, event in replies.items():
        for call in event["reply"].get("tool_calls") or []:
            key = (event["case_id"], event["system"], call["call_id"])
            if key in call_owner:
                raise ValueError(f"Repeated tool call ID: {key}")
            call_owner[key] = request_id

    tool_starts: dict[tuple[str, str, str], dict] = {}
    outcome_counts: Counter = Counter()
    outcome_status_counts: Counter = Counter()
    unattributed: list[dict] = []
    for event in events:
        kind = event.get("event")
        if kind == "tool_start":
            key = (event["case_id"], event["system"], event["citation_id"])
            tool_starts[key] = event
        elif kind == "tool_result":
            observation = event["observation"]
            key = (event["case_id"], event["system"], observation["citation_id"])
            start = tool_starts.pop(key)
            call = start["call"]
            category = _tool_category(observation)
            outcome_counts[category] += 1
            outcome_status_counts[(observation["status"], category)] += 1
            record = {"tool": call["name"], "category": category,
                      "status": observation["status"], "citation_id": key[2]}
            owner = call_owner.get((key[0], key[1], call["call_id"]))
            if owner:
                starts[owner]["tool_outcomes"].append(record)
            else:
                unattributed.append({"case_id": key[0], "system": key[1], **record})
    rows = list(starts.values())
    usage_mismatches = []
    for row in rows:
        request_id = row["request_id"]
        response = responses.get(request_id)
        reply = replies.get(request_id)
        row["response_received"] = response is not None
        row["parsed_reply"] = reply is not None
        usage = (response or {}).get("summary", {}).get("usage") or {}
        row["reported_usage"] = {
            "input_tokens": usage.get("input_tokens", usage.get("prompt_tokens")),
            "output_tokens": usage.get("output_tokens", usage.get("completion_tokens")),
            "total_tokens": usage.get("total_tokens"),
        }
        row["reported_usage_missing"] = row["reported_usage"]["total_tokens"] is None
        reply_usage = (reply or {}).get("reply", {}).get("usage") or {}
        if reply is not None and reply_usage and any(
            row["reported_usage"].get(name) != reply_usage.get(name)
            for name in ("input_tokens", "output_tokens", "total_tokens")
        ):
            usage_mismatches.append(request_id)
    totals = {name: sum(row["reported_usage"].get(name) or 0 for row in rows)
              for name in ("input_tokens", "output_tokens", "total_tokens")}
    by_cell: dict[str, Counter] = defaultdict(Counter)
    by_role: dict[str, Counter] = defaultdict(Counter)
    purposes = Counter()
    for row in rows:
        cell = f"{row['case_id']}/{row['system']}"
        by_cell[cell]["requests"] += 1
        by_role[row["role"]]["requests"] += 1
        purposes[row["purpose"]] += 1
        for group in (by_cell[cell], by_role[row["role"]]):
            group["tokens"] += row["reported_usage"].get("total_tokens") or 0
            group[f"purpose:{row['purpose']}"] += 1
            for outcome in row["tool_outcomes"]:
                group[f"tool:{outcome['category']}"] += 1
    result = {
        "run_directory": str(run_dir),
        "request_count": len(rows),
        "response_count": len(responses),
        "parsed_reply_count": len(replies),
        "missing_response_ids": sorted(set(starts) - set(responses)),
        "missing_parsed_reply_ids": sorted(set(starts) - set(replies)),
        "response_reply_usage_mismatch_ids": usage_mismatches,
        "reported_tokens": totals,
        "requests_missing_reported_usage": sum(row["reported_usage_missing"] for row in rows),
        "tool_result_count": sum(outcome_counts.values()),
        "tool_outcomes": dict(outcome_counts),
        "tool_outcomes_by_status": [
            {"status": status, "category": category, "count": count}
            for (status, category), count in sorted(outcome_status_counts.items())
        ],
        "internal_tools_without_model_request": unattributed,
        "unpaired_tool_starts": [
            {"case_id": key[0], "system": key[1], "citation_id": key[2]}
            for key in sorted(tool_starts)
        ],
        "request_purposes": dict(purposes),
        "model_requests_by_role": {
            role: count["requests"] for role, count in by_role.items()
        },
        "by_cell": {key: dict(value) for key, value in by_cell.items()},
        "by_role": {key: dict(value) for key, value in by_role.items()},
        "requests": rows,
    }
    return result


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: audit_proof_routing_requests RUN_DIR")
    directory = Path(sys.argv[1]).resolve()
    result = audit(directory)
    (directory / "request_audit.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in (
        "request_count", "response_count", "parsed_reply_count",
        "missing_response_ids", "missing_parsed_reply_ids",
        "response_reply_usage_mismatch_ids", "reported_tokens", "tool_result_count",
        "requests_missing_reported_usage", "tool_outcomes",
        "tool_outcomes_by_status", "model_requests_by_role", "request_purposes")}, indent=2))
