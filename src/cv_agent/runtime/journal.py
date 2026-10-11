"""Durable experiment events and model/tool request accounting."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import hashlib
from pathlib import Path
from threading import RLock

from cv_agent.tools.registry import ToolRegistry
from cv_agent.tools.validation import full_agent_tools


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def audit_journal(path: Path) -> dict:
    """Read durable events conservatively; never repair, refund or replay calls.

    A record without its terminating newline is uncommitted even if it happens
    to contain valid JSON. Corrupt records are retained as numbered hash-backed
    issues. Unknown usage is distinct from a reported zero.
    """
    issues = []
    starts = set()
    totals: dict[str, list[int]] = {}
    responses = set()

    def issue(number, raw, reason):
        issues.append({"line": number, "reason_code": reason,
                       "record_sha256": hashlib.sha256(raw).hexdigest()})

    for number, raw in enumerate(path.read_bytes().splitlines(keepends=True), 1):
        if not raw.endswith(b"\n"):
            issue(number, raw, "unterminated_record")
            continue
        try:
            record = json.loads(raw)
        except (ValueError, UnicodeError):
            issue(number, raw, "invalid_record")
            continue
        if not isinstance(record, dict) or not isinstance(record.get("event"), str):
            issue(number, raw, "invalid_event_schema")
            continue
        event = record["event"]
        if event not in {"model_start", "model_response_received"}:
            continue
        request = record.get("request_id")
        if not isinstance(request, str) or not request:
            issue(number, raw, "missing_request_identity")
            if event == "model_start":
                starts.add(f"unidentified/{number}")
            continue
        if event == "model_start":
            if request in starts:
                issue(number, raw, "duplicate_request_start")
            starts.add(request)
            continue
        responses.add(request)
        summary = record.get("summary")
        usage = summary.get("usage") if isinstance(summary, dict) else None
        total = usage.get("total_tokens") if isinstance(usage, dict) else None
        if total is None and isinstance(usage, dict):
            counts = [usage.get("prompt_tokens", usage.get("input_tokens")),
                      usage.get("completion_tokens", usage.get("output_tokens"))]
            if all(type(value) is int and value >= 0 for value in counts):
                total = sum(counts)
        if type(total) is int and total >= 0:
            previous = totals.setdefault(request, [])
            if previous and total not in previous:
                issue(number, raw, "conflicting_reported_usage")
            if total not in previous:
                previous.append(total)
    uncertain = sorted(request for request in starts if request not in totals or len(totals[request]) != 1)
    known = sum(max(values) for values in totals.values())
    return {"schema_version": "event-audit-v1", "requests_started": len(starts),
        "responses_received": len(responses), "uncertain_request_ids": uncertain,
        "known_reported_tokens": known, "reported_tokens": None if uncertain or issues else known,
        "reported_totals": totals, "issues": issues, "automatic_retry_allowed": False,
        "recovery_policy": "Manual reconciliation required; this audit never releases reservations or sends requests."}


class Journal:
    """Append and sync events before advancing to the next operation."""

    def __init__(self, path: Path):
        self.path = path

    def write(self, event):
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"time": utc_now(), **event}, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())


class LockedJournal(Journal):
    def __init__(self, path):
        super().__init__(path)
        self.lock = RLock()

    def write(self, event):
        with self.lock:
            super().write(event)


class Trial:
    def __init__(self, case_id, system, journal):
        self.case_id, self.system, self.journal = case_id, system, journal
        self.model_calls = 0
        self.tool_calls = 0

    def record(self, event):
        if event["event"] == "model_start":
            self.model_calls += 1
        elif event["event"] == "tool_start":
            self.tool_calls += 1
        self.journal.write({"case_id": self.case_id, "system": self.system, **event})

    def observe(self, role):
        return lambda event: self.record({"role": role, **event})


class RecordedTools(ToolRegistry):
    def __init__(self, index, trial, registered_tools=None):
        super().__init__(full_agent_tools(index) if registered_tools is None else registered_tools, max_output_bytes=8192)
        self.trial = trial

    def invoke(self, call, *, allowed, scope, citation_id=None):
        allowed = tuple(allowed)
        self.trial.record({
            "event": "tool_start", "call": call.model_dump(mode="json"),
            "allowed": list(allowed), "admitted_paths": sorted(scope.admitted_paths),
            "candidate_path": scope.candidate_path,
            "citation_id": citation_id,
        })
        try:
            observation = super().invoke(
                call, allowed=allowed, scope=scope, citation_id=citation_id)
        except BaseException as error:
            self.trial.record({"event": "tool_error", "error_type": type(error).__name__,
                               "error": str(error)})
            raise
        self.trial.record({"event": "tool_result",
                           "observation": observation.model_dump(mode="json")})
        return observation
