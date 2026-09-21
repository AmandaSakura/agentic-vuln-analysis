"""Durable experiment events and model/tool request accounting."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from threading import RLock

from cv_agent.tools.registry import ToolRegistry
from cv_agent.tools.validation import full_agent_tools


def utc_now():
    return datetime.now(timezone.utc).isoformat()


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
