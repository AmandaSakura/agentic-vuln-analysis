"""Durable authorization limits for serial, preregistered live experiments.

These checks constrain execution and accounting. They do not alter detector
prompts, evidence admission, model transport or its full pytest gate.
"""
from __future__ import annotations

from collections.abc import Callable
import json
import os
from pathlib import Path
import subprocess
from typing import Any

from pydantic import Field

from cv_agent.domain.types import FrozenModel
from cv_agent.runtime.budget import Budget, BudgetExceeded
from cv_agent.runtime.journal import Journal


class ExperimentGuardPolicy(FrozenModel):
    expected_model_id: str = Field(min_length=1)
    cumulative_request_limit: int = Field(ge=1)
    cumulative_token_limit: int = Field(ge=1)
    output_token_limit: int = Field(ge=1)
    framing_token_allowance: int = Field(ge=1)


class ExperimentHardStop(BudgetExceeded):
    def __init__(self, code: str, reason: str):
        super().__init__(f"{code}: {reason}")
        self.code, self.reason = code, reason


def require_committed_clean(root: Path, expected_commit: str | None = None) -> str:
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root,
        capture_output=True, text=True, check=True, timeout=30).stdout.strip()
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=root, capture_output=True, text=True, check=True, timeout=30).stdout
    if status.strip():
        raise RuntimeError("Live experiments require a committed, clean working tree")
    if expected_commit is not None and commit != expected_commit:
        raise RuntimeError("Committed source changed during this experiment")
    return commit


def _write_ledger(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".writing")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class ExperimentGuard:
    """One durable ledger across phases, with one active serial cell at a time."""

    def __init__(self, *, root: Path, ledger_path: Path, phase_id: str,
                 phase_request_limit: int, run_id: str, journal: Journal,
                 policy: ExperimentGuardPolicy, preflight: Callable[[], str] | None = None):
        if not phase_id or not run_id or phase_request_limit < 1:
            raise ValueError("Experiment phase, run identity and request limit are required")
        self.root, self.ledger_path, self.phase_id = root, ledger_path, phase_id
        self.run_id, self.journal, self.policy = run_id, journal, policy
        self.preflight = preflight or (lambda: require_committed_clean(root))
        self.commit = self.preflight()
        self.cell_key: str | None = None
        self.fixed = False
        self.ledger = (json.loads(ledger_path.read_text()) if ledger_path.exists() else {
            "version": 1, "policy": policy.model_dump(mode="json"),
            "phases": {}, "requests": {}, "hard_stop": None,
        })
        if self.ledger.get("version") != 1 or self.ledger.get("policy") != policy.model_dump(mode="json"):
            raise ValueError("Authorization ledger policy differs from the declared experiment")
        self._check_stopped()
        phase = self.ledger["phases"].get(phase_id)
        if phase is None:
            self.ledger["phases"][phase_id] = {
                "request_limit": phase_request_limit, "run_id": run_id,
                "source_commit": self.commit, "cells": {},
            }
        elif phase["request_limit"] != phase_request_limit or phase["run_id"] != run_id:
            self._stop("S4", "A preregistered phase cannot be restarted with a different run or limit")
        self._save()

    @property
    def hard_stop(self) -> dict[str, Any] | None:
        return self.ledger["hard_stop"]

    @property
    def reported_tokens(self) -> int:
        return sum(request["reported_tokens"] or 0 for request in self.ledger["requests"].values())

    @property
    def accounted_tokens(self) -> int:
        return sum(request["accounted_tokens"] for request in self.ledger["requests"].values())

    def _save(self) -> None:
        _write_ledger(self.ledger_path, self.ledger)

    def _check_stopped(self) -> None:
        if self.hard_stop is not None:
            raise ExperimentHardStop(self.hard_stop["code"], self.hard_stop["reason"])

    def _stop(self, code: str, reason: str, **details: Any) -> None:
        if self.hard_stop is None:
            record = {"code": code, "reason": reason, "phase_id": self.phase_id,
                      "cell_key": self.cell_key, **details}
            self.ledger["hard_stop"] = record
            self._save()
            self.journal.write({"event": "experiment_hard_stop", **record})
        self._check_stopped()

    def bind_cell(self, cell_key: str, *, fixed: bool) -> None:
        self._check_stopped()
        phase = self.ledger["phases"][self.phase_id]
        if not cell_key or self.cell_key is not None:
            raise ValueError("A serial experiment requires one explicit active cell")
        if cell_key in phase["cells"]:
            self._stop("S4", "A preregistered cell cannot be executed again", repeated_cell=cell_key)
        self.cell_key, self.fixed = cell_key, fixed
        # Preparing a cell does not spend a model request. The started state is
        # written only when its first request is actually admitted.

    def finish_cell(self) -> None:
        if self.cell_key is None:
            raise ValueError("No active experiment cell")
        cells = self.ledger["phases"][self.phase_id]["cells"]
        if self.cell_key in cells:
            cells[self.cell_key]["status"] = "completed"
            self._save()
        self.cell_key, self.fixed = None, False

    def _token_reservation(self, event: dict[str, Any]) -> int:
        if not isinstance(event.get("messages"), list) or not isinstance(event.get("tools"), list):
            self._stop("S3", "Cannot reserve a request without its serialized messages and tool definitions")
        visible = json.dumps({"messages": event["messages"], "tools": event["tools"]},
                             ensure_ascii=True, sort_keys=True, allow_nan=False)
        # Reserve escaped serialized bytes, doubled for transport's nested
        # tool-argument string encoding, plus the configured output ceiling and
        # explicit framing allowance. This is a conservative byte-token bound,
        # not reported usage. Missing usage keeps the reservation in the ledger.
        return 2 * len(visible.encode("utf-8")) + self.policy.output_token_limit + self.policy.framing_token_allowance

    def before_request(self, event: dict[str, Any]) -> None:
        self._check_stopped()
        if event.get("event") != "model_start" or self.cell_key is None:
            raise ValueError("Request admission requires an active cell and a model_start event")
        try:
            commit = self.preflight()
        except (RuntimeError, subprocess.SubprocessError) as error:
            self._stop("S4", str(error), request_admitted=False)
        if commit != self.commit:
            self._stop("S4", "Committed source changed during this experiment", request_admitted=False)
        request_id = event.get("request_id")
        if not isinstance(request_id, str) or not request_id or request_id in self.ledger["requests"]:
            raise ValueError("Every request requires a new explicit request_id")
        requests = self.ledger["requests"]
        phase_requests = sum(request["phase_id"] == self.phase_id for request in requests.values())
        phase = self.ledger["phases"][self.phase_id]
        if phase_requests >= phase["request_limit"] or len(requests) >= self.policy.cumulative_request_limit:
            self._stop("S3", "The next request would exceed an authorized request ceiling", request_admitted=False)
        reservation = self._token_reservation(event)
        if self.accounted_tokens + reservation > self.policy.cumulative_token_limit:
            self._stop("S3", "The next request reservation would exceed the cumulative token ceiling",
                       request_admitted=False, next_token_reservation=reservation)
        phase["cells"].setdefault(self.cell_key, {"fixed": self.fixed, "status": "started"})
        requests[request_id] = {
            "phase_id": self.phase_id, "cell_key": self.cell_key,
            "source_commit": commit, "token_reservation": reservation,
            "accounted_tokens": reservation, "reported_tokens": None,
            "reported_usage": None, "reported_usage_history": [],
            "returned_model_id": None, "response_received": False,
        }
        self._save()

    def after_event(self, event: dict[str, Any]) -> None:
        """The caller writes the original event durably before this method."""
        kind = event.get("event")
        if self.hard_stop is not None and kind != "model_response_received":
            # Transport and trial cleanup must still record the original error
            # after a stop. Admission checks remain closed.
            return
        if kind == "model_http_error":
            request_id = event.get("request_id")
            if request_id in self.ledger["requests"]:
                self.ledger["requests"][request_id]["http_status"] = event.get("status_code")
                self._save()
        if kind == "model_response_received":
            request_id = event.get("request_id")
            if request_id not in self.ledger["requests"]:
                raise ValueError("Response has no admitted request")
            request = self.ledger["requests"][request_id]
            summary = event.get("summary", {})
            usage = summary.get("usage")
            if isinstance(usage, dict):
                total = usage.get("total_tokens")
                reported = total if type(total) is int and total >= 0 else None
                component_values = [usage.get("prompt_tokens", usage.get("input_tokens")),
                                    usage.get("completion_tokens", usage.get("output_tokens"))]
                components = (sum(component_values) if all(type(value) is int and value >= 0
                                                         for value in component_values) else None)
                conflict = request["reported_usage"] is not None and request["reported_usage"] != usage
                previous_reported = request["reported_tokens"]
                previous_accounted = request["accounted_tokens"]
                request["reported_usage_history"].append(usage)
                request["reported_usage"] = usage
                known_reported = [value for value in (previous_reported, reported) if value is not None]
                request["reported_tokens"] = max(known_reported) if known_reported else None
                accounted = [value for value in (reported, components) if value is not None]
                if accounted:
                    if reported is None:
                        request["accounted_tokens"] = max(request["token_reservation"], previous_accounted, *accounted)
                    else:
                        request["accounted_tokens"] = max([previous_accounted, *accounted]) if conflict else max(accounted)
                if conflict:
                    request["usage_conflict"] = True
                    self._save()
                    self._stop("S3", "Conflicting reported usage for one request", request_id=request_id)
            request["response_received"] = True
            request["returned_model_id"] = summary.get("model")
            self._save()
            if summary.get("model") != self.policy.expected_model_id:
                self._stop("S2", "Actual returned model ID is missing or differs from the declared model",
                           request_id=request_id, returned_model_id=summary.get("model"))
            if request["accounted_tokens"] > request["token_reservation"]:
                self._stop("S3", "Reported usage exceeded the conservative request reservation",
                           request_id=request_id)
            if self.accounted_tokens > self.policy.cumulative_token_limit:
                self._stop("S3", "Reported usage exceeded the cumulative token ceiling", request_id=request_id)
        elif self.fixed and kind == "tool_result":
            observation = event.get("observation", {})
            measured = observation.get("metadata", {}).get("witness_result_status")
            if observation.get("validation_status") == "CONFIRMED" or measured == "CONFIRMED":
                self._stop("S1", "A fixed-version cell produced a CONFIRMED observation",
                           tool=observation.get("tool"), citation_id=observation.get("citation_id"))
        elif self.fixed and kind == "trial_result":
            if event.get("result", {}).get("predicted_label") == "VULNERABLE":
                self._stop("S1", "A fixed-version cell produced a VULNERABLE verdict")


class GuardedExperimentBudget(Budget):
    """Run the guard before counting or logging an admitted model request."""

    def __init__(self, requests: int, seconds: int, guard: ExperimentGuard):
        super().__init__(requests, seconds)
        self.guard = guard

    def check(self):
        self.guard._check_stopped()
        try:
            super().check()
        except BudgetExceeded as error:
            self.guard._stop("S3", str(error), request_admitted=False)

    def observer(self, trial, role):
        def observe(event):
            if event["event"] == "model_start":
                self.check()
                self.guard.before_request(event)
                self.used += 1
            trial.record({"role": role, **event})

        return observe
