"""Live experiment authorization guards are exercised with offline events."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from cv_agent.evaluation.experiment_guard import (
    ExperimentGuard, ExperimentHardStop, ExperimentGuardPolicy, require_committed_clean,
)
from cv_agent.runtime.journal import Journal


def _policy(**updates):
    return ExperimentGuardPolicy(expected_model_id="test-model", cumulative_request_limit=8,
        cumulative_token_limit=20_000, output_token_limit=20, framing_token_allowance=50,
        **updates)


def _guard(root, *, phase="phase-one", cap=4, policy=None, preflight=None):
    journal = Journal(root / "events.jsonl")
    return ExperimentGuard(root=root, ledger_path=root / "ledger.json", phase_id=phase,
        phase_request_limit=cap, run_id=phase + "-run", journal=journal,
        policy=policy or _policy(), preflight=preflight or (lambda: "c" * 40))


def _start(request_id="one", **updates):
    return {"event": "model_start", "request_id": request_id,
            "messages": [{"role": "user", "content": "Observe the supplied source."}],
            "tools": [], **updates}


def _response(request_id="one", *, model="test-model", usage=None):
    return {"event": "model_response_received", "request_id": request_id,
            "summary": {"model": model, "usage": usage or {"total_tokens": 5}},
            "raw_response": {"model": model, "usage": usage or {"total_tokens": 5}, "choices": []}}


def _record(guard, event):
    guard.journal.write(event)
    guard.after_event(event)


def test_pre_request_dirty_source_stops_before_admission(tmp_path):
    state = {"clean": True}

    def preflight():
        if not state["clean"]:
            raise RuntimeError("working tree is dirty")
        return "c" * 40

    guard = _guard(tmp_path, preflight=preflight)
    guard.bind_cell("one", fixed=False)
    state["clean"] = False
    with pytest.raises(ExperimentHardStop, match="S4"):
        guard.before_request(_start())
    assert guard.ledger["requests"] == {}
    assert "experiment_hard_stop" in (tmp_path / "events.jsonl").read_text()
    assert '"event": "model_start"' not in (tmp_path / "events.jsonl").read_text()


def test_raw_model_mismatch_keeps_usage_before_exact_id_stop(tmp_path):
    guard = _guard(tmp_path)
    guard.bind_cell("one", fixed=False)
    event = _start()
    guard.before_request(event)
    _record(guard, event)
    with pytest.raises(ExperimentHardStop, match="S2"):
        _record(guard, _response(model="different-model", usage={"prompt_tokens": 11, "total_tokens": 15}))
    saved = json.loads((tmp_path / "ledger.json").read_text())
    assert saved["requests"]["one"]["reported_usage"] == {"prompt_tokens": 11, "total_tokens": 15}
    assert guard.reported_tokens == 15
    assert guard.hard_stop["code"] == "S2"
    lines = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert lines[-2]["event"] == "model_response_received"
    assert lines[-1]["event"] == "experiment_hard_stop"
    with pytest.raises(ExperimentHardStop, match="S2"):
        guard.before_request(_start("two"))
    assert len(guard.ledger["requests"]) == 1


def test_missing_raw_model_id_cannot_use_requested_model_fallback(tmp_path):
    guard = _guard(tmp_path)
    guard.bind_cell("one", fixed=False)
    guard.before_request(_start())
    with pytest.raises(ExperimentHardStop, match="S2"):
        _record(guard, {"event": "model_response_received", "request_id": "one",
                        "summary": {"usage": {"total_tokens": 7}}})
    assert guard.reported_tokens == 7


@pytest.mark.parametrize("event", [
    {"event": "tool_result", "observation": {"tool": "validator", "status": "ok",
                                              "validation_status": "CONFIRMED", "metadata": {}}},
    {"event": "trial_result", "result": {"predicted_label": "VULNERABLE", "status": "completed"}},
])
def test_fixed_confirmation_or_material_verdict_immediately_stops(tmp_path, event):
    guard = _guard(tmp_path)
    guard.bind_cell("fixed-cell", fixed=True)
    with pytest.raises(ExperimentHardStop, match="S1"):
        _record(guard, event)
    assert json.loads((tmp_path / "ledger.json").read_text())["hard_stop"]["code"] == "S1"
    with pytest.raises(ExperimentHardStop, match="S1"):
        guard.before_request(_start())
    assert not guard.ledger["requests"]


def test_positive_cell_confirmation_and_fixed_unresolved_are_allowed(tmp_path):
    guard = _guard(tmp_path)
    guard.bind_cell("positive", fixed=False)
    _record(guard, {"event": "tool_result", "observation": {"validation_status": "CONFIRMED"}})
    guard.finish_cell()
    guard.bind_cell("fixed", fixed=True)
    _record(guard, {"event": "tool_result", "observation": {"validation_status": "UNRESOLVED"}})
    _record(guard, {"event": "trial_result", "result": {"predicted_label": "ABSTAIN"}})
    assert guard.hard_stop is None


def test_per_phase_cap_and_cumulative_caps_survive_restart(tmp_path):
    first = _guard(tmp_path, cap=4)
    first.bind_cell("one", fixed=False)
    for number in range(4):
        event = _start(str(number))
        first.before_request(event)
        _record(first, event)
        _record(first, _response(str(number)))
    first.finish_cell()
    second = _guard(tmp_path, phase="phase-two", cap=4)
    second.bind_cell("two", fixed=False)
    for number in range(4, 8):
        event = _start(str(number))
        second.before_request(event)
        _record(second, event)
        _record(second, _response(str(number)))
    with pytest.raises(ExperimentHardStop, match="S3"):
        second.before_request(_start("ninth"))
    assert len(second.ledger["requests"]) == 8
    assert second.reported_tokens == 40


def test_phase_request_cap_does_not_consume_a_rejected_request(tmp_path):
    guard = _guard(tmp_path, cap=1)
    guard.bind_cell("one", fixed=False)
    guard.before_request(_start())
    _record(guard, _response())
    with pytest.raises(ExperimentHardStop, match="S3"):
        guard.before_request(_start("two"))
    assert set(guard.ledger["requests"]) == {"one"}


def test_token_reservation_rejects_imminent_overshoot_before_a_request(tmp_path):
    policy = ExperimentGuardPolicy(expected_model_id="test-model", cumulative_request_limit=8,
        cumulative_token_limit=200, output_token_limit=20, framing_token_allowance=50)
    guard = _guard(tmp_path, policy=policy)
    guard.bind_cell("one", fixed=False)
    with pytest.raises(ExperimentHardStop, match="S3"):
        guard.before_request(_start(messages=[{"role": "user", "content": "a" * 1000}]))
    assert not guard.ledger["requests"]


def test_reported_usage_refunds_reservation_once_and_parse_failure_keeps_usage(tmp_path):
    guard = _guard(tmp_path)
    guard.bind_cell("one", fixed=False)
    guard.before_request(_start())
    reserved = guard.accounted_tokens
    response = _response(usage={"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5,
                                "prompt_cache_hit_tokens": 1})
    _record(guard, response)
    _record(guard, response)
    _record(guard, {"event": "model_invalid_response", "request_id": "one"})
    assert reserved > guard.accounted_tokens == guard.reported_tokens == 5
    assert guard.ledger["requests"]["one"]["reported_usage"]["prompt_cache_hit_tokens"] == 1


def test_missing_usage_reservation_is_retained_and_known_model_is_allowed(tmp_path):
    guard = _guard(tmp_path)
    guard.bind_cell("one", fixed=False)
    guard.before_request(_start())
    reserved = guard.accounted_tokens
    _record(guard, {"event": "model_response_received", "request_id": "one",
                    "summary": {"model": "test-model"}})
    assert guard.reported_tokens == 0
    assert guard.accounted_tokens == reserved
    assert guard.ledger["requests"]["one"]["reported_tokens"] is None


def test_conflicting_usage_is_accounted_and_preserved_before_stop(tmp_path):
    guard = _guard(tmp_path)
    guard.bind_cell("one", fixed=False)
    guard.before_request(_start())
    _record(guard, _response(usage={"total_tokens": 5}))
    with pytest.raises(ExperimentHardStop, match="S3"):
        _record(guard, _response(usage={"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}))
    assert guard.accounted_tokens == guard.reported_tokens == 20
    saved = json.loads((tmp_path / "ledger.json").read_text())["requests"]["one"]
    assert saved["reported_usage_history"] == [{"total_tokens": 5},
        {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}]


def test_http_error_usage_without_model_stops_as_unverified_identity(tmp_path):
    guard = _guard(tmp_path)
    guard.bind_cell("one", fixed=False)
    guard.before_request(_start())
    _record(guard, {"event": "model_http_error", "request_id": "one", "status_code": 429})
    with pytest.raises(ExperimentHardStop, match="S2"):
        _record(guard, {"event": "model_response_received", "request_id": "one",
                        "summary": {"error": {"message": "rate limit"}, "usage": {"total_tokens": 5}}})
    assert guard.hard_stop["code"] == "S2"
    assert guard.reported_tokens == 5


@pytest.mark.parametrize("total", [None, "invalid"])
def test_missing_or_invalid_total_keeps_reservation_despite_reported_components(tmp_path, total):
    guard = _guard(tmp_path)
    guard.bind_cell("one", fixed=False)
    guard.before_request(_start())
    reservation = guard.accounted_tokens
    _record(guard, _response(usage={"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": total}))
    assert guard.reported_tokens == 0
    assert guard.accounted_tokens == reservation
    assert guard.ledger["requests"]["one"]["reported_usage"]["prompt_tokens"] == 2


def test_same_cell_cannot_be_reexecuted_in_a_new_run(tmp_path):
    guard = _guard(tmp_path)
    guard.bind_cell("one", fixed=False)
    guard.before_request(_start())
    _record(guard, _response())
    guard.finish_cell()
    replacement = _guard(tmp_path)
    with pytest.raises(ExperimentHardStop, match="S4"):
        replacement.bind_cell("one", fixed=False)
    assert len(replacement.ledger["requests"]) == 1


def test_real_git_preflight_requires_a_commit_and_clean_tree(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Offline Test"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "offline@example.invalid"], cwd=tmp_path, check=True)
    (tmp_path / "source.py").write_text("pass\n")
    subprocess.run(["git", "add", "source.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "fixture"], cwd=tmp_path, check=True, capture_output=True)
    commit = require_committed_clean(tmp_path)
    assert len(commit) == 40
    (tmp_path / "source.py").write_text("value = 1\n")
    with pytest.raises(RuntimeError, match="clean"):
        require_committed_clean(tmp_path, commit)


@pytest.mark.parametrize("quoted,measured", [(False, "CONFIRMED"), (True, "UNRESOLVED")])
def test_producer_status_survives_truncation_for_stop_without_becoming_proof(tmp_path, quoted, measured):
    from cv_agent.tools.registry import ToolRegistry
    from cv_agent.tools.validation.registry import full_agent_tools
    from test_bounded_witness_tool import _inputs, _call, _conclude

    index, candidate, context, _ = _inputs(tmp_path / "repo", quoted=quoted)
    tools = ToolRegistry(full_agent_tools(index, witness_contexts={candidate.repository_id: context}),
                         max_output_bytes=256)
    call, observation, scope = _call(tools, index, candidate)
    assert observation.metadata["observation_truncated"] is True
    assert observation.validation_status is None
    assert observation.fixture_proof is None
    assert observation.metadata["witness_result_status"] == measured
    assert "witness_result_status" not in tools.prompt_payload(observation)
    with pytest.raises(ValueError):
        _conclude(call, observation, scope.subject)

    guard = _guard(tmp_path)
    guard.bind_cell("fixed", fixed=True)
    event = {"event": "tool_result", "observation": observation.model_dump(mode="json")}
    if measured == "CONFIRMED":
        with pytest.raises(ExperimentHardStop, match="S1"):
            _record(guard, event)
        assert guard.hard_stop["code"] == "S1"
    else:
        _record(guard, event)
        assert guard.hard_stop is None
