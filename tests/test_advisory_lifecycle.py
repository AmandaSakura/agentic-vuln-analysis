"""Advisory execution and review retain their observable experiment protocol."""
import copy
import importlib
import json
import signal
from types import SimpleNamespace

import pytest

from cv_agent.evaluation.datasets.advisory_config import (
    PythonHeldoutPairExperimentConfig,
    planned_heldout_cells,
)
from test_python_heldout_pair_config import config_dict


def selected_config():
    data = config_dict()
    data["selected_cells"] = [
        {"case_id": "hp001_a", "system": "E1"},
        {"case_id": "hp001_b", "system": "E1"},
    ]
    return PythonHeldoutPairExperimentConfig.model_validate(data)


def planned_rows(config):
    return [
        dict(case_id=case.case_id, system=system.value, pair_id=pair.pair_id,
             revision_role=case.revision_role, status="completed",
             predicted_label="VULNERABLE" if case.revision_role == "vulnerable" else "SAFE",
             model_calls=1, tool_calls=0, latency_sec=0.1, verdict=None)
        for pair, case, system in planned_heldout_cells(config)
    ]


def test_categorized_issues_preserve_original_interleaved_order():
    from cv_agent.evaluation.protocols.advisory import (
        heldout_pair_acceptance_issues,
        review_heldout_pair_rows,
    )

    config = selected_config()
    rows = planned_rows(config)
    rows[0]["predicted_label"] = "SAFE"
    rows[1].update(pair_id="wrong", status="failed", predicted_label=None)
    expected = [
        "hp001_a E1 predicted SAFE expected VULNERABLE",
        "Result metadata mismatch for hp001_b E1",
        "hp001_b E1 did not complete: failed",
        "No model requests were recorded",
    ]
    review = review_heldout_pair_rows(rows, {"requests": 0}, config)

    assert heldout_pair_acceptance_issues(rows, {"requests": 0}, config) == expected
    assert review["legacy_issues"] == expected
    assert review["legacy_passed"] is False
    assert review["detection_quality_issues"] == expected[:1]
    assert review["run_integrity_issues"] == expected[1:]


def test_unexpected_abstention_is_quality_and_expected_abstention_stays_accepted():
    from cv_agent.evaluation.protocols.advisory import review_heldout_pair_rows

    config = selected_config()
    rows = planned_rows(config)
    rows[0].update(status="abstained", predicted_label="ABSTAIN")
    review = review_heldout_pair_rows(rows, {"requests": 2}, config)
    assert review["run_integrity_issues"] == []
    assert review["detection_quality_issues"] == ["hp001_a E1 did not complete: abstained"]
    data = config.model_dump(mode="json", by_alias=True)
    data["expected_abstentions"] = [{"case_id": "hp001_a", "system": "E1"}]
    accepted = review_heldout_pair_rows(
        rows, {"requests": 2}, PythonHeldoutPairExperimentConfig.model_validate(data),
    )
    assert accepted["legacy_passed"] is True
    assert accepted["legacy_issues"] == []


def test_pure_advisory_summary_does_not_mutate_or_write(tmp_path, monkeypatch):
    from cv_agent.evaluation.results import build_heldout_summary

    config = selected_config()
    rows = planned_rows(config)
    rows.append({**rows[0], "status": "failed", "predicted_label": None})
    rows.append({**rows[0], "case_id": "unexpected"})
    usage = {"requests": 4}
    before = copy.deepcopy((rows, usage))
    monkeypatch.chdir(tmp_path)

    summary = build_heldout_summary(config, rows, usage)

    assert summary["systems"]["E1"]["total"] == 2
    assert summary["systems"]["E1"]["failed"] == 1
    assert summary["duplicate_cells"] == [{"case_id": "hp001_a", "system": "E1", "rows": 2}]
    assert summary["unexpected_rows"][0]["case_id"] == "unexpected"
    assert (rows, usage) == before
    assert list(tmp_path.iterdir()) == []


def configure_lifecycle(tmp_path, monkeypatch, config):
    from cv_agent.evaluation import lifecycle

    manifest_path = tmp_path / config.source_manifest
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text('{"summary":{"pairs":1}}')
    monkeypatch.setattr(lifecycle, "require_passing_tests", lambda: None)
    monkeypatch.setattr(lifecycle, "load_experiment_model", lambda *_: ({"model": "offline"}, "offline-key"))
    monkeypatch.setattr(lifecycle, "source_fingerprint", lambda *_: "offline-fingerprint")
    monkeypatch.setattr(lifecycle, "snapshot_sources", lambda root, output: {})
    tasks = [
        (pair.pair_id, case.revision_role, None, SimpleNamespace(case_id=case.case_id), (), system)
        for pair, case, system in planned_heldout_cells(config)
    ]
    return lifecycle, lambda *_: (tasks, {}, {})


@pytest.mark.parametrize("first_status", ["failed", "abstained"])
@pytest.mark.parametrize("latest_pointer", [None, "artifacts/gate_pointer.json"])
def test_shared_lifecycle_continues_and_preserves_legacy_decision(tmp_path, monkeypatch, first_status, latest_pointer):
    config = selected_config()
    lifecycle, prepare = configure_lifecycle(tmp_path, monkeypatch, config)
    rows = planned_rows(config)
    rows[0].update(status=first_status, predicted_label="ABSTAIN" if first_status == "abstained" else None)
    observed = []

    def execute(index, candidate, system, journal, budget, **kwargs):
        assert kwargs["api_key"] == "offline-key"
        observed.append(candidate.case_id)
        return dict(rows[len(observed) - 1])

    output = lifecycle.run_advisory_experiment(
        tmp_path, tmp_path / "run", config, run_root="artifacts/unused",
        latest_pointer=latest_pointer, prepare=prepare, execute=execute,
    )
    assert observed == ["hp001_a", "hp001_b"]
    saved = json.loads((output / "results.json").read_text())
    assert [row["status"] for row in saved] == [first_status, "completed"]
    decision = json.loads((output / "acceptance.json").read_text())
    assert decision == {
        "passed": False,
        "issues": [f"hp001_a E1 did not complete: {first_status}", "No model requests were recorded"],
        "automatic_expansion": False,
    }
    if latest_pointer is not None:
        assert json.loads((tmp_path / latest_pointer).read_text()) == {"run_directory": "run"}
    assert "offline-key" not in (output / "metadata.json").read_text()


@pytest.mark.parametrize("exception", [KeyboardInterrupt, RuntimeError])
def test_shared_lifecycle_finalizes_and_restores_signal_before_propagating(tmp_path, monkeypatch, exception):
    config = selected_config()
    lifecycle, prepare = configure_lifecycle(tmp_path, monkeypatch, config)
    rows = planned_rows(config)
    previous_handler = signal.getsignal(signal.SIGTERM)
    calls = []

    def execute(index, candidate, system, journal, budget, **kwargs):
        calls.append(candidate.case_id)
        request_id = str(len(calls))
        journal.write({"event": "model_start", "request_id": request_id})
        journal.write({"event": "model_response_received", "request_id": request_id,
                       "summary": {"usage": {"total_tokens": 100}}})
        journal.write({"event": "model_reply", "request_id": request_id,
                       "reply": {"model_id": "offline", "usage": {"total_tokens": 100}}})
        if len(calls) == 2:
            raise exception("offline interruption")
        return rows[0]

    output = tmp_path / "run"
    with pytest.raises(exception, match="offline interruption"):
        lifecycle.run_advisory_experiment(
            tmp_path, output, config, run_root="artifacts/unused", prepare=prepare, execute=execute,
        )
    assert signal.getsignal(signal.SIGTERM) == previous_handler
    saved = json.loads((output / "results.json").read_text())
    assert [row["status"] for row in saved] == ["completed", "not_run"]
    decision = json.loads((output / "acceptance.json").read_text())
    assert decision["passed"] is False
    assert "Experiment interrupted" in decision["issues"]
    events = [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
    assert events[-1]["event"] == "run_end"
    assert events[-1]["interrupted"] is True
    usage = json.loads((output / "usage.json").read_text())
    assert usage["requests"] == 2
    assert usage["reported_total_tokens"] == 200


@pytest.mark.parametrize("name, run_root, pointer", [
    ("gate", "artifacts/python_heldout_pair_gate_v4",
     "artifacts/python_heldout_pair_gate_v4.json"),
    ("matrix", "artifacts/python_heldout_pair_matrix_v4", None),
])
def test_entrypoints_select_their_composed_configuration_and_destinations(
    tmp_path, monkeypatch, name, run_root, pointer,
):
    runner = importlib.import_module(f"cv_agent.evaluation.runners.run_python_heldout_pair_{name}")
    config = selected_config()
    from advisory_config_fixtures import write_advisory_config
    write_advisory_config(tmp_path, config.model_dump(mode="json", by_alias=True), name)
    calls = []
    output = tmp_path / "requested-output"

    def lifecycle(root, target, resolved_config, **kwargs):
        calls.append((root, target, resolved_config, kwargs))
        return target

    monkeypatch.setattr(runner, "run_advisory_experiment", lifecycle)
    assert runner.run(root=tmp_path, output=output) == output
    assert calls == [(tmp_path, output, config, {"run_root": run_root, "latest_pointer": pointer})]


def test_gate_pointer_is_saved_before_preparation_failure(tmp_path, monkeypatch):
    config = selected_config()
    lifecycle, _ = configure_lifecycle(tmp_path, monkeypatch, config)

    def prepare(*args):
        raise ValueError("source preparation failed")

    with pytest.raises(ValueError, match="source preparation failed"):
        lifecycle.run_advisory_experiment(
            tmp_path, tmp_path / "run", config, run_root="unused",
            latest_pointer="artifacts/gate_pointer.json", prepare=prepare,
        )
    assert json.loads((tmp_path / "artifacts/gate_pointer.json").read_text()) == {
        "run_directory": "run",
    }
    assert not (tmp_path / "run/events.jsonl").exists()


def test_budget_exhaustion_is_recorded_and_finalized(tmp_path, monkeypatch):
    from cv_agent.runtime.budget import BudgetExceeded

    config = selected_config()
    lifecycle, prepare = configure_lifecycle(tmp_path, monkeypatch, config)

    def execute(*args, **kwargs):
        raise BudgetExceeded("offline budget exhausted")

    output = lifecycle.run_advisory_experiment(
        tmp_path, tmp_path / "run", config, run_root="unused", prepare=prepare, execute=execute,
    )
    events = [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
    assert [event["event"] for event in events] == ["run_start", "budget_stop", "run_end"]
    assert events[1]["error"] == "offline budget exhausted"
    assert events[2]["interrupted"] is True
    assert json.loads((output / "acceptance.json").read_text())["passed"] is False
