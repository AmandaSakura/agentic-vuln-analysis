"""Scenario discovery inputs and the bounded comparison remain offline."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairExperimentConfig
from cv_agent.evaluation.datasets.advisory_source import build_pair_input
from test_python_heldout_pair_config import config_dict


def _classified(value, classification="deployment_configuration"):
    return {"value": value, "classification": classification, "rationale": "Declared test premise."}


def _configuration(root):
    data = config_dict()
    pair = data["pairs"][0]
    pair.update(property_id="command-execution", input_parameters=["uri"],
                entry_boolean_arguments={"enabled": True},
                entry_condition_assumptions={"environment_ready()": True},
                entry_value_assumptions={"port": 7000},
                vulnerability_title="Editorial branch enabled=True",
                analysis_scope="Editorial assumes environment_ready() and port=7000",
                entry_point={"code": "def serve(self, uri, port, enabled=False):"},
                critical_operation={"code": "subprocess.Popen(command)"})
    for case, directory in zip(pair["cases"], ("first", "second")):
        checkout = root / directory
        checkout.mkdir()
        (checkout / "example.py").write_text(
            "import subprocess\nclass Service:\n"
            "    def serve(self, uri, port, enabled=False):\n"
            '        subprocess.Popen(["bash", "-c", f"record {uri}"])\n'
        )
        case.update(checkout=directory, file_path="example.py", line_hint=4)
    config = PythonHeldoutPairExperimentConfig.model_validate(data)
    dataset_path = root / "configs/datasets/advisory_pairs_v4.json"
    profile_path = root / "configs/profiles/scenario.json"
    dataset_path.parent.mkdir(parents=True)
    profile_path.parent.mkdir(parents=True)
    dataset_fields = {"dataset_role", "claim_eligible", "source_manifest", "pairs"}
    dataset_path.write_text(json.dumps({key: value for key, value in data.items() if key in dataset_fields}))
    profile_path.write_text(json.dumps({key: value for key, value in data.items() if key not in dataset_fields}))
    (root / "configs/model.json").write_text(json.dumps({"base_url": "https://model.invalid/v1", "model": "fake-model"}))
    (root / "resources.json").write_text("{}")
    (root / "read_grants.json").write_text("[]")
    matrix = {
        "dataset_role": "development", "claim_eligible": False,
        "dataset": "configs/datasets/advisory_pairs_v4.json",
        "selection_profile": "configs/profiles/scenario.json",
        "model_config": "configs/model.json", "system": "E1", "max_requests": 60,
        "max_seconds": 60, "resource_profile": "resources.json", "read_grants": "read_grants.json",
        "phase_id": "offline-phase", "expected_returned_model": "fake-model",
        "authorization_ledger": "authorization_ledger.json", "cumulative_request_limit": 210,
        "cumulative_token_limit": 2500000, "output_token_limit": 6000, "framing_token_allowance": 4096,
        "advisory_text": "Advisory reports a command interpolation weakness.",
        "advisory_text_origin": "dataset_advisory_summary",
        "advisory_text_note": "Test editorial scenario clues are omitted.",
        "dataset_scenario": {
            "input_parameter": _classified("uri", "attacker_controlled_input"),
            "entry_boolean_arguments": {"enabled": _classified(True)},
            "entry_condition_assumptions": {"environment_ready()": _classified(True, "environment_condition")},
            "entry_value_assumptions": {"port": _classified(7000)},
            "constructor_parameters": {}, "precondition_files": {},
        },
        "cases": [{"case_id": case.case_id, "python_executable": "unused-python"}
                  for case in config.pairs[0].cases],
    }
    return config, matrix


def test_scenario_free_source_clears_subject_and_editorial_query_hints(tmp_path):
    config, matrix = _configuration(tmp_path)
    pair, case = config.pairs[0], config.pairs[0].cases[0]
    _, supplied, _ = build_pair_input(tmp_path, pair, case)
    assert supplied.input_parameters == ("uri",)
    assert "environment_ready()" in supplied.analysis_scope
    assert "enabled=True" in supplied.query
    _, discovered, _ = build_pair_input(tmp_path, pair, case,
        include_scenario_assumptions=False, advisory_text=matrix["advisory_text"],
        include_scoped_operation=False)
    assert discovered.input_parameters == ()
    assert discovered.entry_boolean_arguments == {}
    assert discovered.entry_condition_assumptions == {}
    assert discovered.entry_value_assumptions == {}
    assert "Scenario condition assumptions" not in discovered.analysis_scope
    assert "environment_ready()" not in discovered.analysis_scope
    assert "7000" not in discovered.query
    assert "enabled=True" not in discovered.query
    assert "Scoped operation code marker" not in discovered.analysis_scope
    assert "subprocess.Popen(command)" not in discovered.query
    assert "subprocess.Popen(command)" not in discovered.analysis_scope
    assert "Scoped operation code marker" in supplied.analysis_scope
    assert matrix["advisory_text"] in discovered.analysis_scope
    assert pair.input_parameters == ("uri",)
    assert pair.entry_boolean_arguments == {"enabled": True}


def test_scene_removal_requires_explicit_advisory_text_before_indexing(tmp_path):
    config, _ = _configuration(tmp_path)
    with pytest.raises(ValueError, match="separately disclosed"):
        build_pair_input(tmp_path, config.pairs[0], config.pairs[0].cases[0],
                         include_scenario_assumptions=False)


def _module(monkeypatch):
    from cv_agent.evaluation.runners import run_witness_scenario_matrix as module
    monkeypatch.setattr(module, "require_clean_checkout", lambda *args: None)
    monkeypatch.setattr(module, "require_committed_clean", lambda *args: "c" * 40)
    monkeypatch.setattr(module, "case_identity", lambda root, pair, case, hashes:
                        {"case_id": case.case_id, "source_sha256": hashes})
    return module


def test_prepare_four_cells_without_credentials_models_or_execution(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    _, payload = _configuration(tmp_path)
    config = module.ScenarioMatrixConfig.model_validate(payload)

    def forbidden(*args, **kwargs):
        raise AssertionError("Preparation must not load credentials or execute models")

    monkeypatch.setattr(module, "load_experiment_model", forbidden)
    monkeypatch.setattr(module, "require_passing_tests", forbidden)
    monkeypatch.setattr(module, "run_candidate", forbidden)
    runtime = tmp_path / "no-runtime"
    cells = module.prepare_cells(tmp_path, config, runtime_root=runtime, nonce="PREPAREONLY123456")
    record = module.preparation_record(tmp_path, config, cells)
    assert record["live_model_requests"] == 0
    assert len(cells) == 4
    assert [cell.scenario_origin for cell in cells] == ["dataset_provided"] * 2 + ["model_proposed"] * 2
    assert {cell.candidate.candidate_id for cell in cells} == {"neutral-entry"}
    assert {cell.candidate.repository_id for cell in cells} == {"neutral-entry"}
    assert {cell.candidate.path for cell in cells} == {"example.py::Service.serve@3-4"}
    assert cells[0].context.dataset_scenario is not None
    assert cells[2].context.dataset_scenario is None
    assert all(cell.context.runtime_root == runtime for cell in cells)
    assert all("Scoped operation code marker" not in cell.candidate.analysis_scope for cell in cells)
    assert all("subprocess.Popen(command)" not in cell.candidate.query for cell in cells)
    assert not runtime.exists()
    assert not (tmp_path / "artifacts").exists()
    for cell in cells[2:]:
        assert cell.candidate.input_parameters == ()
        assert not cell.candidate.entry_boolean_arguments
        assert "environment_ready()" not in cell.candidate.analysis_scope
        assert "Editorial" not in cell.candidate.query


def test_request_cap_cannot_exceed_declared_sixty(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    _, payload = _configuration(tmp_path)
    payload["max_requests"] = 61
    with pytest.raises(ValueError):
        module.ScenarioMatrixConfig.model_validate(payload)


def test_preparation_rejects_dataset_classification_value_drift(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    _, payload = _configuration(tmp_path)
    payload["dataset_scenario"]["entry_boolean_arguments"]["enabled"]["value"] = False
    config = module.ScenarioMatrixConfig.model_validate(payload)
    with pytest.raises(ValueError, match="match the supplied subject"):
        module.prepare_cells(tmp_path, config, runtime_root=tmp_path / "no-runtime", nonce="PREPAREONLY123456")
    assert not (tmp_path / "no-runtime").exists()


def _row(case, origin):
    return {"evaluation_case_id": case, "scenario_origin": origin,
            "status": "abstained", "predicted_label": "ABSTAIN"}


def test_reports_do_not_mix_origins_or_call_literal_observation_safe(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    _, payload = _configuration(tmp_path)
    config = module.ScenarioMatrixConfig.model_validate(payload)
    events = []
    for origin, status in (("dataset_provided", "CONFIRMED"), ("model_proposed", "UNRESOLVED")):
        events.append({"event": "tool_result", "evaluation_case_id": "private-a", "scenario_origin": origin,
            "observation": {"tool": "run_bounded_execution_witness", "status": "ok",
                "validation_status": status, "metadata": {"witness_attempted": True},
                "content": json.dumps({"scenario_origin": origin, "raw_status":
                    "EXPANDED_OBSERVED" if status == "CONFIRMED" else "LITERAL_OBSERVED"})}})
    rows = [_row("private-a", origin) for origin in module.ORIGINS]
    summary = module.summarize(tmp_path, rows, events, config)
    assert summary["conditions"]["dataset_provided"]["confirmed_cells"] == ["private-a"]
    assert summary["conditions"]["model_proposed"]["confirmed_cells"] == []
    assert summary["conditions"]["model_proposed"]["cell_outcomes"][0]["predicted_label"] == "ABSTAIN"
    assert "recall" not in summary
    assert summary["usage"]["requests"] == 0


def test_live_failure_preserves_usage_and_stops_without_retry(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    _, payload = _configuration(tmp_path)
    config = module.ScenarioMatrixConfig.model_validate(payload)
    monkeypatch.setattr(module, "load_config", lambda root: config)
    monkeypatch.setattr(module, "require_passing_tests", lambda: None)
    monkeypatch.setattr(module, "load_experiment_model", lambda *args:
                        ({"model": "fake-model", "max_tokens": 6000}, "fake-key"))
    monkeypatch.setattr(module, "snapshot_sources", lambda *args: {})
    calls = []

    def failed(index, candidate, system, journal, budget, **kwargs):
        from cv_agent.runtime.journal import Trial
        calls.append(kwargs["model_config"])
        observe = budget.observer(Trial(candidate.case_id, system.value, journal), "scan")
        observe({"event": "model_start", "request_id": "failed-request", "messages": [], "tools": []})
        observe({"event": "model_response_received", "request_id": "failed-request",
                 "summary": {"model": "fake-model", "usage": {"total_tokens": 19}},
                 "raw_response": {"usage": {"total_tokens": 19}, "choices": []}})
        observe({"event": "model_invalid_response", "request_id": "failed-request"})
        observe({"event": "model_error", "request_id": "failed-request", "error": "empty choices"})
        return {"status": "failed", "predicted_label": None, "verdict": None,
                "error": "empty choices", "model_calls": 1, "tool_calls": 0, "latency_sec": 0}

    monkeypatch.setattr(module, "run_candidate", failed)
    output = tmp_path / "result"
    with pytest.raises(RuntimeError, match="empty choices"):
        module.run(tmp_path, output)
    summary = json.loads((output / "summary.json").read_text())
    results = json.loads((output / "results.json").read_text())
    assert calls == [{"model": "fake-model", "max_tokens": 6000}]
    assert summary["usage"]["requests"] == 1
    assert summary["usage"]["reported_total_tokens"] == 19
    assert summary["usage"]["invalid_responses"] == 1
    assert summary["conditions"]["model_proposed"]["usage"]["requests"] == 0
    assert [row["status"] for row in results] == ["failed", "not_run", "not_run", "not_run"]
    assert "failed-request" in (output / "events.jsonl").read_text()


def test_four_cells_share_one_budget_and_one_resolved_model(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    _, payload = _configuration(tmp_path)
    payload["max_requests"] = 4
    payload["expected_returned_model"] = "same-model"
    config = module.ScenarioMatrixConfig.model_validate(payload)
    monkeypatch.setattr(module, "load_config", lambda root: config)
    monkeypatch.setattr(module, "require_passing_tests", lambda: None)
    resolved = {"model": "same-model", "max_tokens": 6000}
    monkeypatch.setattr(module, "load_experiment_model", lambda *args: (resolved, "fake-key"))
    monkeypatch.setattr(module, "snapshot_sources", lambda *args: {})
    budgets, models, systems = [], [], []

    def complete(index, candidate, system, journal, budget, **kwargs):
        from cv_agent.runtime.journal import Trial
        budgets.append(budget)
        models.append(kwargs["model_config"])
        systems.append(system.value)
        observe = budget.observer(Trial(candidate.case_id, system.value, journal), "scan")
        request_id = f"request-{len(budgets)}"
        observe({"event": "model_start", "request_id": request_id, "messages": [], "tools": []})
        observe({"event": "model_response_received", "request_id": request_id,
                 "summary": {"model": "same-model", "usage": {"total_tokens": 3}}})
        return {"status": "abstained", "predicted_label": "ABSTAIN", "verdict": None,
                "model_calls": 1, "tool_calls": 0, "latency_sec": 0}

    monkeypatch.setattr(module, "run_candidate", complete)
    output = module.run(tmp_path, tmp_path / "result")
    summary = json.loads((output / "summary.json").read_text())
    assert len({id(budget) for budget in budgets}) == 1
    assert all(model is resolved for model in models)
    assert systems == ["E1"] * 4
    assert budgets[0].used == 4
    assert summary["usage"]["requests"] == 4
    assert [summary["conditions"][origin]["usage"]["requests"] for origin in module.ORIGINS] == [2, 2]


def test_aggregate_request_exhaustion_stops_before_an_extra_request(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    _, payload = _configuration(tmp_path)
    payload["max_requests"] = 4
    payload["expected_returned_model"] = "same-model"
    config = module.ScenarioMatrixConfig.model_validate(payload)
    monkeypatch.setattr(module, "load_config", lambda root: config)
    monkeypatch.setattr(module, "require_passing_tests", lambda: None)
    monkeypatch.setattr(module, "load_experiment_model", lambda *args:
                        ({"model": "same-model", "max_tokens": 6000}, "fake-key"))
    monkeypatch.setattr(module, "snapshot_sources", lambda *args: {})

    def complete(index, candidate, system, journal, budget, **kwargs):
        from cv_agent.runtime.budget import BudgetExceeded
        from cv_agent.runtime.journal import Trial
        trial = Trial(candidate.case_id, system.value, journal)
        observe = budget.observer(trial, "scan")
        try:
            for _ in range(2):
                observe({"event": "model_start", "request_id": f"request-{budget.used}", "messages": [], "tools": []})
        except BudgetExceeded as error:
            return {"status": "not_run", "predicted_label": None, "error": str(error),
                    "verdict": None, "model_calls": trial.model_calls, "tool_calls": 0, "latency_sec": 0}
        return {"status": "abstained", "predicted_label": "ABSTAIN", "verdict": None,
                "model_calls": trial.model_calls, "tool_calls": 0, "latency_sec": 0}

    monkeypatch.setattr(module, "run_candidate", complete)
    output = tmp_path / "result"
    with pytest.raises(RuntimeError, match="request or wall-time limit"):
        module.run(tmp_path, output)
    summary = json.loads((output / "summary.json").read_text())
    results = json.loads((output / "results.json").read_text())
    assert summary["usage"]["requests"] == 4
    assert [row["status"] for row in results] == ["abstained", "abstained", "not_run", "not_run"]
    starts = [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()
              if json.loads(line)["event"] == "model_start"]
    assert len(starts) == 4


def test_ordinary_cell_failure_can_continue_without_reexecuting_the_cell(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    _, payload = _configuration(tmp_path)
    payload["continue_on_cell_failure"] = True
    config = module.ScenarioMatrixConfig.model_validate(payload)
    monkeypatch.setattr(module, "load_config", lambda root: config)
    monkeypatch.setattr(module, "require_passing_tests", lambda: None)
    monkeypatch.setattr(module, "load_experiment_model", lambda *args:
                        ({"model": "fake-model", "max_tokens": 6000}, "fake-key"))
    monkeypatch.setattr(module, "snapshot_sources", lambda *args: {})
    calls = []

    def complete(index, candidate, system, journal, budget, **kwargs):
        from cv_agent.runtime.journal import Trial
        calls.append(journal.cell.evaluation_case_id)
        observe = budget.observer(Trial(candidate.case_id, system.value, journal), "scan")
        request_id = f"request-{len(calls)}"
        observe({"event": "model_start", "request_id": request_id, "messages": [], "tools": []})
        observe({"event": "model_response_received", "request_id": request_id,
                 "summary": {"model": "fake-model", "usage": {"total_tokens": 3}}})
        return {"status": "failed" if len(calls) == 1 else "abstained",
                "predicted_label": None if len(calls) == 1 else "ABSTAIN", "verdict": None,
                "model_calls": 1, "tool_calls": 0, "latency_sec": 0,
                "error": "ordinary protocol failure" if len(calls) == 1 else None}

    monkeypatch.setattr(module, "run_candidate", complete)
    output = module.run(tmp_path, tmp_path / "result")
    summary = json.loads((output / "summary.json").read_text())
    results = json.loads((output / "results.json").read_text())
    assert calls == ["hp001_a", "hp001_b", "hp001_a", "hp001_b"]
    assert summary["usage"]["requests"] == 4
    assert summary["hard_stop"] is None
    assert [row["status"] for row in results] == ["failed", "abstained", "abstained", "abstained"]


def test_model_identity_stop_overrides_continue_flag_and_surfaces_usage(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    _, payload = _configuration(tmp_path)
    payload["continue_on_cell_failure"] = True
    config = module.ScenarioMatrixConfig.model_validate(payload)
    monkeypatch.setattr(module, "load_config", lambda root: config)
    monkeypatch.setattr(module, "require_passing_tests", lambda: None)
    monkeypatch.setattr(module, "load_experiment_model", lambda *args:
                        ({"model": "fake-model", "max_tokens": 6000}, "fake-key"))
    monkeypatch.setattr(module, "snapshot_sources", lambda *args: {})
    calls = []

    def complete(index, candidate, system, journal, budget, **kwargs):
        from cv_agent.runtime.journal import Trial
        calls.append(candidate.case_id)
        observe = budget.observer(Trial(candidate.case_id, system.value, journal), "scan")
        observe({"event": "model_start", "request_id": "first", "messages": [], "tools": []})
        try:
            observe({"event": "model_response_received", "request_id": "first",
                     "summary": {"model": "different-model", "usage": {"total_tokens": 7}}})
        except module.ExperimentHardStop as error:
            return {"status": "failed", "predicted_label": None, "error": str(error),
                    "verdict": None, "model_calls": 1, "tool_calls": 0, "latency_sec": 0}
        raise AssertionError("Identity guard must stop the returned model")

    monkeypatch.setattr(module, "run_candidate", complete)
    output = tmp_path / "result"
    with pytest.raises(module.ExperimentHardStop, match="S2"):
        module.run(tmp_path, output)
    summary = json.loads((output / "summary.json").read_text())
    assert calls == ["neutral-entry"]
    assert summary["hard_stop"]["code"] == "S2"
    assert summary["authorization_accounting"]["cumulative_requests"] == 1
    assert summary["usage"]["reported_total_tokens"] == 7
