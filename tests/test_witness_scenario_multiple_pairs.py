"""Several development pairs share budgets while their private identities stay private."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from test_witness_scenario_matrix import _configuration, _module


def _two_pairs(root):
    _, payload = _configuration(root)
    path = root / payload["dataset"]
    dataset = json.loads(path.read_text())
    second = deepcopy(dataset["pairs"][0])
    second.update(pair_id="hp902_entry_10002_ghsa_wxyz_abcd_efgh", entry_id="entry-10002",
                  entry_point={"code": "def invoke(self, location, port, enabled=False):"})
    for index, case in enumerate(second["cases"]):
        directory = f"other-{index}"
        checkout = root / directory
        checkout.mkdir()
        (checkout / "other.py").write_text(
            "import subprocess\nclass Service:\n"
            "    def invoke(self, location, port, enabled=False):\n"
            '        subprocess.Popen(["bash", "-c", f"record {location}"])\n'
        )
        case.update(case_id=f"hp902_{'a' if index == 0 else 'b'}", checkout=directory,
                    file_path="other.py", line_hint=4)
    dataset["pairs"].append(second)
    path.write_text(json.dumps(dataset))
    payload.update(origins=["model_proposed"], dataset_scenario=None)
    payload["cases"].extend({"case_id": case["case_id"], "python_executable": "unused-other-python"}
                            for case in second["cases"])
    return payload


@pytest.mark.parametrize("mode", ["full", "compact"])
def test_four_b_cells_preserve_each_pair_and_actual_neutral_requests(tmp_path, monkeypatch, mode):
    module = _module(monkeypatch)
    payload = _two_pairs(tmp_path)
    payload["response_mode"] = mode
    config = module.ScenarioMatrixConfig.model_validate(payload)

    def forbidden(*args, **kwargs):
        raise AssertionError("Preparation must not execute models, workers or credentials")

    for name in ("load_experiment_model", "require_passing_tests", "run_candidate"):
        monkeypatch.setattr(module, name, forbidden)
    runtime = tmp_path / "unused-runtime"
    cells = module.prepare_cells(tmp_path, config, runtime_root=runtime, nonce="PREPAREONLY123456")
    record = module.preparation_record(tmp_path, config, cells)
    assert len(cells) == len(record["request_preflight"]["cells"]) == 4
    assert {cell.context.response_mode for cell in cells} == {mode}
    assert {cell.candidate.candidate_id for cell in cells} == {"neutral-entry"}
    assert {cell.candidate.case_id for cell in cells} == {"neutral-entry"}
    assert {cell.candidate.repository_id for cell in cells} == {"neutral-entry"}
    assert len({cell.identity["pair_id"] for cell in cells}) == 2
    controls = record["request_preflight"]["controls"]["model_proposed"]
    assert controls["same_supplied_inputs"] is True
    assert len(controls["pairs"]) == 2
    assert all(pair["same_supplied_inputs"] and pair["same_initial_request"]
               for pair in controls["pairs"].values())
    assert cells[0].candidate.query != cells[2].candidate.query
    assert cells[0].candidate.analysis_scope != cells[2].candidate.analysis_scope
    assert record["live_model_requests"] == record["request_preflight"]["live_model_requests"] == 0
    private = {item["case_id"] for item in payload["cases"]} | {cell.identity["pair_id"] for cell in cells}
    for cell, request in zip(cells, record["request_preflight"]["cells"]):
        assert cell.candidate.input_parameters == ()
        assert cell.candidate.entry_boolean_arguments == {}
        assert cell.candidate.entry_condition_assumptions == {}
        assert cell.candidate.entry_value_assumptions == {}
        actual = json.dumps(request["request"])
        assert not any(marker in actual for marker in private)
        assert "Scenario condition assumptions:" not in actual
        assert "Scoped operation code marker" not in actual
        witness = next(tool["function"] for tool in request["request"]["tools"]
                       if tool["function"]["name"] == "run_bounded_execution_witness")
        assert "response_mode" not in witness["parameters"]["properties"]
    assert not runtime.exists()


def test_config_rejects_reused_case_and_more_than_two_pairs(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    payload = _two_pairs(tmp_path)
    repeated = deepcopy(payload)
    repeated["cases"][-1] = repeated["cases"][0]
    with pytest.raises(ValueError, match="distinct"):
        module.ScenarioMatrixConfig.model_validate(repeated)
    payload["cases"].append({"case_id": "private-fifth", "python_executable": "unused"})
    with pytest.raises(ValueError):
        module.ScenarioMatrixConfig.model_validate(payload)


def test_response_mode_defaults_full_and_rejects_model_selected_or_unknown_modes(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    payload = _two_pairs(tmp_path)
    assert module.ScenarioMatrixConfig.model_validate(payload).response_mode == "full"
    payload["response_mode"] = "model_selected"
    with pytest.raises(ValueError):
        module.ScenarioMatrixConfig.model_validate(payload)


def test_preparation_rejects_pair_incomplete_selection(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    payload = _two_pairs(tmp_path)
    payload["cases"] = [payload["cases"][0], payload["cases"][2]]
    config = module.ScenarioMatrixConfig.model_validate(payload)
    with pytest.raises(ValueError, match="two snapshots.*pair"):
        module.prepare_cells(tmp_path, config, runtime_root=tmp_path / "unused", nonce="PREPAREONLY123456")
    assert not (tmp_path / "unused").exists()


def test_preparation_independently_rejects_missing_fixed_role(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    payload = _two_pairs(tmp_path)
    config = module.ScenarioMatrixConfig.model_validate(payload)
    original = module.load_advisory_config

    def wrong_role(*args, **kwargs):
        advisory = original(*args, **kwargs)
        pair = advisory.pairs[1]
        changed = pair.model_copy(update={"cases": (pair.cases[0],
            pair.cases[1].model_copy(update={"revision_role": "vulnerable"}))})
        return advisory.model_copy(update={"pairs": (advisory.pairs[0], changed)})

    monkeypatch.setattr(module, "load_advisory_config", wrong_role)
    with pytest.raises(ValueError, match="vulnerable.*fixed"):
        module.prepare_cells(tmp_path, config, runtime_root=tmp_path / "unused", nonce="PREPAREONLY123456")


def test_preflight_rejects_cell_reuse_and_changed_inputs_within_a_pair(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    config = module.ScenarioMatrixConfig.model_validate(_two_pairs(tmp_path))
    cells = module.prepare_cells(tmp_path, config, runtime_root=tmp_path / "unused", nonce="PREPAREONLY123456")
    reused = cells[:-1] + (cells[0],)
    with pytest.raises(ValueError, match="duplicate|reused|declared"):
        module.preflight_cells(reused, config)
    changed = cells[:-1] + (replace(cells[-1], candidate=cells[-1].candidate.model_copy(
        update={"query": "Different disclosure for one version."})),)
    with pytest.raises(ValueError, match="paired snapshots"):
        module.preflight_cells(changed, config)
    wrong_flag = cells[:-1] + (replace(cells[-1], fixed=False),)
    with pytest.raises(ValueError, match="revision role"):
        module.preflight_cells(wrong_flag, config)
    changed_delivery = cells[:-1] + (replace(cells[-1], context=replace(
        cells[-1].context, response_mode="compact")),)
    with pytest.raises(ValueError, match="paired snapshots"):
        module.preflight_cells(changed_delivery, config)


def test_preflight_rejects_editorial_scene_added_to_second_pair(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    config = module.ScenarioMatrixConfig.model_validate(_two_pairs(tmp_path))
    cells = module.prepare_cells(tmp_path, config, runtime_root=tmp_path / "unused", nonce="PREPAREONLY123456")
    altered = replace(cells[2], candidate=cells[2].candidate.model_copy(update={
        "analysis_scope": cells[2].candidate.analysis_scope + " Scenario condition assumptions: {}"}))
    with pytest.raises(ValueError, match="supplied scenario declarations"):
        module.preflight_cells((cells[0], cells[1], altered, cells[3]), config)


def test_both_pairs_share_one_phase_budget_model_and_durable_ledger(tmp_path, monkeypatch):
    module = _module(monkeypatch)
    payload = _two_pairs(tmp_path)
    payload["max_requests"] = 4
    config = module.ScenarioMatrixConfig.model_validate(payload)
    monkeypatch.setattr(module, "load_config", lambda root: config)
    monkeypatch.setattr(module, "require_passing_tests", lambda: None)
    resolved = {"model": "fake-model", "max_tokens": 6000}
    monkeypatch.setattr(module, "load_experiment_model", lambda *args: (resolved, "fake-key"))
    monkeypatch.setattr(module, "snapshot_sources", lambda *args: {})
    budgets, models = [], []

    def complete(index, candidate, system, journal, budget, **kwargs):
        from cv_agent.runtime.journal import Trial
        budgets.append(budget)
        models.append(kwargs["model_config"])
        assert candidate.candidate_id == candidate.case_id == candidate.repository_id == "neutral-entry"
        assert system.value == "E1"
        request_id = f"request-{len(budgets)}"
        observe = budget.observer(Trial(candidate.case_id, system.value, journal), "scan")
        observe({"event": "model_start", "request_id": request_id, "messages": [], "tools": []})
        observe({"event": "model_response_received", "request_id": request_id,
                 "summary": {"model": "fake-model", "usage": {"total_tokens": 3}}})
        return {"status": "abstained", "predicted_label": "ABSTAIN", "verdict": None,
                "model_calls": 1, "tool_calls": 0, "latency_sec": 0}

    monkeypatch.setattr(module, "run_candidate", complete)
    output = module.run(tmp_path, tmp_path / "result")
    summary = json.loads((output / "summary.json").read_text())
    ledger = json.loads((tmp_path / payload["authorization_ledger"]).read_text())
    assert len(budgets) == 4 and len({id(budget) for budget in budgets}) == 1
    assert all(model is resolved for model in models)
    assert budgets[0].used == summary["usage"]["requests"] == 4
    assert len(ledger["requests"]) == len(ledger["phases"][config.phase_id]["cells"]) == 4
    assert sum(entry["reported_tokens"] for entry in ledger["requests"].values()) == 12
    assert ledger["hard_stop"] is None
