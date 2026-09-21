import importlib
import json
import sys
from pathlib import Path

from cv_agent.evaluation import lifecycle
from cv_agent.harness import AgentSystemVersion
from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairExperimentConfig
from cv_agent.domain.types import Candidate

from test_python_heldout_pair_config import config_dict
from advisory_config_fixtures import write_advisory_config


ROOT = Path(__file__).parents[1]


class EmptyIndex:
    documents = {}


def setup_config(tmp_path):
    (tmp_path / "configs").mkdir()
    (tmp_path / "artifacts").mkdir()
    data = config_dict()
    write_advisory_config(tmp_path, data, "matrix")
    (tmp_path / "configs/model.json").write_text("{}")
    (tmp_path / "artifacts/manifest.json").write_text(json.dumps({"summary": {"pairs": 1}}))
    return data


def setup_gate_config(tmp_path):
    (tmp_path / "configs").mkdir()
    (tmp_path / "artifacts").mkdir()
    data = config_dict()
    data["graph_direction"] = "both"
    data["dataset_name"] = "synthetic heldout gate"
    data["concurrency"] = 2
    data["selected_cells"] = [
        {"case_id": case["case_id"], "system": system}
        for case in data["pairs"][0]["cases"]
        for system in data["systems"]
    ]
    write_advisory_config(tmp_path, data, "gate")
    (tmp_path / "configs/model.json").write_text("{}")
    (tmp_path / "artifacts/manifest.json").write_text(json.dumps({"summary": {"pairs": 1}}))
    return data


def test_runner_gates_before_trials_and_preserves_full_denominator(monkeypatch, tmp_path):
    data = setup_config(tmp_path)
    mod = importlib.import_module('cv_agent.evaluation.runners.run_python_heldout_pair_matrix')
    events = []
    candidate = Candidate(
        candidate_id="hp001_a",
        case_id="hp001_a",
        repository_id="hp001_a",
        path="example.py::risky@1-3",
        line=1,
        query="example",
    )
    tasks = [("pair", "vulnerable", EmptyIndex(), candidate, (), AgentSystemVersion.E1_LOCAL_SINGLE)]
    monkeypatch.setattr(lifecycle, "build_tasks", lambda root, config: (tasks, {}, {}))
    monkeypatch.setattr(lifecycle, "snapshot_sources", lambda root, path: {})
    monkeypatch.setattr(lifecycle, "source_fingerprint", lambda root: "fingerprint")
    monkeypatch.setenv("ANTIGRAVITY_API_KEY", "test-key")

    def gate():
        events.append("gate")

    def complete(*args, **kwargs):
        assert events == ["gate"]
        events.append("trial")
        return {
            "case_id": "hp001_a",
            "system": "E1",
            "status": "completed",
            "predicted_label": "VULNERABLE",
            "model_calls": 1,
            "tool_calls": 0,
            "latency_sec": 0.1,
            "verdict": None,
        }

    monkeypatch.setattr(lifecycle, "require_passing_tests", gate)
    monkeypatch.setattr(lifecycle, "run_candidate", complete)
    output = mod.run(root=tmp_path, output=tmp_path / "run")

    rows = json.loads((output / "results.json").read_text())
    assert len(rows) == len(data["systems"]) * 2
    assert rows[0]["case_id"] == "hp001_a"
    assert rows[0]["ground_truth"] == "VULNERABLE"
    assert any(row["status"] == "not_run" and row["case_id"] == "hp001_b" for row in rows)
    assert events == ["gate", "trial"]


def test_rows_with_truth_preserves_duplicate_result_cells():
    parsed = PythonHeldoutPairExperimentConfig.model_validate(config_dict())
    mod = importlib.import_module('cv_agent.evaluation.results')
    completed = {
        "case_id": "hp001_a",
        "system": "E1",
        "status": "completed",
        "predicted_label": "VULNERABLE",
        "model_calls": 1,
        "tool_calls": 0,
        "latency_sec": 0.1,
        "verdict": None,
        "pair_id": "hp001_entry_00001_ghsa_abcd_efgh_ijkl",
        "revision_role": "vulnerable",
    }
    failed = {**completed, "status": "failed", "predicted_label": None}

    rows = mod.rows_with_truth([failed, completed], parsed)

    matches = [row for row in rows if row["case_id"] == "hp001_a" and row["system"] == "E1"]
    assert [row["status"] for row in matches] == ["failed", "completed"]


def test_heldout_gate_runs_exactly_ten_cells_and_updates_pointer(monkeypatch, tmp_path):
    data = setup_gate_config(tmp_path)
    mod = importlib.import_module('cv_agent.evaluation.runners.run_python_heldout_pair_gate')
    events = []
    candidates = {
        case["case_id"]: Candidate(
            candidate_id=case["case_id"],
            case_id=case["case_id"],
            repository_id=case["case_id"],
            path="example.py::risky@1-3",
            line=1,
            query="example",
        )
        for case in data["pairs"][0]["cases"]
    }

    def fake_build_tasks(root, config):
        events.append(("build", len(config.pairs), config.concurrency))
        tasks = []
        for pair in config.pairs:
            for case in pair.cases:
                for system in config.systems:
                    tasks.append((pair.pair_id, case.revision_role, EmptyIndex(), candidates[case.case_id], (), system))
        return tasks, {}, {}

    def complete(index, candidate, system, journal, budget, **kwargs):
        assert kwargs["graph_direction"] == "both"
        events.append(("trial", candidate.case_id, system.value))
        return {
            "case_id": candidate.case_id,
            "system": system.value,
            "status": "completed",
            "predicted_label": "VULNERABLE" if candidate.case_id.endswith("_a") else "SAFE",
            "model_calls": 1,
            "tool_calls": 0,
            "latency_sec": 0.1,
            "verdict": None,
        }

    monkeypatch.setattr(lifecycle, "build_tasks", fake_build_tasks)
    monkeypatch.setattr(lifecycle, "snapshot_sources", lambda root, path: {})
    monkeypatch.setattr(lifecycle, "source_fingerprint", lambda root: "fingerprint")
    monkeypatch.setattr(lifecycle, "require_passing_tests", lambda: events.append(("gate",)))
    monkeypatch.setattr(lifecycle, "run_candidate", complete)
    monkeypatch.setenv("ANTIGRAVITY_API_KEY", "test-key")
    output = mod.run(root=tmp_path, output=tmp_path / "run")

    rows = json.loads((output / "results.json").read_text())
    pointer = json.loads((tmp_path / "artifacts/python_heldout_pair_gate_v4.json").read_text())
    assert pointer == {"run_directory": "run"}
    assert events[0] == ("build", 1, 2)
    assert events[1] == ("gate",)
    assert len([event for event in events if event[0] == "trial"]) == 10
    assert len(rows) == 10
    assert {(row["case_id"], row["system"]) for row in rows} == {
        (case["case_id"], system)
        for case in data["pairs"][0]["cases"]
        for system in data["systems"]
    }
    assert json.loads((output / "acceptance.json").read_text()) == {
        "passed": False,
        "issues": ["No model requests were recorded"],
        "automatic_expansion": False,
    }


def test_runner_blocks_without_api_key_after_full_gate(monkeypatch, tmp_path):
    setup_config(tmp_path)
    mod = importlib.import_module('cv_agent.evaluation.runners.run_python_heldout_pair_matrix')
    events = []
    monkeypatch.setattr(lifecycle, "build_tasks", lambda root, config: ([], {}, {}))
    monkeypatch.setattr(lifecycle, "require_passing_tests", lambda: events.append("gate"))
    monkeypatch.delenv("ANTIGRAVITY_API_KEY", raising=False)

    try:
        mod.run(root=tmp_path, output=tmp_path / "run")
    except ValueError as error:
        assert "ANTIGRAVITY_API_KEY" in str(error)
    else:
        raise AssertionError("missing API key should block live run")
    assert events == ["gate"]


def test_runner_continues_after_abstain(monkeypatch, tmp_path):
    setup_config(tmp_path)
    mod = importlib.import_module('cv_agent.evaluation.runners.run_python_heldout_pair_matrix')
    candidates = [
        Candidate(
            candidate_id="hp001_a",
            case_id="hp001_a",
            repository_id="hp001_a",
            path="example.py::risky@1-3",
            line=1,
            query="example",
        ),
        Candidate(
            candidate_id="hp001_b",
            case_id="hp001_b",
            repository_id="hp001_b",
            path="example.py::risky@1-3",
            line=1,
            query="example",
        ),
    ]
    tasks = [
        ("pair", "vulnerable", EmptyIndex(), candidates[0], (), AgentSystemVersion.E1_LOCAL_SINGLE),
        ("pair", "fixed", EmptyIndex(), candidates[1], (), AgentSystemVersion.E1_LOCAL_SINGLE),
    ]
    monkeypatch.setattr(lifecycle, "build_tasks", lambda root, config: (tasks, {}, {}))
    monkeypatch.setattr(lifecycle, "require_passing_tests", lambda: None)
    monkeypatch.setattr(lifecycle, "snapshot_sources", lambda root, path: {})
    monkeypatch.setattr(lifecycle, "source_fingerprint", lambda root: "fingerprint")
    monkeypatch.setenv("ANTIGRAVITY_API_KEY", "test-key")
    calls = []

    def scripted(index, candidate, system, journal, budget, **kwargs):
        calls.append(candidate.case_id)
        if candidate.case_id == "hp001_a":
            return {
                "case_id": "hp001_a",
                "system": "E1",
                "status": "abstained",
                "predicted_label": "ABSTAIN",
                "model_calls": 1,
                "tool_calls": 0,
                "latency_sec": 0.1,
                "verdict": None,
            }
        return {
            "case_id": "hp001_b",
            "system": "E1",
            "status": "completed",
            "predicted_label": "SAFE",
            "model_calls": 1,
            "tool_calls": 0,
            "latency_sec": 0.1,
            "verdict": None,
        }

    monkeypatch.setattr(lifecycle, "run_candidate", scripted)
    output = mod.run(root=tmp_path, output=tmp_path / "run")
    rows = json.loads((output / "results.json").read_text())
    observed = {(row["case_id"], row["system"]): row["status"] for row in rows}
    assert calls == ["hp001_a", "hp001_b"]
    assert observed[("hp001_a", "E1")] == "abstained"
    assert observed[("hp001_b", "E1")] == "completed"


def test_runner_continues_after_failed_cell(monkeypatch, tmp_path):
    setup_config(tmp_path)
    mod = importlib.import_module('cv_agent.evaluation.runners.run_python_heldout_pair_matrix')
    candidates = [
        Candidate(
            candidate_id="hp001_a",
            case_id="hp001_a",
            repository_id="hp001_a",
            path="example.py::risky@1-3",
            line=1,
            query="example",
        ),
        Candidate(
            candidate_id="hp001_b",
            case_id="hp001_b",
            repository_id="hp001_b",
            path="example.py::risky@1-3",
            line=1,
            query="example",
        ),
    ]
    tasks = [
        ("pair", "vulnerable", EmptyIndex(), candidates[0], (), AgentSystemVersion.E1_LOCAL_SINGLE),
        ("pair", "fixed", EmptyIndex(), candidates[1], (), AgentSystemVersion.E1_LOCAL_SINGLE),
    ]
    monkeypatch.setattr(lifecycle, "build_tasks", lambda root, config: (tasks, {}, {}))
    monkeypatch.setattr(lifecycle, "require_passing_tests", lambda: None)
    monkeypatch.setattr(lifecycle, "snapshot_sources", lambda root, path: {})
    monkeypatch.setattr(lifecycle, "source_fingerprint", lambda root: "fingerprint")
    monkeypatch.setenv("ANTIGRAVITY_API_KEY", "test-key")
    calls = []

    def scripted(index, candidate, system, journal, budget, **kwargs):
        calls.append(candidate.case_id)
        if candidate.case_id == "hp001_a":
            return {
                "case_id": "hp001_a",
                "system": "E1",
                "status": "failed",
                "predicted_label": None,
                "model_calls": 1,
                "tool_calls": 0,
                "latency_sec": 0.1,
                "verdict": None,
                "error": "upstream_blocked: OTHER",
            }
        return {
            "case_id": "hp001_b",
            "system": "E1",
            "status": "completed",
            "predicted_label": "SAFE",
            "model_calls": 1,
            "tool_calls": 0,
            "latency_sec": 0.1,
            "verdict": None,
        }

    monkeypatch.setattr(lifecycle, "run_candidate", scripted)
    output = mod.run(root=tmp_path, output=tmp_path / "run")
    rows = json.loads((output / "results.json").read_text())
    observed = {(row["case_id"], row["system"]): row["status"] for row in rows}
    assert calls == ["hp001_a", "hp001_b"]
    assert observed[("hp001_a", "E1")] == "failed"
    assert observed[("hp001_b", "E1")] == "completed"
