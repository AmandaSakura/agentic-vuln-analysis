import json
from copy import deepcopy
from pathlib import Path

import pytest

from cv_agent.agent_types import ValidationSubject
from cv_agent.python_pair_acceptance import pair_acceptance_issues, require_python_pair_gate
from cv_agent.python_pair_config import PythonPairExperimentConfig, PythonPairLabels
from cv_agent.live_gate import source_fingerprint


ROOT = Path(__file__).parents[1]


def load_gate():
    config = PythonPairExperimentConfig.model_validate_json(
        (ROOT / "configs/python_pair_gate.json").read_text()
    )
    labels = PythonPairLabels.model_validate_json((ROOT / config.label_file).read_text())
    return config, labels


def evidence_rows():
    config, labels = load_gate()
    subjects = {
        case.case_id: ValidationSubject(
            candidate_id=case.case_id,
            repository_id=case.case_id,
            entry_path=f"{case.file_path}::entry@1-2",
            entry_line=1,
            source_digest=f"digest-{case.case_id}",
            analysis_scope="scope",
        )
        for pair in config.pairs
        for case in pair.cases
    }
    rows = []
    for pair in config.pairs:
        for case in pair.cases:
            label = "VULNERABLE" if case.revision_role == "vulnerable" else "SAFE"
            status = labels.labels[case.case_id].required_validation_status
            subject = subjects[case.case_id]
            observation = {
                "tool": "run_fixture_test",
                "status": "ok",
                "content": "{}",
                "citation_id": "tool:1",
                "validation_status": status,
                "subject": subject.model_dump(mode="json"),
            }
            vote = {
                "expert": "scan",
                "label": label,
                "confidence": 0.9,
                "validation_status": status,
                "evidence_ids": ["local:entry", "tool:1"],
                "rationale": "bounded witness",
                "runtime_mode": "live",
                "trace": [{
                    "step": 1,
                    "model_id": "offline-test",
                    "tool_call": {"call_id": "one", "name": "run_fixture_test", "arguments": {}},
                    "observation": observation,
                }],
                "model_ids": ["offline-test"],
                "model_calls": 2,
                "tool_calls": 1,
                "tool_observation_token_count": 20,
                "usage": {},
            }
            for system in config.systems:
                rows.append({
                    "case_id": case.case_id,
                    "system": system.value,
                    "status": "completed",
                    "predicted_label": label,
                    "model_calls": 2,
                    "tool_calls": 1,
                    "latency_sec": 0,
                    "verdict": {"label": label, "runtime_mode": "live", "votes": [vote]},
                })
    usage = {
        "requests": 20,
        "responses": 20,
        "invalid_responses": 0,
        "requests_without_reported_usage": 0,
        "usage_conflicts": 0,
        "orphaned_responses": 0,
        "duplicate_request_starts": 0,
    }
    return config, labels, rows, usage, subjects


def test_pair_acceptance_requires_exact_cells_and_bound_evidence():
    config, labels, rows, usage, subjects = evidence_rows()
    assert pair_acceptance_issues(rows, usage, config, labels, subjects) == []
    for mutation in ("duplicate", "missing", "wrong_label", "wrong_subject", "usage"):
        changed_rows = deepcopy(rows)
        changed_usage = deepcopy(usage)
        if mutation == "duplicate":
            changed_rows[0] = deepcopy(changed_rows[1])
        elif mutation == "missing":
            changed_rows.pop()
        elif mutation == "wrong_label":
            changed_rows[0]["predicted_label"] = "SAFE"
        elif mutation == "wrong_subject":
            changed_rows[0]["verdict"]["votes"][0]["trace"][0]["observation"]["subject"]["entry_line"] = 2
        else:
            changed_usage["responses"] = 19
        assert pair_acceptance_issues(changed_rows, changed_usage, config, labels, subjects), mutation


def test_gate_pointer_cannot_escape(tmp_path):
    matrix = PythonPairExperimentConfig.model_validate_json(
        (ROOT / "configs/python_pair_matrix.json").read_text()
    )
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts/python_pair_gate.json").write_text(json.dumps({"run_directory": "/tmp/outside"}))
    with pytest.raises(ValueError, match="escapes"):
        require_python_pair_gate(tmp_path, matrix)


def test_matrix_refuses_stale_gate_before_trusting_boolean(tmp_path):
    matrix = PythonPairExperimentConfig.model_validate_json(
        (ROOT / "configs/python_pair_matrix.json").read_text()
    )
    gate_dir = tmp_path / "artifacts/python_pair_gate/old"
    gate_dir.mkdir(parents=True)
    (tmp_path / "artifacts/python_pair_gate.json").write_text(
        json.dumps({"run_directory": "artifacts/python_pair_gate/old"})
    )
    (gate_dir / "metadata.json").write_text(json.dumps({
        "config": json.loads((ROOT / "configs/python_pair_gate.json").read_text()),
        "source_fingerprint": "stale",
        "model_config": {},
    }))
    (gate_dir / "events.jsonl").write_text(json.dumps({"event": "run_end", "interrupted": False}) + "\n")
    (gate_dir / "acceptance.json").write_text(json.dumps({"passed": True}))
    with pytest.raises(ValueError, match="incomplete|stale"):
        require_python_pair_gate(tmp_path, matrix)


def test_source_fingerprint_helper_is_callable_for_gate_tests():
    assert isinstance(source_fingerprint(ROOT), str)
