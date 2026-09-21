import json
from pathlib import Path

import pytest

from cv_agent.python_heldout_pair_config import PythonHeldoutPairExperimentConfig
from cv_agent.python_heldout_pair_acceptance import heldout_pair_acceptance_issues


def config_dict():
    return {
        "dataset_name": "synthetic heldout",
        "dataset_role": "paired_heldout_advisory",
        "claim_eligible": False,
        "model_config": "configs/model.json",
        "systems": ["E1", "E2", "E3", "E4", "E5"],
        "concurrency": 1,
        "limits": {"max_requests": 20, "max_seconds": 60},
        "source_manifest": "artifacts/manifest.json",
        "pairs": [
            {
                "pair_id": "hp001_entry_00001_ghsa_abcd_efgh_ijkl",
                "entry_id": "entry-00001",
                "repository_url": "https://github.com/example/project",
                "advisory": "GHSA-abcd-efgh-ijkl",
                "source_link": "https://github.com/advisories/GHSA-abcd-efgh-ijkl",
                "vuln_ids": ["GHSA-abcd-efgh-ijkl"],
                "source_root": ".",
                "exclude_path_parts": ["tests"],
                "vulnerability_title": "Example issue",
                "source_scope": "example.py:3",
                "analysis_scope": "Assess only this example issue.",
                "entry_point": {"file": "example.py", "line": 1, "code": "def entry():", "desc": "entry"},
                "critical_operation": {"file": "example.py", "line": 3, "code": "eval(x)", "desc": "sink"},
                "cases": [
                    {
                        "case_id": "hp001_a",
                        "revision_role": "vulnerable",
                        "commit": "a" * 40,
                        "checkout": "data/a",
                        "file_path": "example.py",
                        "line_hint": 3,
                    },
                    {
                        "case_id": "hp001_b",
                        "revision_role": "fixed",
                        "commit": "b" * 40,
                        "checkout": "data/b",
                        "file_path": "example.py",
                        "line_hint": 3,
                    },
                ],
            }
        ],
    }


def test_v3_declares_retrieval_change_and_preserves_v2_cells_and_limits():
    root = Path(__file__).resolve().parents[1]
    for stem in ("python_heldout_pair_gate", "python_heldout_pairs"):
        old = PythonHeldoutPairExperimentConfig.model_validate_json((root / f"configs/{stem}_v2.json").read_text())
        new = PythonHeldoutPairExperimentConfig.model_validate_json((root / f"configs/{stem}_v3.json").read_text())
        assert old.graph_direction == "forward"
        assert new.graph_direction == "both"
        assert old.limits == new.limits
        assert old.selected_cells == new.selected_cells
        assert old.expected_abstentions == new.expected_abstentions
        for before, after in zip(old.pairs, new.pairs):
            assert before.cases == after.cases
            assert before.python_import_root is None
            if "langflow-ai/langflow" in after.repository_url:
                assert after.python_import_root == "src/backend/base"


@pytest.mark.parametrize("path", ["../outside", "/tmp/outside"])
def test_import_root_cannot_escape_checkout(path):
    data = config_dict()
    data["pairs"][0]["python_import_root"] = path
    with pytest.raises(ValueError, match="python_import_root"):
        PythonHeldoutPairExperimentConfig.model_validate(data)


def test_heldout_pair_config_uses_neutral_cases_and_fixed_matrix():
    config = PythonHeldoutPairExperimentConfig.model_validate(config_dict())
    assert [case.case_id for case in config.pairs[0].cases] == ["hp001_a", "hp001_b"]
    detector_json = json.dumps(config.model_dump(mode="json"))
    assert "required_validation_status" not in detector_json
    assert "required_fixture_status" not in detector_json


def test_heldout_pair_config_accepts_security_relevant_config_source():
    data = config_dict()
    data["pairs"][0]["cases"][0]["file_path"] = "settings/basic_auth.ini"
    data["pairs"][0]["cases"][1]["file_path"] = "settings/basic_auth.ini"
    data["pairs"][0]["critical_operation"]["file"] = "settings/basic_auth.ini"

    config = PythonHeldoutPairExperimentConfig.model_validate(data)

    assert config.pairs[0].cases[0].file_path == "settings/basic_auth.ini"


def test_selected_cells_define_gate_denominator_and_budget():
    data = config_dict()
    data["selected_cells"] = [
        {"case_id": "hp001_a", "system": "E1"},
        {"case_id": "hp001_b", "system": "E5"},
    ]
    data["limits"]["max_requests"] = 2

    config = PythonHeldoutPairExperimentConfig.model_validate(data)

    assert [(cell.case_id, cell.system.value) for cell in config.selected_cells] == [
        ("hp001_a", "E1"),
        ("hp001_b", "E5"),
    ]


def test_expected_abstentions_are_explicit_and_do_not_hide_other_abstains():
    data = config_dict()
    data["expected_abstentions"] = [{"case_id": "hp001_a", "system": "E1"}]
    config = PythonHeldoutPairExperimentConfig.model_validate(data)
    rows = [
        {
            "case_id": "hp001_a",
            "system": system,
            "status": "abstained" if system in {"E1", "E2"} else "completed",
            "predicted_label": "ABSTAIN" if system in {"E1", "E2"} else "VULNERABLE",
            "pair_id": "hp001_entry_00001_ghsa_abcd_efgh_ijkl",
            "revision_role": "vulnerable",
        }
        for system in ("E1", "E2", "E3", "E4", "E5")
    ]
    rows.extend(
        {
            "case_id": "hp001_b",
            "system": system,
            "status": "completed",
            "predicted_label": "SAFE",
            "pair_id": "hp001_entry_00001_ghsa_abcd_efgh_ijkl",
            "revision_role": "fixed",
        }
        for system in ("E1", "E2", "E3", "E4", "E5")
    )

    issues = heldout_pair_acceptance_issues(rows, {"requests": 1}, config)

    assert "hp001_a E1 did not complete" not in "; ".join(issues)
    assert any("hp001_a E2 did not complete: abstained" in issue for issue in issues)


def test_heldout_pair_acceptance_rejects_duplicate_result_cells():
    config = PythonHeldoutPairExperimentConfig.model_validate(config_dict())
    rows = [
        {
            "case_id": "hp001_a",
            "system": system,
            "status": "completed",
            "predicted_label": "VULNERABLE",
            "pair_id": "hp001_entry_00001_ghsa_abcd_efgh_ijkl",
            "revision_role": "vulnerable",
        }
        for system in ("E1", "E2", "E3", "E4", "E5")
    ]
    rows.extend(
        {
            "case_id": "hp001_b",
            "system": system,
            "status": "completed",
            "predicted_label": "SAFE",
            "pair_id": "hp001_entry_00001_ghsa_abcd_efgh_ijkl",
            "revision_role": "fixed",
        }
        for system in ("E1", "E2", "E3", "E4", "E5")
    )
    rows.insert(0, {**rows[0], "status": "failed", "predicted_label": None})

    issues = heldout_pair_acceptance_issues(rows, {"requests": 1}, config)

    assert any("Duplicate held-out result cell hp001_a E1" in issue for issue in issues)


def test_selected_cells_reject_unknown_or_oversized_gate():
    data = config_dict()
    data["selected_cells"] = [{"case_id": "hp999_a", "system": "E1"}]
    with pytest.raises(ValueError, match="Selected held-out cells"):
        PythonHeldoutPairExperimentConfig.model_validate(data)

    data = config_dict()
    data["pairs"].append(json.loads(json.dumps(data["pairs"][0])))
    data["pairs"][1]["pair_id"] = "hp002_entry_00002_ghsa_abcd_efgh_ijkl"
    data["pairs"][1]["entry_id"] = "entry-00002"
    data["pairs"][1]["cases"][0]["case_id"] = "hp002_a"
    data["pairs"][1]["cases"][1]["case_id"] = "hp002_b"
    data["selected_cells"] = [
        {"case_id": case_id, "system": system}
        for case_id in ("hp001_a", "hp001_b", "hp002_a")
        for system in data["systems"]
    ]
    with pytest.raises(ValueError, match="at most ten"):
        PythonHeldoutPairExperimentConfig.model_validate(data)

    data = config_dict()
    data["expected_abstentions"] = [
        {"case_id": "hp999_a", "system": "E1"},
    ]
    with pytest.raises(ValueError, match="Expected held-out abstentions"):
        PythonHeldoutPairExperimentConfig.model_validate(data)

    data = config_dict()
    data["expected_abstentions"] = [
        {"case_id": "hp001_a", "system": "E1"},
        {"case_id": "hp001_a", "system": "E1"},
    ]
    with pytest.raises(ValueError, match="Duplicate expected"):
        PythonHeldoutPairExperimentConfig.model_validate(data)


@pytest.mark.parametrize(
    "path, value, error",
    [
        (("pairs", 0, "cases", 1, "file_path"), "other.py", "same source path"),
        (("pairs", 0, "cases", 0, "checkout"), "../escape", "relative"),
        (("pairs", 0, "cases", 0, "file_path"), "frontend/App.svelte", "supported source"),
        (("systems",), ["E1", "E2"], "E1 through E5"),
        (("limits", "max_requests"), 1, "one request per planned cell"),
    ],
)
def test_heldout_pair_config_rejects_unsafe_expansion(path, value, error):
    data = config_dict()
    cursor = data
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    with pytest.raises(ValueError, match=error):
        PythonHeldoutPairExperimentConfig.model_validate(data)
