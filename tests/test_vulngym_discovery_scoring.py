import importlib
import json
from pathlib import Path

import pytest


def scorer_module():
    return importlib.import_module("cv_agent.evaluation.diagnostics.score_vulngym_discovery")


def make_run(tmp_path: Path, run_state: str = "complete", candidates=None):
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    candidates = candidates or [
        {"case_id": "candidate-1", "path": "handler.py::entry", "line": 10},
    ]
    inventory = {
        "run_state": run_state,
        "systems": [],
        "subjects": [
            {
                "repository_id": "subject-001",
                "repository_url": "https://github.com/example/repo",
                "commit": "a" * 40,
                "source_prefix": ".",
                "selected_case_ids": [c["case_id"] for c in candidates],
                "candidates": candidates,
                "discovery": {"parse_errors": []},
            }
        ],
    }
    (run_dir / "inventory.json").write_text(json.dumps(inventory))
    (run_dir / "results.json").write_text("[]")
    return run_dir


def make_labels(tmp_path: Path, references: dict):
    labels_path = tmp_path / "labels.json"
    labels_path.write_text(json.dumps(references))
    return labels_path


def test_scorer_rejects_incomplete_inventory(tmp_path):
    mod = scorer_module()
    run_dir = make_run(tmp_path, run_state="interrupted")
    labels_path = make_labels(tmp_path, {})
    with pytest.raises(ValueError, match="Cannot score an incomplete source inventory"):
        mod.score(run_dir, labels_path)


def test_scorer_exact_location_matching(tmp_path):
    mod = scorer_module()
    candidates = [
        {"case_id": "c1", "path": "handler.py::func", "line": 20},
        {"case_id": "c2", "path": "utils.py::helper", "line": 50},
    ]
    run_dir = make_run(tmp_path, candidates=candidates)
    refs = {
        "hit-1": {
            "entry_id": "hit-1",
            "repo_url": "https://github.com/example/repo",
            "commit": "a" * 40,
            "report_id": "CVE-2026-0001",
            "verify": True,
            "critical_operation": {"file": "handler.py", "line": 20},
        },
        "miss-line": {
            "entry_id": "miss-line",
            "repo_url": "https://github.com/example/repo",
            "commit": "a" * 40,
            "report_id": "CVE-2026-0002",
            "verify": True,
            "critical_operation": {"file": "handler.py", "line": 25},
        },
        "miss-file": {
            "entry_id": "miss-file",
            "repo_url": "https://github.com/example/repo",
            "commit": "a" * 40,
            "report_id": "CVE-2026-0003",
            "verify": True,
            "critical_operation": {"file": "other.py", "line": 50},
        },
        "non-python-reference": {
            "entry_id": "non-python-ref",
            "repo_url": "https://github.com/example/repo",
            "commit": "a" * 40,
            "report_id": "CVE-2026-0004",
            "verify": True,
            "critical_operation": {"file": "frontend/app.ts", "line": 100},
        },
    }
    labels_path = make_labels(tmp_path, refs)

    report = mod.score(run_dir, labels_path)

    assert report["evaluation_stage"] == "source_discovery_only"
    assert report["claim_eligible"] is False
    assert report["reference_entries"] == 4
    assert report["discovered_entries"] == 1
    assert report["discovered_entry_ids"] == ["hit-1"]
    assert report["discovery_recall"] == 0.25
    assert (run_dir / "reference_score.json").exists()

    # Second call should fail with FileExistsError (immutable report)
    with pytest.raises(FileExistsError):
        mod.score(run_dir, labels_path)


def test_scorer_cli(tmp_path, monkeypatch, capsys):
    mod = scorer_module()
    run_dir = make_run(tmp_path)
    labels_path = make_labels(tmp_path, {})
    monkeypatch.setattr("sys.argv", ["score_vulngym_discovery", str(run_dir), str(labels_path)])
    mod.main()
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert output["evaluation_stage"] == "source_discovery_only"
