import importlib
import json
from pathlib import Path

import pytest

from cv_agent.runtime.provenance import GitIdentity


def module():
    return importlib.import_module("cv_agent.evaluation.runners.run_vulngym_discovery")


def manifest():
    return {
        "dataset_identity": {"revision": "a" * 40, "dirty": False},
        "role": "heldout_candidate_inputs",
        "claim_eligible": False,
        "split_version": 4,
        "subjects": [{"repository_url": "https://github.com/example/repo", "commit": "b" * 40}],
    }


def test_detector_manifest_rejects_labels_duplicate_subjects_and_extra_fields():
    mod = module()
    mod.validate_detector_manifest(manifest())
    with pytest.raises(ValueError, match="Unexpected field"):
        mod.validate_detector_manifest({**manifest(), "labels": {}})
    with pytest.raises(ValueError, match="only repository URL"):
        mod.validate_detector_manifest({**manifest(), "subjects": [{**manifest()["subjects"][0],
                                                                      "entry_id": "entry-1"}]})
    with pytest.raises(ValueError, match="Duplicate detector subject"):
        mod.validate_detector_manifest({**manifest(), "subjects": manifest()["subjects"] * 2})


def test_full_inventory_has_no_label_inputs_or_first_n_truncation(monkeypatch, tmp_path):
    mod = module()
    source = tmp_path / "data/vulngym-heldout-subjects/example__repo" / ("b" * 40)
    source.mkdir(parents=True)
    (source / "handler.py").write_text("def entry(value):\n    return eval(value)\n")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest()))
    monkeypatch.setattr(mod, "git_identity", lambda _: GitIdentity(revision="b" * 40, dirty=False))
    monkeypatch.setattr(mod, "snapshot_sources", lambda root, output: {"runner.py": "hash"})
    monkeypatch.setattr(mod, "ensure_checkout", lambda *args: source)
    removed = []
    monkeypatch.setattr(mod, "remove_checkout", lambda *args: removed.append(args))

    output = mod.run(manifest_path, root=tmp_path, output=tmp_path / "run")

    inventory = json.loads((output / "inventory.json").read_text())
    assert inventory["run_state"] == "complete"
    assert inventory["selection_protocol"].startswith("complete inventory")
    assert len(inventory["subjects"][0]["candidates"]) > 0
    assert json.loads((output / "metadata.json").read_text())["model_requests"] == 0
    assert len(removed) == 1
    serialized = json.dumps(inventory).lower()
    assert "entry_id" not in serialized
    assert "critical_operation" not in serialized


def test_runner_rejects_modified_or_wrong_commit_checkout(monkeypatch, tmp_path):
    mod = module()
    source = tmp_path / "data/vulngym-heldout-subjects/example__repo" / ("b" * 40)
    source.mkdir(parents=True)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest()))
    monkeypatch.setattr(mod, "snapshot_sources", lambda root, output: {})
    monkeypatch.setattr(mod, "git_identity", lambda _: GitIdentity(revision="c" * 40, dirty=False))
    monkeypatch.setattr(mod, "ensure_checkout", lambda *args: source)
    removed = []
    monkeypatch.setattr(mod, "remove_checkout", lambda *args: removed.append(args))
    with pytest.raises(ValueError, match="differs from frozen commit"):
        mod.run(manifest_path, root=tmp_path, output=tmp_path / "run")
    assert removed == []


def test_reference_scorer_keeps_positive_only_limitations(tmp_path):
    scorer = importlib.import_module("cv_agent.evaluation.diagnostics.score_vulngym_discovery")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    inventory = {
        "run_state": "complete", "systems": [],
        "subjects": [{"repository_id": "subject-001", "repository_url": "https://github.com/example/repo", "commit": "b" * 40,
                      "source_prefix": ".", "selected_case_ids": ["candidate-1"],
                      "candidates": [{"case_id": "candidate-1", "path": "handler.py::entry", "line": 2}],
                      "discovery": {"parse_errors": []}}],
    }
    (run_dir / "inventory.json").write_text(json.dumps(inventory))
    (run_dir / "results.json").write_text("[]")
    refs = {
        "entry-hit": {"entry_id": "entry-hit", "repo_url": "https://github.com/example/repo",
                      "commit": "b" * 40, "report_id": "CVE-TEST-1", "verify": True,
                      "critical_operation": {"file": "handler.py", "line": 2}},
        "entry-miss": {"entry_id": "entry-miss", "repo_url": "https://github.com/example/repo",
                       "commit": "b" * 40, "report_id": "CVE-TEST-2", "verify": True,
                       "critical_operation": {"file": "other.py", "line": 3}},
    }
    references_path = tmp_path / "labels.json"
    references_path.write_text(json.dumps(refs))

    report = scorer.score(run_dir, references_path)

    assert report["discovery_recall"] == 0.5
    assert report["systems"] == {}
    assert report["claim_eligible"] is False
    assert report["evaluation_stage"] == "source_discovery_only"
    with pytest.raises(FileExistsError):
        scorer.score(run_dir, references_path)


def test_runner_supports_durable_partial_progress_and_resume(monkeypatch, tmp_path):
    mod = module()
    c1, c2 = "1" * 40, "2" * 40
    two_subjects_manifest = {
        "dataset_identity": {"revision": "a" * 40, "dirty": False},
        "role": "heldout_candidate_inputs",
        "claim_eligible": False,
        "split_version": 4,
        "subjects": [
            {"repository_url": "https://github.com/example/repo", "commit": c1},
            {"repository_url": "https://github.com/example/repo", "commit": c2},
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(two_subjects_manifest))

    source1 = tmp_path / "src1"
    source1.mkdir()
    (source1 / "app.py").write_text("def f(): return eval('1')\n")
    source2 = tmp_path / "src2"
    source2.mkdir()
    (source2 / "app.py").write_text("def g(): return eval('2')\n")

    def mock_checkout(url, commit, cache, subjects):
        return source1 if commit == c1 else source2

    monkeypatch.setattr(mod, "ensure_checkout", mock_checkout)
    monkeypatch.setattr(mod, "remove_checkout", lambda *args: None)
    monkeypatch.setattr(mod, "snapshot_sources", lambda root, output: {})

    current_commit = c1

    def mock_git_id(path):
        return GitIdentity(revision=current_commit, dirty=False)

    monkeypatch.setattr(mod, "git_identity", mock_git_id)

    run_dir = tmp_path / "resumable_run"

    # Simulate interruption on subject 2
    orig_discover = mod.discover_python_repository
    calls = []

    def failing_discover(source_root, repo_id):
        calls.append(repo_id)
        if len(calls) == 2:
            raise KeyboardInterrupt("Simulated user interrupt")
        return orig_discover(source_root, repo_id)

    monkeypatch.setattr(mod, "discover_python_repository", failing_discover)

    current_commit = c1
    with pytest.raises(KeyboardInterrupt):
        # We need git_identity to match the commit of subject being processed
        def tracking_checkout(url, commit, cache, subjects):
            nonlocal current_commit
            current_commit = commit
            return source1 if commit == c1 else source2

        monkeypatch.setattr(mod, "ensure_checkout", tracking_checkout)
        mod.run(manifest_path, root=tmp_path, output=run_dir)

    inv = json.loads((run_dir / "inventory.json").read_text())
    assert inv["run_state"] == "interrupted"
    assert inv["error_type"] == "KeyboardInterrupt"
    assert len(inv["subjects"]) == 1
    assert inv["subjects"][0]["commit"] == c1

    # Now resume without failure
    monkeypatch.setattr(mod, "discover_python_repository", orig_discover)
    mod.run(manifest_path, root=tmp_path, output=run_dir)

    inv_resumed = json.loads((run_dir / "inventory.json").read_text())
    assert inv_resumed["run_state"] == "complete"
    assert "error_type" not in inv_resumed
    assert len(inv_resumed["subjects"]) == 2
    assert inv_resumed["subjects"][0]["commit"] == c1
    assert inv_resumed["subjects"][1]["commit"] == c2

    # If run on already completed directory, returns directory directly
    assert mod.run(manifest_path, root=tmp_path, output=run_dir) == run_dir


def test_runner_rejects_dataset_mismatch_on_resume(tmp_path):
    mod = module()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest()))
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    inventory = {
        "dataset_identity": {"revision": "wrong" + "0" * 35, "dirty": False},
        "run_state": "interrupted",
        "subjects": [],
    }
    (run_dir / "inventory.json").write_text(json.dumps(inventory))
    (run_dir / "metadata.json").write_text(json.dumps({"manifest": manifest(), "source_sha256": {}}))
    with pytest.raises(ValueError, match="Dataset identity mismatch on resume"):
        mod.run(manifest_path, root=tmp_path, output=run_dir)


def test_runner_rejects_manifest_mismatch_or_reordering_on_resume(tmp_path):
    mod = module()
    c1, c2 = "1" * 40, "2" * 40
    manifest1 = {
        "dataset_identity": {"revision": "a" * 40, "dirty": False},
        "role": "heldout_candidate_inputs",
        "claim_eligible": False,
        "split_version": 4,
        "subjects": [
            {"repository_url": "https://github.com/example/repo", "commit": c1},
            {"repository_url": "https://github.com/example/repo", "commit": c2},
        ],
    }
    manifest_swapped = {
        **manifest1,
        "subjects": [
            {"repository_url": "https://github.com/example/repo", "commit": c2},
            {"repository_url": "https://github.com/example/repo", "commit": c1},
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest_swapped))
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "inventory.json").write_text(json.dumps({
        "dataset_identity": manifest1["dataset_identity"],
        "run_state": "interrupted",
        "subjects": [],
    }))
    (run_dir / "metadata.json").write_text(json.dumps({
        "manifest": manifest1,
        "source_sha256": {},
    }))
    with pytest.raises(ValueError, match="Detector manifest mismatch on resume"):
        mod.run(manifest_path, root=tmp_path, output=run_dir)


def test_runner_rejects_source_code_change_on_resume(tmp_path):
    mod = module()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest()))
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "inventory.json").write_text(json.dumps({
        "dataset_identity": manifest()["dataset_identity"],
        "run_state": "interrupted",
        "subjects": [],
    }))
    # Saved metadata has expected hash for a file, but current has empty or different
    (run_dir / "metadata.json").write_text(json.dumps({
        "manifest": manifest(),
        "source_sha256": {"src/cv_agent/scanner.py": "old_hash"},
    }))
    with pytest.raises(ValueError, match="Analysis source fingerprint mismatch on resume"):
        mod.run(manifest_path, root=tmp_path, output=run_dir)


def test_discover_empty_repository_produces_empty_inventory(tmp_path):
    mod = module()
    manifest_path = tmp_path / "manifest.json"
    c1 = "3" * 40
    empty_manifest = {
        "dataset_identity": {"revision": "a" * 40, "dirty": False},
        "role": "heldout_candidate_inputs",
        "claim_eligible": False,
        "split_version": 4,
        "subjects": [{"repository_url": "https://github.com/example/empty_repo", "commit": c1}],
    }
    manifest_path.write_text(json.dumps(empty_manifest))
    source = tmp_path / "empty_src"
    source.mkdir()
    # No python files in source

    from unittest.mock import patch
    with patch.object(mod, "ensure_checkout", return_value=source), \
         patch.object(mod, "remove_checkout"), \
         patch.object(mod, "git_identity", return_value=GitIdentity(revision=c1, dirty=False)), \
         patch.object(mod, "snapshot_sources", return_value={}):
        output = mod.run(manifest_path, root=tmp_path, output=tmp_path / "empty_run")

    inv = json.loads((output / "inventory.json").read_text())
    assert inv["run_state"] == "complete"
    assert len(inv["subjects"]) == 1
    assert inv["subjects"][0]["candidates"] == []
    assert inv["subjects"][0]["discovery"]["source_files"] == 0


