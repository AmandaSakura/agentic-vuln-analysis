import importlib

import pytest


def module():
    return importlib.import_module(
        "cv_agent.evaluation.preparation.prepare_vulngym_evaluation_v4"
    )


def fixture_data():
    inputs = {
        "dataset_identity": {"revision": "a" * 40, "dirty": False},
        "subjects": [
            {"repository_url": "https://github.com/example/seen", "commit": "b" * 40},
            {"repository_url": "https://github.com/example/clean", "commit": "c" * 40},
        ],
    }
    labels = {
        "entry-seen": {"entry_id": "entry-seen", "repo_url": "https://github.com/example/seen",
                       "commit": "b" * 40, "critical_operation": {"file": "a.py", "line": 1}},
        "entry-clean": {"entry_id": "entry-clean", "repo_url": "https://github.com/example/clean",
                        "commit": "c" * 40, "critical_operation": {"file": "b.py", "line": 2}},
    }
    exclusions = [{"repository_url": "https://github.com/example/seen", "reason": "prior exposure"}]
    return inputs, labels, exclusions


def test_split_excludes_every_commit_from_prior_exposure_repository():
    detector, evaluator, summary = module().build_split(*fixture_data(), split_version=4)

    assert [row["repository_url"] for row in detector["subjects"]] == [
        "https://github.com/example/clean"
    ]
    assert list(evaluator) == ["entry-clean"]
    assert summary["excluded_positive_entries"] == 1
    assert detector["claim_eligible"] is False


def test_detector_manifest_contains_no_evaluator_labels_or_locations():
    detector, _, _ = module().build_split(*fixture_data(), split_version=4)

    serialized = str(detector)
    for forbidden in ("entry_id", "report_id", "critical_operation", "verify", "entry-clean"):
        assert forbidden not in serialized


def test_split_rejects_unknown_exclusion_and_label_outside_source_manifest():
    inputs, labels, exclusions = fixture_data()
    with pytest.raises(ValueError, match="absent from the source manifest"):
        module().build_split(inputs, labels, [{"repository_url": "https://github.com/example/missing",
                                               "reason": "prior exposure"}], 4)

    labels["entry-outside"] = {"entry_id": "entry-outside", "repo_url": "https://github.com/example/elsewhere",
                               "commit": "d" * 40}
    with pytest.raises(ValueError, match="outside the frozen input manifest"):
        module().build_split(inputs, labels, exclusions, 4)


def test_frozen_writer_refuses_to_replace_different_content(tmp_path):
    path = tmp_path / "labels.json"
    module().write_frozen(path, {"a": 1})
    module().write_frozen(path, {"a": 1})
    with pytest.raises(FileExistsError, match="Refusing to replace"):
        module().write_frozen(path, {"a": 2})
