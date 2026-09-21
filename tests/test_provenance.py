from pathlib import Path

import cv_agent.runtime.provenance as provenance


def test_find_project_root_walks_up_to_git_pyproject(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    nested = tmp_path / "data" / "raw"
    nested.mkdir(parents=True)
    assert provenance.find_project_root(nested) == tmp_path


def test_run_identity_records_code_and_dataset_git_state(tmp_path: Path, monkeypatch):
    code = tmp_path / "code"
    dataset = tmp_path / "dataset"
    code.mkdir()
    dataset.mkdir()

    def fake_git(repository: Path, *arguments: str) -> str:
        if arguments[:2] == ("rev-parse", "HEAD"):
            return f"{repository.name}-revision"
        if arguments and arguments[0] == "status":
            return " M changed.py" if repository == dataset else ""
        raise AssertionError(arguments)

    monkeypatch.setattr(provenance, "_git", fake_git)
    identity = provenance.build_run_identity(code, {"fixture": dataset})
    assert identity == {
        "code": {"revision": "code-revision", "dirty": False},
        "datasets": {
            "fixture": {"revision": "dataset-revision", "dirty": True}
        },
        "uv_lock_tracked_by_code_revision": True,
    }
    assessment = provenance.assess_claim_eligibility(False, identity)
    assert assessment == {
        "eligible": False,
        "reasons": [
            "the dataset role is not configured for final claims",
            "dataset fixture is dirty",
        ],
    }
