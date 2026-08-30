import json
from pathlib import Path

import cv_agent.vulngym_subset as subset


def _row(entry_id: str, repository_url: str, commit: str, verify: int) -> dict:
    return {
        "entry_id": entry_id,
        "repo_url": repository_url,
        "commit": commit,
        "report_id": f"report-{entry_id}",
        "verify": verify,
        "entry_point": {"file": "api.py", "line": 1, "code": "entry()"},
        "critical_operation": {"file": "sink.py", "line": 2, "code": "sink()"},
        "trace": [],
    }


def test_selection_prefers_commit_with_most_verified_entries(tmp_path: Path, monkeypatch):
    repo = "https://github.com/example/project"
    monkeypatch.setattr(subset, "SELECTED_REPOSITORIES", (repo,))
    rows = [
        _row("entry-1", repo, "a" * 40, 1),
        _row("entry-2", repo, "b" * 40, 1),
        _row("entry-3", repo, "b" * 40, 1),
        _row("entry-4", repo, "c" * 40, 0),
    ]
    entries = tmp_path / "entries.jsonl"
    entries.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    selections = subset.select_vulngym_subjects(entries)

    assert selections == [
        subset.SubjectSelection(
            repository_url=repo,
            commit="b" * 40,
            entry_ids=("entry-2", "entry-3"),
        )
    ]
    assert selections[0].slug == "example__project"


def test_selection_breaks_equal_count_ties_by_commit(tmp_path: Path, monkeypatch):
    repo = "https://github.com/example/project"
    monkeypatch.setattr(subset, "SELECTED_REPOSITORIES", (repo,))
    rows = [
        _row("entry-1", repo, "b" * 40, 1),
        _row("entry-2", repo, "a" * 40, 1),
    ]
    entries = tmp_path / "entries.jsonl"
    entries.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    assert subset.select_vulngym_subjects(entries)[0].commit == "a" * 40


def test_subject_git_paths_are_absolute(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    selection = subset.SubjectSelection(
        repository_url="https://github.com/example/project",
        commit="a" * 40,
        entry_ids=("entry-1",),
    )

    cache_path, checkout_path = subset._subject_paths(Path("data"), selection)

    assert cache_path == tmp_path / "data" / "git-cache" / "example__project"
    assert checkout_path == (
        tmp_path / "data" / "subjects" / "example__project" / ("a" * 40)
    )
