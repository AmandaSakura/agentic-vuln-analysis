from __future__ import annotations

import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .datasets import load_vulngym_entries


SELECTED_REPOSITORIES = (
    "https://github.com/google/adk-python",
    "https://github.com/PrefectHQ/fastmcp",
    "https://github.com/jlowin/fastmcp",
)


@dataclass(frozen=True)
class SubjectSelection:
    repository_url: str
    commit: str
    entry_ids: tuple[str, ...]

    @property
    def slug(self) -> str:
        parsed = urlparse(self.repository_url)
        parts = [part for part in parsed.path.removesuffix(".git").split("/") if part]
        if parsed.scheme != "https" or parsed.netloc != "github.com" or len(parts) != 2:
            raise ValueError(f"unsupported subject repository URL: {self.repository_url}")
        return f"{parts[0]}__{parts[1]}"


def select_vulngym_subjects(entries_path: Path) -> list[SubjectSelection]:
    """Choose one high-density verified commit per explicitly selected repository."""

    cases, labels = load_vulngym_entries(entries_path)
    cases_by_id = {case.case_id: case for case in cases}
    grouped: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for case_id, label in labels.items():
        if not label.verify:
            continue
        detector_case = cases_by_id[case_id]
        if detector_case.repository_url in SELECTED_REPOSITORIES:
            grouped[detector_case.repository_url][detector_case.commit].append(case_id)

    selections: list[SubjectSelection] = []
    for repository_url in SELECTED_REPOSITORIES:
        commits = grouped.get(repository_url)
        if not commits:
            raise ValueError(f"selected repository has no verified VulnGym entries: {repository_url}")
        commit, entry_ids = min(
            commits.items(),
            key=lambda item: (-len(item[1]), item[0]),
        )
        selections.append(
            SubjectSelection(
                repository_url=repository_url,
                commit=commit,
                entry_ids=tuple(sorted(entry_ids)),
            )
        )
    return selections


def describe_vulngym_subjects(raw_root: Path) -> dict[str, object]:
    selections = select_vulngym_subjects(raw_root / "VulnGym" / "data" / "entries.jsonl")
    return {
        "selection_policy": "one commit with the most verified entries per explicit Python repository",
        "repository_count": len(selections),
        "entry_count": sum(len(selection.entry_ids) for selection in selections),
        "subjects": [
            {
                "repository_url": selection.repository_url,
                "commit": selection.commit,
                "verified_entry_count": len(selection.entry_ids),
            }
            for selection in selections
        ],
    }


def _run_git(arguments: list[str], *, timeout: int = 300) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=None,
        timeout=timeout,
    )
    return completed.stdout.strip()


def _subject_paths(data_root: Path, selection: SubjectSelection) -> tuple[Path, Path]:
    absolute_data_root = data_root.resolve()
    return (
        absolute_data_root / "git-cache" / selection.slug,
        absolute_data_root / "subjects" / selection.slug / selection.commit,
    )


def fetch_vulngym_subjects(data_root: Path) -> dict[str, object]:
    data_root = data_root.resolve()
    selections = select_vulngym_subjects(
        data_root / "raw" / "VulnGym" / "data" / "entries.jsonl"
    )
    cache_root = data_root / "git-cache"
    checkout_root = data_root / "subjects"
    cache_root.mkdir(parents=True, exist_ok=True)
    checkout_root.mkdir(parents=True, exist_ok=True)

    fetched: list[dict[str, object]] = []
    for selection in selections:
        cache_path, checkout_path = _subject_paths(data_root, selection)
        if not cache_path.exists():
            _run_git(
                [
                    "clone",
                    "--filter=blob:none",
                    "--no-checkout",
                    "--depth=1",
                    selection.repository_url,
                    str(cache_path),
                ]
            )
        elif not (cache_path / ".git").is_dir():
            raise RuntimeError(f"subject cache exists but is not a Git repository: {cache_path}")

        if checkout_path.exists():
            actual_commit = _run_git(["-C", str(checkout_path), "rev-parse", "HEAD"])
            if actual_commit != selection.commit:
                raise RuntimeError(
                    f"existing subject checkout has wrong commit: {checkout_path}: {actual_commit}"
                )
        else:
            checkout_path.parent.mkdir(parents=True, exist_ok=True)
            _run_git(
                ["-C", str(cache_path), "fetch", "--depth=1", "origin", selection.commit]
            )
            _run_git(
                [
                    "-C",
                    str(cache_path),
                    "-c",
                    "advice.detachedHead=false",
                    "worktree",
                    "add",
                    "--detach",
                    str(checkout_path),
                    selection.commit,
                ]
            )

        actual_commit = _run_git(["-C", str(checkout_path), "rev-parse", "HEAD"])
        fetched.append(
            {
                "repository_url": selection.repository_url,
                "commit": actual_commit,
                "verified_entry_count": len(selection.entry_ids),
                "checkout": checkout_path.relative_to(data_root.parent).as_posix(),
            }
        )
    return {"repository_count": len(fetched), "subjects": fetched}
