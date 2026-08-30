from __future__ import annotations

import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from .types import FrozenModel


class GitIdentity(FrozenModel):
    revision: str
    dirty: bool


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    return completed.stdout.strip()


def git_identity(repository: Path) -> GitIdentity:
    repository = repository.resolve()
    revision = _git(repository, "rev-parse", "HEAD")
    status = _git(repository, "status", "--porcelain", "--untracked-files=normal")
    return GitIdentity(revision=revision, dirty=bool(status))


def find_project_root(start: Path) -> Path:
    resolved = start.resolve()
    candidates = [resolved, *resolved.parents]
    for candidate in candidates:
        if (candidate / "pyproject.toml").is_file() and (candidate / ".git").exists():
            return candidate
    raise ValueError(f"project Git root not found from {start}")


def build_run_identity(
    project_root: Path,
    datasets: Mapping[str, Path],
) -> dict[str, object]:
    code = git_identity(project_root)
    return {
        "code": code.model_dump(mode="json"),
        "datasets": {
            name: git_identity(path).model_dump(mode="json")
            for name, path in sorted(datasets.items())
        },
        "uv_lock_tracked_by_code_revision": True,
    }


def assess_claim_eligibility(
    configured_eligible: bool,
    run_identity: Mapping[str, object],
) -> dict[str, object]:
    reasons: list[str] = []
    if not configured_eligible:
        reasons.append("the dataset role is not configured for final claims")
    code = cast(Mapping[str, object], run_identity["code"])
    if bool(code["dirty"]):
        reasons.append("the code working tree is dirty")
    datasets = cast(Mapping[str, Mapping[str, object]], run_identity["datasets"])
    for name, identity in datasets.items():
        if bool(identity["dirty"]):
            reasons.append(f"dataset {name} is dirty")
    return {"eligible": not reasons, "reasons": reasons}
