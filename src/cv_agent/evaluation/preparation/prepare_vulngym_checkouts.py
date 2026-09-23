"""Materialize label-free, pinned VulnGym source checkouts with Git worktrees."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from cv_agent.evaluation.datasets.heldout_manifest import repository_key
from cv_agent.runtime.paths import PROJECT_ROOT
from cv_agent.runtime.provenance import git_identity


def repository_slug(repository_url: str) -> str:
    owner, repository = urlparse(repository_key(repository_url)).path.strip("/").split("/")
    return f"{owner}__{repository}"


def run_git(arguments: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=cwd, check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600,
    )
    return result.stdout.strip()


def ensure_repository_cache(repository_url: str, cache_root: Path) -> Path:
    cache_root.mkdir(parents=True, exist_ok=True)
    cache = cache_root / repository_slug(repository_url)
    if not cache.exists():
        with tempfile.TemporaryDirectory(prefix="vulngym-cache-", dir=cache_root) as temporary:
            staged = Path(temporary) / "repository"
            run_git(["clone", "--filter=blob:none", "--no-checkout", "--no-tags",
                     "--depth=1", repository_url, str(staged)])
            os.replace(staged, cache)
    if not (cache / ".git").exists():
        raise ValueError(f"Repository cache is incomplete: {cache}")
    actual_url = repository_key(run_git(["remote", "get-url", "origin"], cwd=cache))
    if actual_url != repository_key(repository_url):
        raise ValueError(f"Repository cache origin mismatch: {cache}")
    return cache


def ensure_checkout(repository_url: str, commit: str, cache_root: Path,
                    checkout_root: Path) -> Path:
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise ValueError(f"Invalid pinned commit: {commit}")
    cache = ensure_repository_cache(repository_url, cache_root)
    run_git(["fetch", "--filter=blob:none", "--depth=1", "origin", commit], cwd=cache)
    fetched = run_git(["rev-parse", "FETCH_HEAD"], cwd=cache)
    if fetched != commit:
        raise ValueError(f"Fetched commit mismatch: expected {commit}, got {fetched}")

    checkout = checkout_root / repository_slug(repository_url) / commit
    if not checkout.exists():
        checkout.parent.mkdir(parents=True, exist_ok=True)
        run_git(["worktree", "add", "--detach", str(checkout), commit], cwd=cache)
    identity = git_identity(checkout)
    if identity.revision != commit or identity.dirty:
        raise ValueError(f"Pinned source checkout is not clean: {checkout}")
    return checkout


def remove_checkout(repository_url: str, commit: str, cache_root: Path,
                    checkout_root: Path) -> None:
    checkout = checkout_root / repository_slug(repository_url) / commit
    if not checkout.exists():
        return
    identity = git_identity(checkout)
    if identity.revision != commit or identity.dirty:
        raise ValueError(f"Refusing to remove a changed source checkout: {checkout}")
    cache = cache_root / repository_slug(repository_url)
    run_git(["worktree", "remove", str(checkout)], cwd=cache)


def prepare_all(manifest_path: Path, *, root: Path = PROJECT_ROOT) -> dict:
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("claim_eligible") is not False:
        raise ValueError("This positive-only source manifest cannot be claim eligible")
    cache_root = root / "data/vulngym-evaluation-git"
    prepared = []
    repositories = set()
    seen = set()
    for subject in manifest["subjects"]:
        identity = (repository_key(subject["repository_url"]), subject["commit"])
        if identity in seen:
            raise ValueError(f"Duplicate repository/commit subject: {identity}")
        seen.add(identity)
        if identity[0] not in repositories:
            ensure_repository_cache(identity[0], cache_root)
            repositories.add(identity[0])
        prepared.append(subject)
        print(f"cached source {len(seen)}/{len(manifest['subjects'])}: {identity[0]}@{identity[1]}", flush=True)
    return {
        "dataset_identity": manifest["dataset_identity"],
        "claim_eligible": False,
        "subjects": len(prepared),
        "repositories": sorted(repositories),
        "checkout_policy": "Create one exact-commit worktree during discovery and remove it after hashing the source inventory.",
    }


if __name__ == "__main__":
    result = prepare_all(PROJECT_ROOT / "configs/datasets/vulngym_heldout_inputs_v4.json")
    output = PROJECT_ROOT / "artifacts/vulngym_heldout_preparation_v4/caches.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(result, indent=2) + "\n"
    if output.exists() and output.read_text() != rendered:
        raise FileExistsError(f"Refusing to replace a different checkout manifest: {output}")
    if not output.exists():
        output.write_text(rendered)
    print(output)
