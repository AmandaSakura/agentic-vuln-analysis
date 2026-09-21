"""Freeze Python held-out advisory pairs with GitHub-advisory fixed commits."""
from __future__ import annotations

from cv_agent.runtime.paths import PROJECT_ROOT

import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from cv_agent.evaluation.datasets.github_advisory import advisory_commit_urls, advisory_versions, fetch_advisory_html
from cv_agent.evaluation.datasets.heldout_manifest import repository_key
from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairExperimentConfig, is_supported_heldout_source_path
from cv_agent.runtime.provenance import git_identity

LABELS_PATH = PROJECT_ROOT / "artifacts/vulngym_heldout_preparation_v3/labels.json"
INPUTS_PATH = PROJECT_ROOT / "configs/datasets/vulngym_heldout_inputs_v3.json"
CONFIG_PATH = PROJECT_ROOT / "configs/history/python_heldout_pairs_v2.json"
MANIFEST_PATH = PROJECT_ROOT / "artifacts/python_heldout_pair_preparation_v2/manifest.json"
HTML_CACHE = PROJECT_ROOT / "artifacts/python_heldout_pair_preparation_v2/advisory_html"
GIT_CACHE = PROJECT_ROOT / "data/heldout-pair-git"
CHECKOUT_ROOT = PROJECT_ROOT / "data/heldout-pair-subjects"

PYTHON_REPOSITORIES = {
    "https://github.com/apache/airflow",
    "https://github.com/mlflow/mlflow",
    "https://github.com/langflow-ai/langflow",
    "https://github.com/BerriAI/litellm",
    "https://github.com/NVIDIA/NeMo",
    "https://github.com/open-webui/open-webui",
    "https://github.com/Significant-Gravitas/AutoGPT",
}

EXCLUDE_PATH_PARTS = ("tests", "test", "testing", "docs", "examples", "__pycache__")


def save_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if path.exists():
        if path.read_text() != content:
            raise FileExistsError(f"Frozen file differs from regenerated content: {path}")
        return
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content)
    temporary.replace(path)


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def first_line(value) -> int:
    match = re.search(r"[0-9]+", str(value))
    if not match:
        raise ValueError(f"Line hint is missing: {value!r}")
    return int(match.group(0))


def repo_slug(repository_url: str) -> str:
    parsed = urlparse(repository_key(repository_url))
    owner, repo = parsed.path.strip("/").split("/")
    return f"{owner}__{repo}"


def run_git(arguments: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
    )
    return result.stdout.strip()


def ensure_repo_cache(repository_url: str) -> Path:
    GIT_CACHE.mkdir(parents=True, exist_ok=True)
    cache = GIT_CACHE / repo_slug(repository_url)
    if not cache.exists():
        run_git(["clone", "--filter=blob:none", "--no-checkout", repository_url, str(cache)])
    return cache


def ensure_checkout(repository_url: str, commit: str) -> str:
    cache = ensure_repo_cache(repository_url)
    run_git(["fetch", "--filter=blob:none", "origin", commit], cwd=cache)
    checkout = CHECKOUT_ROOT / repo_slug(repository_url) / commit
    if not checkout.exists():
        checkout.parent.mkdir(parents=True, exist_ok=True)
        run_git(["worktree", "add", "--detach", str(checkout), commit], cwd=cache)
    identity = git_identity(checkout)
    if identity.revision != commit or identity.dirty:
        raise ValueError(f"Checkout is not the pinned clean commit: {checkout}")
    return checkout.relative_to(PROJECT_ROOT).as_posix()


def verify_ancestry(repository_url: str, vulnerable_commit: str, fixed_commit: str) -> bool:
    cache = ensure_repo_cache(repository_url)
    try:
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", vulnerable_commit, fixed_commit],
            cwd=cache,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def commit_sha(commit_url: str) -> str:
    match = re.search(r"/commit/([0-9a-f]{40})(?:$|[?#])", commit_url, re.I)
    if not match:
        raise ValueError(f"Commit URL lacks a full SHA: {commit_url}")
    return match.group(1).lower()


def commit_changed_paths(repository_url: str, commit: str) -> tuple[str, ...]:
    cache = ensure_repo_cache(repository_url)
    output = run_git(["show", "--format=", "--name-only", commit], cwd=cache)
    return tuple(sorted(path for path in output.splitlines() if path.strip()))


def candidate_evidence_files(row: dict) -> tuple[str, ...]:
    paths: list[str] = []
    for key in ("entry_point", "critical_operation"):
        path = row[key]["file"]
        if is_supported_heldout_source_path(path) and path not in paths:
            paths.append(path)
    return tuple(paths)


def read_checkout_text(checkout: str, file_path: str) -> str | None:
    path = PROJECT_ROOT / checkout / file_path
    if not path.is_file():
        return None
    return path.read_text(errors="ignore")


def normalized_contains(text: str, snippet: str) -> bool:
    compact_text = re.sub(r"\s+", " ", text)
    compact_snippet = re.sub(r"\s+", " ", str(snippet).strip())
    return bool(compact_snippet) and compact_snippet in compact_text


def scope_mentions_path(row: dict, path: str) -> bool:
    haystack = " ".join(
        str(value)
        for value in (
            row["vuln_title"],
            candidate_source_scope(row),
            candidate_analysis_scope(row),
            row["entry_point"].get("desc", ""),
            row["critical_operation"].get("desc", ""),
        )
    )
    basename = PurePosixPath(path).name
    generic_basenames = {"__init__.py", "config.py", "utils.py", "main.py", "cli.py"}
    return path in haystack or (basename not in generic_basenames and basename in haystack)


def fixed_commit_repair_evidence(
    row: dict,
    *,
    repository_url: str,
    vulnerable_checkout: str,
    fixed_checkout: str,
    fixed_commit: str,
) -> dict:
    changed_paths = commit_changed_paths(repository_url, fixed_commit)
    evidence_files = candidate_evidence_files(row)
    touched_evidence = tuple(path for path in evidence_files if path in changed_paths)
    mentioned_changed_paths = tuple(
        path for path in changed_paths if path not in evidence_files and scope_mentions_path(row, path)
    )
    if not touched_evidence and not mentioned_changed_paths:
        return {
            "verified": False,
            "reason": "fixed_commit_does_not_touch_candidate_or_scope",
            "changed_paths": changed_paths,
            "candidate_evidence_files": evidence_files,
        }

    matched_snippets: list[dict] = []
    changed_snippets: list[dict] = []
    unchanged_snippets: list[dict] = []
    for key in ("entry_point", "critical_operation"):
        file_path = row[key]["file"]
        if file_path not in evidence_files:
            continue
        vulnerable_text = read_checkout_text(vulnerable_checkout, file_path)
        fixed_text = read_checkout_text(fixed_checkout, file_path)
        snippet = row[key]["code"]
        if vulnerable_text is None or fixed_text is None:
            return {
                "verified": False,
                "reason": "candidate_evidence_file_missing",
                "file_path": file_path,
                "changed_paths": changed_paths,
                "candidate_evidence_files": evidence_files,
            }
        if normalized_contains(vulnerable_text, snippet):
            item = {"field": key, "file": file_path}
            matched_snippets.append(item)
            if normalized_contains(fixed_text, snippet):
                unchanged_snippets.append(item)
            elif file_path in touched_evidence:
                changed_snippets.append(item)

    if not matched_snippets:
        return {
            "verified": False,
            "reason": "candidate_source_snippet_not_found",
            "changed_paths": changed_paths,
            "candidate_evidence_files": evidence_files,
        }

    changed_scope_files: list[str] = []
    for path in mentioned_changed_paths:
        vulnerable_text = read_checkout_text(vulnerable_checkout, path)
        fixed_text = read_checkout_text(fixed_checkout, path)
        if vulnerable_text is not None and fixed_text is not None and vulnerable_text != fixed_text:
            changed_scope_files.append(path)

    if not changed_snippets and not changed_scope_files:
        return {
            "verified": False,
            "reason": "fixed_candidate_not_repaired",
            "changed_paths": changed_paths,
            "candidate_evidence_files": evidence_files,
            "unchanged_snippets": unchanged_snippets,
        }

    return {
        "verified": True,
        "reason": "candidate_specific_repair_observed",
        "changed_paths": changed_paths,
        "candidate_evidence_files": evidence_files,
        "touched_evidence_files": touched_evidence,
        "mentioned_changed_paths": mentioned_changed_paths,
        "changed_scope_files": tuple(changed_scope_files),
        "matched_snippets": tuple(matched_snippets),
        "changed_snippets": tuple(changed_snippets),
        "unchanged_snippets": tuple(unchanged_snippets),
    }


def choose_fixed_commit(
    row: dict,
    commit_urls: tuple[str, ...],
    vulnerable_checkout: str,
) -> tuple[dict | None, list[dict]]:
    rejected: list[dict] = []
    vulnerable_commit = row["commit"]
    for commit_url in commit_urls:
        fixed_commit = commit_sha(commit_url)
        if fixed_commit == vulnerable_commit:
            rejected.append({"commit_url": commit_url, "reason": "fixed_commit_equals_vulnerable_commit"})
            continue
        fixed_checkout = ensure_checkout(row["repo_url"], fixed_commit)
        file_path = row["critical_operation"]["file"]
        if not (PROJECT_ROOT / fixed_checkout / file_path).is_file():
            rejected.append({"commit_url": commit_url, "reason": "fixed_source_path_missing"})
            continue
        ancestry_verified = verify_ancestry(row["repo_url"], vulnerable_commit, fixed_commit)
        evidence = fixed_commit_repair_evidence(
            row,
            repository_url=row["repo_url"],
            vulnerable_checkout=vulnerable_checkout,
            fixed_checkout=fixed_checkout,
            fixed_commit=fixed_commit,
        )
        if not evidence["verified"]:
            rejected.append({"commit_url": commit_url, **evidence})
            continue
        return {
            "fixed_commit": fixed_commit,
            "fixed_commit_url": commit_url,
            "fixed_checkout": fixed_checkout,
            "ancestry_verified": ancestry_verified,
            "repair_evidence": evidence,
        }, rejected
    return None, rejected


def candidate_source_scope(row: dict) -> str:
    critical = row["critical_operation"]
    entry = row["entry_point"]
    return (
        f"{row['vuln_category_l1']} / {row['vuln_category_l2']} at "
        f"{critical['file']}:{critical['line']}; entry {entry['file']}:{entry['line']}"
    )


def candidate_analysis_scope(row: dict) -> str:
    critical = row["critical_operation"]
    entry = row["entry_point"]
    return (
        "Assess only the advisory-scoped weakness described here for this exact source snapshot. "
        f"Title: {row['vuln_title']}. "
        f"Entry point code: {entry['code']}. "
        f"Critical operation code: {critical['code']}. "
        "Use repository evidence; do not infer the answer from case identity or commit ordering."
    )


def build_pairs(labels: dict[str, dict]) -> tuple[list[dict], list[dict]]:
    report_html: dict[str, str] = {}
    report_commits: dict[str, tuple[str, ...]] = {}
    report_versions: dict[str, dict[str, str | None]] = {}
    skipped: list[dict] = []
    candidates: list[dict] = []
    for entry_id, row in sorted(labels.items()):
        repository = repository_key(row["repo_url"])
        if repository not in {repository_key(url) for url in PYTHON_REPOSITORIES}:
            skipped.append({"entry_id": entry_id, "reason": "not_selected_python_repository"})
            continue
        critical = row["critical_operation"]
        file_path = critical["file"]
        if not is_supported_heldout_source_path(file_path):
            skipped.append({"entry_id": entry_id, "reason": "critical_operation_not_supported_source"})
            continue
        if row["report_id"] not in report_html:
            text = fetch_advisory_html(row["report_id"], row["source_link"], HTML_CACHE)
            report_html[row["report_id"]] = text
            report_commits[row["report_id"]] = advisory_commit_urls(row["repo_url"], text)
            report_versions[row["report_id"]] = advisory_versions(text)
        commit_urls = report_commits[row["report_id"]]
        if not commit_urls:
            skipped.append({"entry_id": entry_id, "reason": "advisory_has_no_same_repository_commit"})
            continue
        vulnerable_commit = row["commit"]
        vulnerable_checkout = ensure_checkout(row["repo_url"], vulnerable_commit)
        source = PROJECT_ROOT / vulnerable_checkout / file_path
        if not source.is_file():
            skipped.append({"entry_id": entry_id, "reason": "vulnerable_source_path_missing"})
            continue
        selected, rejected = choose_fixed_commit(row, commit_urls, vulnerable_checkout)
        if selected is None:
            skipped.append({
                "entry_id": entry_id,
                "reason": "no_candidate_specific_fixed_commit",
                "rejected_fixed_commits": rejected,
            })
            continue
        candidates.append(
            {
                "entry_id": entry_id,
                "row": row,
                "fixed_commit": selected["fixed_commit"],
                "fixed_commit_url": selected["fixed_commit_url"],
                "vulnerable_checkout": vulnerable_checkout,
                "fixed_checkout": selected["fixed_checkout"],
                "advisory_versions": report_versions[row["report_id"]],
                "ancestry_verified": selected["ancestry_verified"],
                "repair_evidence": selected["repair_evidence"],
                "rejected_fixed_commits": rejected,
            }
        )
    return candidates, skipped


def freeze(labels: dict[str, dict]) -> tuple[dict, dict]:
    candidates, skipped = build_pairs(labels)
    pairs: list[dict] = []
    manifest_pairs: list[dict] = []
    for index, candidate in enumerate(candidates, start=1):
        row = candidate["row"]
        pair_id = f"hp{index:03d}_{slug(row['entry_id'])}_{slug(row['report_id'])}"
        case_prefix = f"hp{index:03d}"
        file_path = row["critical_operation"]["file"]
        line_hint = first_line(row["critical_operation"]["line"])
        common = {
            "file_path": file_path,
            "line_hint": line_hint,
        }
        vulnerable_case = {
            "case_id": f"{case_prefix}_a",
            "revision_role": "vulnerable",
            "commit": row["commit"],
            "checkout": candidate["vulnerable_checkout"],
            **common,
        }
        fixed_case = {
            "case_id": f"{case_prefix}_b",
            "revision_role": "fixed",
            "commit": candidate["fixed_commit"],
            "checkout": candidate["fixed_checkout"],
            **common,
        }
        pair = {
            "pair_id": pair_id,
            "entry_id": row["entry_id"],
            "repository_url": row["repo_url"],
            "advisory": row["report_id"],
            "source_link": row["source_link"],
            "vuln_ids": row["vuln_ids"],
            "source_root": ".",
            "exclude_path_parts": EXCLUDE_PATH_PARTS,
            "vulnerability_title": row["vuln_title"],
            "source_scope": candidate_source_scope(row),
            "analysis_scope": candidate_analysis_scope(row),
            "entry_point": row["entry_point"],
            "critical_operation": row["critical_operation"],
            "cases": [vulnerable_case, fixed_case],
        }
        pairs.append(pair)
        manifest_pairs.append(
            {
                "pair_id": pair_id,
                "entry_id": row["entry_id"],
                "repository_url": row["repo_url"],
                "advisory": row["report_id"],
                "source_link": row["source_link"],
                "fixed_commit_url": candidate["fixed_commit_url"],
                "advisory_versions": candidate["advisory_versions"],
                "ancestry_verified": candidate["ancestry_verified"],
                "repair_evidence": candidate["repair_evidence"],
                "rejected_fixed_commits": candidate["rejected_fixed_commits"],
                "vulnerable_case": vulnerable_case,
                "fixed_case": fixed_case,
                "critical_operation": row["critical_operation"],
                "entry_point": row["entry_point"],
            }
        )
    config = {
        "dataset_name": "Python held-out GitHub advisory paired matrix",
        "dataset_role": "paired_heldout_advisory",
        "claim_eligible": False,
        "model_config": "configs/models/micro_benchmark_gemini_native.json",
        "systems": ["E1", "E2", "E3", "E4", "E5"],
        "concurrency": 1,
        "limits": {"max_requests": 900, "max_seconds": 14400},
        "source_manifest": MANIFEST_PATH.relative_to(PROJECT_ROOT).as_posix(),
        "pairs": pairs,
    }
    manifest = {
        "dataset_role": "paired_heldout_advisory",
        "claim_eligible": False,
        "source_inputs": INPUTS_PATH.relative_to(PROJECT_ROOT).as_posix(),
        "source_labels": LABELS_PATH.relative_to(PROJECT_ROOT).as_posix(),
        "selection_protocol": (
            "All v3 held-out entries in selected Python repositories whose critical operation is a Python file "
            "or supported security-relevant config file and whose GitHub Advisory page contains a same-repository "
            "commit reference with candidate-specific repair evidence. Vulnerable side is the VulnGym commit; "
            "fixed side is the first same-repository advisory commit that touches the candidate evidence files "
            "or an advisory-scoped helper path and passes the repair-evidence gate."
        ),
        "pairs": manifest_pairs,
        "skipped": skipped,
        "summary": {
            "entries_considered": len(labels),
            "pairs": len(pairs),
            "cells": len(pairs) * 10,
            "skipped": len(skipped),
            "repositories": sorted({pair["repository_url"] for pair in pairs}),
            "advisories": sorted({pair["advisory"] for pair in pairs}),
        },
    }
    PythonHeldoutPairExperimentConfig.model_validate(config)
    return config, manifest


def main() -> None:
    labels = json.loads(LABELS_PATH.read_text())
    config, manifest = freeze(labels)
    save_json(MANIFEST_PATH, manifest)
    save_json(CONFIG_PATH, config)
    fingerprint = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    print(json.dumps({"config": str(CONFIG_PATH), "manifest": str(MANIFEST_PATH), "sha256": fingerprint,
                      **manifest["summary"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
