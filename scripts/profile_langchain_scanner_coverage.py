"""Profile parsing and label-free candidate generation on LangChain vulnerable/fixed checkouts."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import sys
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from cv_agent.code_adapters import load_code_repository
from cv_agent.scanner import StaticScanner
from cv_agent.provenance import git_identity


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def covers_reference(candidates, source_path, line):
    return any(candidate.path.split('::', 1)[0] == source_path and candidate.line == line
               for candidate in candidates)


def profile_langchain(output_dir: Path | None = None) -> dict:
    if output_dir is None:
        run_id = uuid4().hex
        output_dir = PROJECT_ROOT / "artifacts/langchain_scanner_coverage" / run_id
    output_dir.mkdir(parents=True, exist_ok=True)

    targets = [
        ("langchain-vulnerable", PROJECT_ROOT / "data/diagnostics/langchain-vulnerable"),
        ("langchain-fixed", PROJECT_ROOT / "data/diagnostics/langchain-fixed"),
    ]

    scanner = StaticScanner()
    summaries = []

    for name, checkout in targets:
        core_dir = checkout / "libs/core"
        identity = git_identity(checkout)
        repo_docs = load_code_repository(name, core_dir)
        candidates = scanner.scan(name, repo_docs.documents)

        # Write candidates
        (output_dir / f"{name}-candidates.json").write_text(
            json.dumps([c.model_dump(mode="json") for c in candidates], indent=2) + "\n"
        )

        # Check if reference sink / entry point is hit
        # GHSA-6qv9-48xg-fc7f reference lines: prompt.py:198 (critical_op), prompt.py:251 (entry_point)
        prompt_candidates = [
            c for c in candidates
            if "prompt.py" in c.path or "string.py" in c.path
        ]

        summary = {
            "name": name,
            "commit": identity.revision,
            "source_files": repo_docs.source_file_count,
            "documents": len(repo_docs.documents),
            "language_files": repo_docs.language_file_counts,
            "adapter_tier_files": repo_docs.adapter_tier_file_counts,
            "parse_error_paths": list(repo_docs.parse_error_paths),
            "candidate_count": len(candidates),
            "prompt_or_string_candidate_count": len(prompt_candidates),
            "covered_reference_sink": covers_reference(candidates, 'langchain_core/prompts/prompt.py', 198),
            "reference_matching": "Exact source path and line; nearby findings are not sink coverage.",
            "detector_used_reference_locations": False,
            "claim_eligible": False,
        }
        summaries.append(summary)

    meta = {
        "started_at": utc_now(),
        "purpose": "Static scanner coverage on LangChain libs/core without reference location leakage",
        "scanner_rules": list(scanner.rule_names),
        "verdict": "REFERENCE_MATCH_OBSERVED" if any(s['covered_reference_sink'] for s in summaries)
                   else "SINK_NOT_COVERED_BY_V0_SCANNER",
        "explanation": (
            "StaticScanner includes Python AST template-call and formatter-dispatch candidates. "
            "These are static hints, including benign and fixed calls, not vulnerability confirmation. "
            "Candidate counts and reference matches are computed for each checkout below."
        ),
    }

    (output_dir / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
    (output_dir / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")

    return {"output_dir": str(output_dir), "meta": meta, "summaries": summaries}


def main() -> None:
    res = profile_langchain()
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
