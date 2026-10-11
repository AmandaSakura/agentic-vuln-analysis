"""Human-readable offline results with an atomic two-artifact commit."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import time

from cv_agent.domain.product_result import ReviewResult
from cv_agent.presentation.commit import commit_directory, fsync_directory


def render_report(result: ReviewResult) -> str:
    rows = ["# cv-agent offline source review", "", f"Run state: {result.run_state}",
        f"Profile: {result.profile_id}", "Model requests: 0", "Target executions: 0", "",
        "Application security: NOT_ASSESSED. Public entry reachability and remote authority are not evaluated.",
        "", f"Source files: {result.counts.source_files}; parsed: {result.counts.parsed_files}; "
        f"parse errors: {result.counts.parse_errors}; candidates: {result.counts.candidate_count}; "
        f"complete property evidence: {result.counts.sufficient_evidence_candidates}.",
        f"Delivered observation bytes: {result.accounting.observation_bytes}; context bytes: {result.accounting.context_bytes}.",
        f"Source identity (source-bytes-v1): {result.identity.source_digest}", ""]
    if not result.findings:
        rows += ["No candidates were discovered within the supported indexed source scope. "
                 "This is not a whole-application security verdict.", ""]
    for finding in result.findings:
        rows += [f"## {finding.candidate_id}", "", f"Location: {finding.subject.entry_path}:"
                 f"{finding.subject.entry_line or '?'}", f"Property: {finding.contract.property_id}",
                 f"Property state: {finding.property_state}",
                 f"Predicate: {finding.contract.predicate}",
                 f"Scope: {finding.subject.analysis_scope or 'Declared candidate only.'}", ""]
        for title, values in (("Established observations", finding.facts),
                              ("Missing obligations", finding.missing_obligations),
                              ("Next steps", finding.next_steps), ("Evidence references", finding.evidence_refs)):
            rows += [f"{title}:", "", *[f"- {value}" for value in values], ""]
    rows += ["## Capabilities", "", "| Method | State | Required | Reason |",
             "| --- | --- | --- | --- |"]
    rows += [f"| {c.method} | {c.state} | {c.required} | {c.reason_code} |" for c in result.capabilities]
    rows += ["", "## Diagnoses", ""]
    rows += [f"- {d.reason_code} ({d.stage}, owner: {d.owner}, retry: {d.retry_policy}): {d.message}"
             for d in result.diagnoses] or ["No operational diagnosis."]
    return "\n".join(rows).rstrip() + "\n"


def export_result(result: ReviewResult, output: Path, *, private_records=()) -> ReviewResult:
    started = time.monotonic()
    if output.exists() or output.is_symlink():
        raise FileExistsError("Output path already exists; select a new run directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    try:
        private = staging / ".private"
        private.mkdir(mode=0o700)
        with (private / "observations.jsonl").open("w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            for record in private_records:
                stream.write(json.dumps(record, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        # Output time covers serialization/staging preparation up to the final
        # commit. The durable completion receipt below includes commit latency.
        render_report(result)
        json.dumps(result.model_dump(mode="json"), sort_keys=True, ensure_ascii=False, allow_nan=False)
        elapsed = time.monotonic() - started
        result = result.model_copy(update={"accounting": result.accounting.model_copy(update={
            "output_seconds": elapsed, "total_seconds": result.accounting.total_seconds + elapsed})})
        for name, content in (("result.json", json.dumps(result.model_dump(mode="json"),
                sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + "\n"),
                              ("report.md", render_report(result))):
            with (staging / name).open("w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        # Kernel-enforced no-replace publication commits the staged set together.
        commit_directory(staging, output)
        # Completion timing is an optional diagnostic outside proof authority.
        # Its failure cannot undo an already committed result or alter evidence.
        try:
            with (output / ".private/completion.json").open("w", encoding="utf-8") as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump({"run_id": result.run_id, "output_wall_seconds": time.monotonic()-started,
                           "model_requests": 0, "authoritative": False,
                           "role": "postcommit-diagnostic"}, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            fsync_directory(output / ".private")
        except OSError:
            pass
        return result
    finally:
        if staging.exists():
            shutil.rmtree(staging)
