# Product Recovery v2 Implementation Plan

> **For agentic workers:** Execute the explicitly requested repair using the existing collaboration tools, separate file ownership, and observable before/after tests. This repository keeps plans in `.hermes/plans/`; do not create a new documentation root or discard existing dirty changes.

**Goal:** Follow every F01–F22/R00–R17/V01–V60 feedback item and deliver a reproducible, bounded local static trial with complete evidence and actionable review output; retain missing user/human inputs as unmeasured.

**Architecture:** Keep `product_triage_v1` and historic E1–E5/GP/G-A unchanged. Add explicitly selected `product_triage_v2`: sealed byte snapshot, exact operation candidates, existing static tools and shared admission, durable local records, independent summaries, and no-replace package commit. Default v1 remains until user task and human benefit gates pass. No target execution, model, scratch, native build, remote service or automatic patching.

**Tech Stack:** Locked Python/uv/Pydantic/AST, existing tool registry, Linux renameat2/RLIMIT, JSON/Markdown and locally sealed wheels; no dependency upgrades or network installs.

## Baseline and dependencies

- [x] Read all 31 PDF pages, preserve PDF hash and original 47-page report. Save feedback text and 502-file baseline snapshot under `artifacts/design_review_recovery_20261001/`.
- [x] Read `AGENTS.md` and the existing semantic/test contract. Ask only for actual failed command/log and intended review task; absent input does not prove user's incident reproduced.
- [x] R00: record user incident separately from reproducible code defects. Source/version is identified; the actual user's failed command/log remains `NOT_REPRODUCED_MISSING_INPUT` and is not replaced with synthetic failures.
- [x] R01/R02 engineering component: offline fixed wheel in two external clean environments, no repo/PYTHONPATH/pytest/evaluation/langgraph/live transport; console positive/negative/unknown and failure paths. Actual user environment remains unmeasured. Local repacked dependency wheels are explicitly not upstream-identical containers.

## File ownership and concrete changes

1. R03/R04/R09: `application/source_snapshot.py`, `application/operations.py`, optional snapshot in `agents/discovery.py` and `application/context.py`, bounded `code_adapters/source_files.py`. Sealed bytes generate text/AST/snippets. Exact locator is source path + line/UTF8 columns + node/rule/source version. v1 IDs unchanged. Actual context grant precedes reanalysis; do not invent a cache if existing behavior works.
2. R05/R06: readonly `AcceptanceDecision` in `agents/evidence_policy.py` wraps existing semantics; `application/evidence.py` uses the same qualification. `application/local_evidence.py` writes actual producer records with fsync, validates file/producer/subject/context/completeness before reduction. Failed material persistence cannot expose one-sided proof. Summary capacity is not proof capacity.
3. R07/R10: `domain/product_result_v2.py`, `application/service_v2.py` (including the small local/share renderers). Explicit schema v2; independent analysis/persistence/admission/summary states. Preserve all candidates; CONFLICT counted as evidence but not resolved. Review actions specify owner/input/location/reanalysis/done condition. Public reports contain no source; private local view validates snapshot before showing exact text. Actual human use is separate and unmeasured.
4. R08: `domain/types.py` public update reconstructs declared fields and validates the whole model. Existing constructors, valid copies and sealed aliases remain controls; trusted low-level reflection is outside the claim.
5. R11: `presentation/commit.py`, shared exporter plus v2 bundle validator. Existing/raced outputs cannot be replaced. Files/dirs synced before rename, parent synced after; postcommit completion is explicitly nonauthority.
6. R12: `application/product_boundary.py`: fixed project worker, reduced credential environment, 120s/1GiB Linux limits; source limits 1000 files/10MiB/1000 candidates/200000 AST nodes/64MiB evidence. These are frozen trial caps, not measured guarantees. Failed/unknown denominators are explicit. Profile scales 100/500/1000 own files, count digest/serialization repetition before optimization.
7. R13: existing graph16 remains; characterize 8-task topologies, expert restoration/one ballot/producers/conflicts and all costs. No speculative limit increase or historical rewrites.
8. R14/R15/R16/R17: fresh neutral controls have private separate references; machine-designed controls do not impersonate human evaluation. Actual authorized repositories and nonimplementing human reviewers are missing until supplied. Seal trial source/wheel/install receipts; do not release a value-validated product or enable optional models.

## Test-first behaviors

Before each confirmed semantic repair capture actual command/exit/log SHA. Features absent at baseline are marked feature gaps, not reproduced vulnerabilities. Examples below are executable behavioral cases with positive counterparts:

```python
def test_public_copy_cannot_bypass_line_validation(candidate):
    import pytest
    with pytest.raises(ValueError):
        candidate.model_copy(update={"line": 0})
    assert candidate.model_copy(update={"line": 2}).line == 2

def test_summary_does_not_change_local_property(run_owned_v2):
    a = run_owned_v2(summary_bytes=8192)
    b = run_owned_v2(summary_bytes=1)
    assert [f.property_state for f in a.findings] == [f.property_state for f in b.findings]
    assert b.counts.analysis_completed == b.counts.candidate_total

def test_existing_output_never_replaced(tmp_path, commit_directory):
    import pytest
    source, target = tmp_path / "staging", tmp_path / "result"
    source.mkdir(); target.mkdir()
    (source / "result.json").write_text("new")
    with pytest.raises(FileExistsError):
        commit_directory(source, target)
    assert list(target.iterdir()) == []
```

Concrete suites: `tests/test_recovery_model_copy.py`, `test_recovery_snapshot_operations.py`, `test_recovery_commit.py`, `test_recovery_local_evidence.py`, `test_recovery_graph_paths.py`, `test_recovery_product_v2.py`, `test_recovery_resource_boundary.py`. Existing admission positive controls stay; no test assertion is dropped to satisfy this report.

## Public migration and complete accounting

```text
cv-agent review SOURCE --output NEW                       -> existing v1
cv-agent review SOURCE --output NEW --profile product_triage_v2 --summary-bytes 8192
cv-agent verify NEW                                      -> private local package consistency/semantic replay
cv-agent view NEW --candidate-id ID --source-root SOURCE -> verify identity then exact local operation
```

For v2, `--observation-bytes` is an explicit ambiguity error. Summary-only share has `verification_availability=NOT_VERIFIABLE` and no standalone strong property assertion. Local proof authority requires complete accessible records and registered analyzer semantics, not user-supplied hashes. Identity separates source/semantic engine/analysis view/delivery policy. Source-root drift rejects local navigation. Recompute manifest, records, refs/counts and static decisions without executing source.

Counts:

```text
candidate_total = analysis_not_started + analysis_completed + analysis_blocked + analysis_failed
property_total = supported + refuted + unknown + conflict
resolved_without_conflict = supported + refuted
has_sufficient_evidence = supported + refuted + conflict
```

## Validation and delivery

- [x] Run named regressions and affected existing tests, record failures as failures. Final affected controls: 99 passed; additional first-fact retention, output-stage and count regressions have their failing logs preserved.
- [x] Final typed-receipt patch2: third complete `uv run --no-sync pytest` **2941 passed in 422.98s**, exit 0; harness PASS; 423 src/tests hashes unchanged. Prior patch1 **2940 passed in 427.22s** remains historical. The concurrently edited initial baseline remains characterization.
- [x] Rebuild typed-receipt `release-final-patch2`, install in two clean external directories, run actual console v1/v2/verify/view and neutral quality controls; 104 source files bind the new revision. Third whole-suite freeze is separate. 36 new-version engineering controls: 22 exact state matches, 0 wrong strong states, 14 unsupported named modes, unchanged references. Prior patch1 retained.
- [x] Preserve all old reports, final-summary, datasets/configs and historical ledgers. Final mechanical comparison: 45 old report/source artifacts and 73 config/script files unchanged. No new real API call or target execution experiment.
- [x] Write F01–F22/R00–R17/V01–V60 individually with actual references and bounded PASS/partial/NOT_RUN classifications. Missing humans do not count as software success. PR0 user incident/PR1 human quality/PR2 actual task/PR3 human value retain explicit missing input.
- [x] Update existing product guide/current navigation with exact installation, supported constructs, trial limits, recovery/rollback and remaining external measurements. Local archive supplies rollback; unrelated initial dirty changes are preserved without a blanket commit.

## Additional demonstrated integration defects

The final v2 fault controls reproduced evidence reread failure dropping prior completed facts, unexpected analyzer exceptions starting later tools, missing presentation-stage diagnostics, and contradictory persisted counts accepted by the DTO. Fixes retain earlier proof, stop later work, preserve private stages, and reject contradictory copies. `tests/test_recovery_v2_failures.py` contains positive controls; the before logs remain under `artifacts/design_review_recovery_20261001/`.

`verify` regenerates syntax metadata and the complete enumerated operation inventory from sealed bytes. Read-only verify/view are still in the CLI process and do not inherit review's worker limits. Packaging authenticates no external producer. The new `recovery-protocol.json` freezes future human-trial targets, not measurements; PR0 user-task, PR1 human quality, PR2/PR3 value remain incomplete.

R17 remains NOT_ENABLED; original G-A=NO, GP2 not enabled and GP3/GP4 not measured.
