# Python repository discovery and evidence Implementation Plan

> **For agentic workers:** Execute this plan task-by-task in this session. The user has already authorized implementation; preserve the existing dirty work and historical experiment results.

**Goal:** Connect label-free Python repository discovery to bounded agent evaluation and evaluator-only reference scoring, and repair evidence handling that can contaminate expert judgments.

**Architecture:** Keep detector inputs limited to source checkouts and neutral subject identities. Persist the complete candidate inventory before selecting a deterministic bounded pilot. Score frozen results in a separate program that alone reads reference labels. Preserve predictions, abstentions, failures and unreviewed candidates separately.

**Tech Stack:** Python AST, Pydantic, existing LangGraph/ReAct pipeline, pytest, existing native-model transport and request journal.

## Task 1: Source-driven Python discovery

Files: `src/cv_agent/scanner.py`, `src/cv_agent/repository_discovery.py`, `tests/test_repository_discovery.py`, `tests/test_scanner.py`.

- [x] Add behavioral tests for imported aliases, comment/string decoys, module-level calls, overlapping nested function spans, and template dispatch. A `subprocess.run` comment must produce zero candidates; `from subprocess import run as launch; launch(value)` must produce a command candidate. Two overlapping function spans must produce one finding for the same source operation.
- [x] Implement Python AST call classification; retain generic-language heuristics. Add source-derived hypothesis scopes and stable neutral identities. Include module-level source operations and record parse errors.
- [x] Build `discover_python_repository(root, repository_id)` returning index, candidates and a source inventory, without reference labels, entry locations or expected verdicts.
- [x] Run `uv run --no-sync pytest tests/test_scanner.py tests/test_repository_discovery.py`.

## Task 2: Evidence independence and tool access

Files: `src/cv_agent/agentic_workflow.py`, `src/cv_agent/react_engine.py`, `src/cv_agent/consensus.py`, relevant workflow/evidence/quorum tests.

- [x] Demonstrate that an assigned expert currently cannot read an admitted span, that peer dependency conclusions are exposed as voting hints, and that an UNRESOLVED prediction can ignore a contradictory candidate-bound concrete witness.
- [x] Allow repository inspection tools plus the assigned validator, while keeping other validators excluded.
- [x] Pass peer task observations and provenance without peer label/confidence/rationale; retain an expert's own previous judgments for cumulative tasks.
- [x] Reject material conclusions that contradict complete, matching-subject concrete validator evidence. Preserve ABSTAIN for conflicts and ignore unrelated/truncated evidence as proof.
- [x] Reject duplicate-expert ballots at the quorum API; keep positive majority and fixed-ballot fast/full equivalence controls.
- [x] Run targeted workflow, dependency, evidence and consensus tests.

## Task 3: Bounded repository runner and independent scorer

Files: `scripts/run_python_repository_pilot.py`, `configs/python_repository_pilot.json`, `src/cv_agent/discovery_evaluation.py`, `scripts/score_python_repository_pilot.py`, associated tests.

- [x] Test deterministic selection independent of labels, 10-cell cap, missing-results accounting, exact source-location matching, subject/commit isolation, and unknown-negative handling.
- [x] Use existing `run_candidate`, `Journal`, `Budget`, model adapter and full pytest admission. Snapshot detector config, source digests, all candidates and selected candidates before requests. Save results incrementally; do not retry failures or replace them.
- [x] Implement evaluator-only matching by repository, commit and exact critical-operation file/line. Report discovery coverage, detected reference entries/advisories, unknown/unreviewed predictions and parse coverage. Positive-only labels must yield `false_positive_rate: null`.
- [x] Freeze a development-only Python pilot of at most 10 cells; expose the same runner for label-free independent inputs through explicit dedicated configuration, without promoting inspected development data to held-out.

## Task 4: Verification and result record

- [x] Run the full `uv run --no-sync pytest` suite and `uv run --no-sync cv-agent harness-check`.
- [x] Run offline discovery on the real LangChain checkouts and score reference coverage after discovery. Verify that candidate selection never loads evaluator labels.
- [x] Run no more than 10 live cells with explicit request/time bounds; all model calls go through the native adapter and live gate. Read credentials only into the process environment.
- [x] Record actual outcomes, usage, remaining evidence limits and the next independent-evaluation procedure. Do not promise the original 28%/37% targets or revise historical matrices.

## Completion record

Final suite: 452 passed. Ten live cells completed before the final reflection/process-control extension (66 requests, 153,562 reported tokens). The additional two source-rule families were verified offline against synthetic controls and the real source inventories. NLTK was promoted to development data and excluded in split v3. See `docs/PYTHON_REPOSITORY_PIPELINE_2026-09-19.md` for exact artifacts and the configured next independent pilot.
