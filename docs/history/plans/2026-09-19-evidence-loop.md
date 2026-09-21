# Evidence-loop improvement plan

**Goal:** Make the observed model/tool contract terminate honestly and evaluate changes on preserved pilot cases.

**Architecture:** Keep the existing label/evidence gate and shared retrieval budget. Clarify the distinction between a prediction and a validator result, expose static-tool limitations, and reserve the last existing ReAct step for finalization. Improve the evaluation's evidence and cost reporting before any larger run.

**Files:** `src/cv_agent/react_engine.py`, `src/cv_agent/validation_tools.py`, their tests, development runner/configs and pilot documentation.

- [x] Test evidence-contract instructions, finalization under the existing eight-step cap, and unsupported confirmation rejection.
- [x] Implement explicit evidence semantics and finalization without creating synthetic verdicts or bypassing required validators.
- [x] Run regression tests and the same bounded positive/negative pilot; keep failures and run revisions separate.
- [x] Diagnose next observed blocker, implement only evidence-supported changes, then test.
- [x] Extend metrics to separate model predictions from validator-supported judgments and compare E4/E5 only on paired completed runs.
- [x] Record the final operational state, costs, limitations and next reproducible command.

Outcome: 299 regression tests pass; bounded retrieval and Python evidence batches
complete. Provider empty-choice responses remain unresolved after a separately
recorded configuration diagnostic. See `docs/PROJECT_STATUS_2026-09-19.md` for
results, usage and remaining held-out requirements; this checklist does not mean
the full research evaluation is complete.
