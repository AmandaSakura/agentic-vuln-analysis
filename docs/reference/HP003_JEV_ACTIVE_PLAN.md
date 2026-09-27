# hp003 Jev Active Implementation Plan

**Goal:** Run hp003_a/b through E4_JEV active and ordinary E4, recording adopted decisions, LLM escalation, verdicts and usage.

**Architecture:** Reuse the existing Jev runner with an explicit configuration path. Preserve the hp001 shadow configuration and add a fixed hp003 active configuration and direct module launcher. Both arms share the same candidate, indexed source and registered fixtures; Jev replaces only planning when its existing policy accepts the plan.

**Tech Stack:** Python, Pydantic, JSON, Bash, pytest. Execute inline under the user's instruction to start. Keep this plan in the repository's existing reference directory.

## Changes and verification

- [x] Add `configs/experiments/hp003_jev_active.json` with `case_ids=["hp003_a","hp003_b"]`, `systems=["E4_JEV","E4"]`, `mode="active"`, model `jev-1.13.0`, threshold 0.85, 120 requests and 1800 seconds.
- [x] Add offline runner regressions in `tests/test_jev_pilot.py`: exactly four cells, active routing only for E4_JEV, identical index/candidate/fixtures for both arms, only E4_vs_E4_JEV comparisons, and failure retaining all four planned rows. Preserve the existing six-cell positive control.
- [x] Run `uv run --no-sync pytest tests/test_jev_pilot.py -q`; the new tests should fail because the runner lacks explicit config selection.
- [x] In `src/cv_agent/evaluation/runners/run_jev_routing_pilot.py`, change the signature to `run(root=PROJECT_ROOT, output=None, *, config_path='configs/experiments/jev_routing_v2_pilot.json')`; read `root / config_path`. Admit exactly the existing three-arm tuple or `('E4_JEV', 'E4')`; filter paired comparisons by systems actually selected.
- [x] Add `src/cv_agent/evaluation/runners/run_hp003_jev_active.py` with a main guard calling `run(config_path='configs/experiments/hp003_jev_active.json')`.
- [x] Add `scripts/hp003_jev_active.sh`: change to the project root, export `.env.experiments`, then invoke `uv run --no-sync python -m cv_agent.evaluation.runners.run_hp003_jev_active`. Add the script to the existing shell syntax inventory.
- [x] Update experiment/config/script navigation and correct the outdated claim that V2 has never run live. Retain the distinction between historical shadow calls and actual active adoption.
- [x] Run the offline runner, native Jev execution, routing policy and script tests. The full pytest gate must pass in the live process before any request; do not bypass it or reuse an earlier pass.
- [x] Run `bash scripts/hp003_jev_active.sh` once. Preserve the generated directory and all requests. No automatic retry or expansion; LLM planning on routing uncertainty remains the explicitly requested policy.
- [x] Audit each routing decision's `accepted` and `applied`, actual planner calls, expert/tool observations, labels and reported tokens against E4. Record scope limits from the shared fixtures. Comment the completed launcher invocation with its run directory and update documentation with observed results.

## Acceptance boundary

Four correct verdicts alone do not establish Jev adoption: inspect the decision ledger and model request roles. All decisions falling back is a valid measured outcome, not proof that Jev replaced planning. This is development regression evidence with trusted fixtures, not a generalization or cost claim. Do not change routing thresholds or evidence admission to make the pilot pass.

## Observed source-budget blocker

The first active run `a2e6a57f88794517ad82ff190535577d` completed all four cells, but both routing source reads exhausted the fixed 4096 cap and made zero Jev requests. Preserve this result. Add `max_source_observation_tokens` to the routing configuration and pass it through execution/workflow to the scoped read; default remains 4096, hp003 explicitly uses 6144 within the unchanged 8192 planner total. The existing active fallback consumes the remainder. Regression cases cover 4700-character source at both budgets, 10000-character over-limit source, and active/shadow accounting. Run the full gate again before a separate corrected four-cell run; this is a budget configuration correction, not a transport retry or a change to the decision threshold.

## Completion

All implementation and verification steps above were completed. The first full gate caught two new-file inventory omissions, corrected before any live request. The final model-calling snapshot passed all 1828 tests. Run `6b16f651a0904ca194f1af29c86b7366` completed four correct labels, 94 requests and 737914 reported tokens; two Jev requests succeeded, but both plans escalated because the mandatory taint command check was absent. There were zero applied decisions and no planner savings. Both original and corrected run artifacts are retained; see [Jev results](JEV_ROUTING.md). The completed launcher invocations are commented as the batch execution record. Ordinary E4 remains the baseline; the result does not justify making Jev a universally adopted default.
