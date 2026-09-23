# Independent VulnGym Evaluation Implementation Plan

**Goal:** Run a reproducible source-discovery evaluation on VulnGym commits that were not used in the prior MLflow experiments, with labels kept out of detector inputs.

**Architecture:** Freeze a new evaluator split by excluding every repository used in the prior advisory matrix. A reusable preparation command materializes pinned source commits, a detector-only command inventories all candidates without loading labels, and a separate evaluator command scores exact source locations against the frozen positive references. All artifacts remain `claim_eligible=false` because the dataset has no verified fixed negatives.

**Tech Stack:** Python 3.13, Pydantic dataset models, Git shallow fetch/worktrees, existing Python repository discovery and exact-location scorer, pytest.

---

### Task 1: Freeze the independent split

**Files:**
- Create: `configs/preparation/vulngym_evaluation_v4.json`
- Create: `configs/datasets/vulngym_heldout_inputs_v4.json`
- Create: `artifacts/vulngym_heldout_preparation_v4/labels.json`
- Create: `src/cv_agent/evaluation/preparation/prepare_vulngym_evaluation_v4.py`
- Test: `tests/test_prepare_vulngym_evaluation_v4.py`

- [x] **Step 1: Audit prior exposure and current split**

The prior live matrix used MLflow. The v3 source manifest has 156 commits and the evaluator file has 378 positive entries. Excluding the whole MLflow repository leaves 152 commits, 17 repositories, 369 positive entries, and 169 advisories. Do not use entry IDs, lines, or labels in the detector manifest.

- [x] **Step 2: Freeze the repository-level exclusion**

The preparation config records the excluded URL and reason. The preparation function filters detector subjects and evaluator labels separately, verifies every excluded repository was present, keeps source dataset identity, and refuses to overwrite frozen outputs.

- [x] **Step 3: Verify split tests**

Test whole-repository exclusion, stable ordering, exact retained labels, and that the detector manifest contains no label or source-location fields. Run `uv run --no-sync pytest -o addopts='' tests/test_prepare_vulngym_evaluation_v4.py -q`.

### Task 2: Materialize and inventory every pinned source commit

**Files:**
- Create: `src/cv_agent/evaluation/preparation/prepare_vulngym_checkouts.py`
- Create: `src/cv_agent/evaluation/runners/run_vulngym_discovery.py`
- Create: `tests/test_vulngym_discovery_runner.py`
- Modify: `docs/EXPERIMENTS.md`

- [x] **Step 1: Add a reusable shallow-fetch/worktree preparer**

Read only `vulngym_heldout_inputs_v4.json`. Reuse one Git cache per repository, fetch each pinned commit, create a detached worktree under `data/vulngym-heldout-subjects/<owner__repo>/<commit>`, and verify clean exact revisions. Refuse to replace existing mismatched directories.

- [x] **Step 2: Add a source-only full discovery runner**

Process every manifest subject, record source hashes, parser errors, and all candidates before any scoring. Never import or open evaluator labels. Save immutable run artifacts under `artifacts/vulngym_discovery/<run-id>/` and preserve interrupted subjects.

- [x] **Step 3: Test source isolation and reproducibility**

Use temporary Git repositories and scripted discovery doubles to verify pinned revision checks, label-free inputs, durable partial progress, duplicate rejection, and exact candidate inventory. Run the focused runner tests.

### Task 3: Score and analyze the full discovery result

**Files:**
- Create: `src/cv_agent/evaluation/diagnostics/score_vulngym_discovery.py`
- Create: `tests/test_vulngym_discovery_scoring.py`
- Create: `docs/history/records/VULNGYM_INDEPENDENT_EVALUATION_2026-09-23.md`
- Modify: `docs/history/README.md`

- [x] **Step 1: Keep scoring evaluator-only**

Load the full candidate inventory and then evaluator labels; match repository, commit, critical-operation path, and line exactly. Report parse errors, unmatched references, unmatched predictions, and discovery recall. Keep false-positive rate unavailable and `claim_eligible=false`.

- [x] **Step 2: Run the complete offline suite**

Run `uv run --no-sync pytest -o addopts=''`. Before any model API experiment, require the project live gate to pass on the unchanged source/config/test snapshot.

- [x] **Step 3: Run full 152-commit source discovery and review results**

Do not send API requests from this stage. If analysis shows a parser/scanner/evaluator bug, add a failing general regression test, fix it, rerun the full suite, and regenerate the complete inventory in a new immutable run directory. If no implementation bug is found, write the report with the positive-only and dataset-label limitations stated prominently.

### Acceptance limits

- No detector code branches on repository, commit, entry ID, line, label, or expected result.
- Candidate selection is source-only and includes the complete inventory; there is no first-N truncation.
- The 152-commit source inventory and 369 references remain development evidence until dataset verification and fixed negatives are independently established.
- Model classification of every candidate is a separate budgeted stage. Do not describe source-discovery coverage as end-to-end agent recall or exploit confirmation.
