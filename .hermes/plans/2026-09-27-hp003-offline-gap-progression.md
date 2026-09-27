# hp003 Offline Gap Progression Implementation Plan

> **For agentic workers:** Work from the current dirty checkout. Preserve `artifacts/jev_v3_comparison/545892d6559f439a94ef307cc021cac3/` and `artifacts/proof_routing_repair/final_snapshot/`. No model API request is part of this plan.

**Goal:** Advance candidate-bound command analysis through generic retrieval and POSIX path gaps, record each next gap on both hp003 source snapshots, and report a separate Popen call-site property without changing the original candidate score.

**Architecture:** Prefer source-resolved callees inside the existing retrieval budget and record each admission. Extend the command interpreter only for canonical `os.path` lexical functions under an explicit POSIX subject assumption. Keep the original whole-function candidate and any new sink-scoped subject separate. Stop before implementing artifact repository registry dispatch.

**Tech Stack:** Python, Pydantic, pytest, existing `RepositoryIndex`, `ToolExecutionScope`, `ValidationSubject`, and offline advisory checkouts.

---

### Task 1: Preserve baseline and make the missing-definition regression observable

**Files:** `tests/test_retrieval_and_consensus.py`, `tests/test_hp003_semantic_and_verdict_contract.py`, `artifacts/hp003_offline_gap_progression/`.

- [x] Record the old six-cell `definition_not_admitted` result as the before state; do not modify its events, results, or source snapshot.
- [x] Add a focused test that builds a candidate with `entry -> download -> root_helper`, plus a lexical distractor. Assert `root_helper` enters the admitted path set, while an unrelated same-name definition does not.
- [x] Before implementing admission, run that test and save its assertion failure; preserve one existing retrieval-budget positive control.

### Task 2: Admit bound direct callees within the existing budget

**Files:** `src/cv_agent/retrieval/index.py`, `src/cv_agent/agents/workflow.py`, `src/cv_agent/domain/review.py`, `src/cv_agent/evaluation/execution.py`, `tests/test_retrieval_and_consensus.py`, `tests/test_agent_budget_units.py`.

- [x] Prefer a direct callee of the candidate or an already selected span only when the index contains a uniquely source-resolved forward edge for that call. Keep the current `top_k` and serialized context budgets; evict lower-priority context if needed rather than silently expanding the budget.
- [x] Record every newly admitted path, its bound call source, per-document SHA256, whole-subject digest, serialized token cost, and the reason any candidate was skipped. Make this record available in the saved verdict/experiment journal.
- [x] Verify the actual hp003 `_get_root_uri_and_artifact_path@64-97` enters both revisions' admitted sets and that a same-name but unbound definition does not. Merely admitting source must not turn `AMBIGUOUS` into V/S.
- [x] Run `uv run --no-sync pytest -q tests/test_retrieval_and_consensus.py tests/test_agent_budget_units.py tests/test_hp003_semantic_and_verdict_contract.py`.

### Task 3: Interpret canonical os.path lexical operations only on POSIX

**Files:** `src/cv_agent/tools/analysis/commands.py`, `tests/test_semantic_diagnostics.py`, `tests/test_hp003_semantic_and_verdict_contract.py`.

- [x] Add `os.path.basename`, `dirname`, `normpath`, and `join` to the existing lexical path operation handling only when the validation subject explicitly establishes POSIX (the hp003 subject has `sys.platform.startswith('linux')=True` and `is_windows()=False`). Require the canonical stdlib binding and builtin-string inputs; preserve argument effects and POSIX join's absolute-component behavior.
- [x] Keep platform-unknown, Windows, rebound `os.path`, PathLike, and non-string cases unresolved. Add positive and negative tests through the real `inspect_command_construction` tool, including the unchanged original whole-function SAFE barrier.
- [x] Run `uv run --no-sync pytest -q tests/test_semantic_diagnostics.py tests/test_hp003_semantic_and_verdict_contract.py`.

### Task 4: Maintain a two-snapshot gap ledger after each change

**Files:** `src/cv_agent/evaluation/diagnostics/hp003_gap_progression.py`, `artifacts/hp003_offline_gap_progression/gaps.json`, `artifacts/hp003_offline_gap_progression/REPORT.md`.

- [x] Rebuild the exact hp003_a/b indices and subjects from `configs/experiments/jev_v3_hp003_comparison.json`, with fixtures disabled and no model transport. Invoke `inspect_command_construction` at the original candidate entry and record `command_construction_status`, `analysis_gaps`, `issues`, sink facts, admitted paths, and source digests for baseline, admission, and POSIX stages.
- [x] Continue only with a small general semantic rule whose unsupported operation is observable in both snapshots and has negative controls. Save the next gap after every change. Stop before modeling `get_artifact_repository`, plugin dispatch, or `LocalArtifactRepository`.
- [x] If either side remains `AMBIGUOUS`, do not run a live hp003 arm. Even if the offline status changes, this plan has no live model call.

### Task 5: Establish a separate Popen call-site property

**Files:** `src/cv_agent/evaluation/diagnostics/hp003_callsite.py`, `tests/test_hp003_callsite_property.py`, `artifacts/hp003_offline_gap_progression/REPORT.md`.

- [x] Create a distinct subject bound to the `subprocess.Popen` call in `backend.py:311-317`, with a property explicitly limited to shell interpretation of that call's command argument. Keep the original `command-execution` function-head candidate, property, labels, and results unchanged.
- [x] On the fixed revision, verify that `shlex.quote(local_path)` remains one shell argument after the literal `exec ` prefix and `bash -c`; test arbitrary shell metacharacter strings and a vulnerable unquoted control. State that a helper's independent command side effect remains unresolved for the original whole-function candidate.
- [x] Report the call-site result separately from original TP/TN metrics. Run `uv run --no-sync pytest -q tests/test_hp003_callsite_property.py`.

### Task 6: Final offline gate and decision handoff

**Files:** `artifacts/hp003_offline_gap_progression/REPORT.md` and saved test logs.

- [x] Run `uv run --no-sync pytest`, `uv run --no-sync cv-agent harness-check`, and `git diff --check` on the final source. Preserve logs and a source/test/config snapshot.
- [x] State exactly which gap remains in each snapshot and what each call-site result proves. If the next hard gap is artifact repository dispatch, stop and present options A (static registry modeling) and B (candidate-bound isolated execution witness) for a separate decision. Do not start a model run or the three-arm comparison.
