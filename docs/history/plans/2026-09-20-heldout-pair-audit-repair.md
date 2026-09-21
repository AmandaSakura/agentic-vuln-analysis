# Heldout Pair Audit Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use inline execution in this session. Do not dispatch subagents for this repair unless the user explicitly asks for delegated agent work. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair the held-out Python pair pipeline so unsupported fixed sides, missing config evidence, and weak SAFE votes cannot silently produce misleading experiment metrics.

**Architecture:** Keep the existing runner and artifact layout. Add candidate-specific preparation checks, broader read-only repository indexing for security-relevant config files, and stricter expert-output validation that treats missing or negative findings as abstention unless there is concrete counter-evidence.

**Tech Stack:** Python, Pydantic configs, pytest, existing LangGraph/ReAct harness, existing OpenAI-compatible live transport gate.

---

### Task 1: Security-Relevant Source Indexing

**Files:**
- Modify: `src/cv_agent/python_heldout_pair_config.py`
- Modify: `src/cv_agent/python_heldout_pair_source.py`
- Test: `tests/test_python_heldout_pair_config.py`
- Test: `tests/test_python_heldout_pair_source.py`

- [ ] Add a fixed allowlist for Python plus security-relevant text/config files: `.py`, `.ini`, `.cfg`, `.toml`, `.yaml`, `.yml`, `.json`, `.env.example`, `.env.sample`.
- [ ] Keep non-Python files as module-level fallback documents with stable paths like `basic_auth.ini::<file>@1-6`.
- [ ] Keep Python AST spans unchanged so existing candidate selection and graph retrieval still work.
- [ ] Add tests proving config files are accepted, indexed, hashed and searchable without expanding to arbitrary binary files.

### Task 2: Candidate-Specific Fixed Commit Selection

**Files:**
- Modify: `scripts/prepare_python_heldout_pairs.py`
- Test: `tests/test_prepare_python_heldout_pairs.py`

- [ ] Replace first-commit selection with a bounded scoring check over same-repository advisory commits.
- [ ] Require the fixed checkout to differ at the exact candidate file and line, or quarantine the pair as `fixed_candidate_not_repaired`.
- [ ] Prefer candidate-file diffs and ancestry; do not infer repair from unrelated commit references.
- [ ] Update manifest text so historical first-link behavior is no longer described as the protocol.

### Task 3: Evidence-Adequate Expert Material Votes

**Files:**
- Modify: `src/cv_agent/react_engine.py`
- Test: `tests/test_react_engine.py`

- [ ] Reject `SAFE / UNRESOLVED` material expert conclusions that cite only no-result searches, no resolved graph neighbors, or local source reads.
- [ ] Keep `ABSTAIN / UNRESOLVED` valid for insufficient evidence.
- [ ] Keep `VULNERABLE / UNRESOLVED` valid when it cites code evidence, because static evidence can support a hypothesis without confirming it.
- [ ] Keep `SAFE / REFUTED` valid only through matching typed validator output, as already required.

### Task 4: Verification

**Files:**
- Test: complete pytest suite
- Document: `docs/PYTHON_HELDOUT_PAIR_RESULT_2026-09-20.md`

- [ ] Run targeted tests for the changed behavior.
- [ ] Run `uv run --no-sync pytest`.
- [ ] Update the result document with the repair summary and the exact validation commands.
- [ ] Do not run real model requests in this repair turn; a fresh <=10-cell live gate should happen only after tests pass.

### Follow-up verification: close evidence-admission gaps

The existing 489 tests pass, but inspection found untested admission gaps. Continue inline under the existing repair authorization.

Completed: the new tests reproduced 16 failures before implementation. The final suite passes with 511 tests; harness-check is PASS. The 3 frozen v2 pairs pass the local source audit in `scripts/audit_python_heldout_pair_repairs.py`, with results in `artifacts/python_heldout_pair_preparation_v2/repair_reaudit.json`. No model calls were made. Scheduling fixtures retain SAFE-majority coverage using observed guard/sanitizer signals.

- [ ] In `tests/test_evidence_validation.py`, add failing cases for empty guard/route results, unresolved probes, nonempty source searches, unrelated or truncated REFUTED observations, and version comparisons that describe another snapshot. Keep positive controls for actual guards/sanitizers and a matching typed REFUTED result. A SAFE/UNRESOLVED conclusion must fail these weak cases with `pytest.raises(ValueError, match="affirmative counter-evidence")`; VULNERABLE/UNRESOLVED and ABSTAIN remain available.
- [ ] In `src/cv_agent/react_engine.py`, replace default acceptance of unknown observations with explicit counter-evidence checks. Accept a nontruncated REFUTED observation only for `observation.subject == subject` with a non-null subject. Permit unresolved guard/sanitizer hypotheses only when their structured result contains an affirmative signal; never treat search hits, potential sinks, unsupported probes, or another revision's patch as such a signal. Explain the rule in the expert prompt before its first request.
- [ ] In `tests/test_prepare_python_heldout_pairs.py`, add failing cases for snippets absent from the vulnerable source and a mentioned helper whose contents did not change. Keep direct-repair and real helper-change positive controls.
- [ ] In `scripts/prepare_python_heldout_pairs.py`, require at least one source-bound candidate snippet and either a changed candidate snippet or a mentioned helper with different vulnerable/fixed contents. Return explicit quarantine reasons for missing bindings. This is source-level admission, not behavioral proof of repair.
- [ ] Run `uv run --no-sync pytest tests/test_evidence_validation.py tests/test_prepare_python_heldout_pairs.py -q` before and after implementation, then the full `uv run --no-sync pytest` and `uv run --no-sync cv-agent harness-check`. Record results in the result document without overwriting frozen experiment artifacts or making model requests.
