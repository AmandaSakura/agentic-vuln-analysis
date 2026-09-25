# Candidate evidence review loop implementation plan

> Execute inline as requested by the user. Alternate implementation with read-only review-agent passes; preserve the existing dirty changes and do not create commits. This plan follows the repository's established documentation layout.

**Goal:** Repair demonstrated regressions and repeat the complete diff review until a pass has no actionable findings, including excessive defensive gates.

**Architecture:** Keep incomplete command interpretation explicitly ambiguous. Prefer a dataflow witness at the candidate source line without changing the existing trace schema or dropping useful interprocedural witnesses. Preserve subject, admission, and concrete-proof checks.

**Tech Stack:** Python AST analysis, Pydantic observations, uv, offline pytest.

## Task 1: Incomplete command interpretation

Files: `src/cv_agent/agents/evidence_policy.py`, `tests/test_review_completion.py`.

- [x] Add a regression with two loop iterations: the first calls `os.system('echo ok')`, then an unsupported `try` assigns an entry parameter for the next iteration. Assert SAFE is rejected; retain supported safe and unsafe loops as controls.
- [x] Run `uv run --no-sync pytest tests/test_review_completion.py -p no:cacheprovider`; observe the regression fail.
- [x] Before selecting candidate sink facts in `_command_status`, preserve a real interpreter failure:

```python
if content.get("issues"):
    return "AMBIGUOUS"
```

## Task 2: Prefer candidate dataflow evidence

Files: `src/cv_agent/tools/validation/dataflow.py`, `tests/test_review_completion.py`.

- [x] Add a function containing both a tainted eval and `subprocess.run(['python', '-c', request.args['x']])`. Assert the returned trace contains the command candidate and its unresolved vulnerability vote is accepted. Test source slices and both statement orders. A literal interpreter argument must remain rejected.
- [x] Run the same targeted test command and observe the regression fail before implementation.
- [x] Translate the subject entry line to the source slice line. Keep the first discovered witness, continue looking for a tainted sink at the candidate line, and prefer that witness when found. Retain the existing first-witness behavior for unscoped calls and helper-only flows. Keep the existing `trace` JSON shape.
- [x] Run `uv run --no-sync pytest tests/test_review_completion.py tests/test_review_context_and_commands.py tests/test_review_state_and_scope.py tests/test_review_followup.py -p no:cacheprovider` (79 passed).

## Task 3: Review and complete

- [x] Review all changed and new source files, tests, and their callers using review-agent. Verify candidate scope, partial execution, negative controls, and unnecessary rejection paths.
- [x] For each additional demonstrated regression, add a failing behavioral test with a positive control, apply a focused repair, and repeat the read-only review.
- [x] Run `uv run --no-sync pytest -p no:cacheprovider` and `git diff --check` after the final code changes.
- [x] Record the completed iterations and test result here. Stop after a complete pass with no actionable findings; do not claim exhaustive absence of bugs.

## Additional review iterations

- Added explicit `sink_category` selection after reproducing ambiguous trace selection for two sink categories on one source line. Kept the eval probe's argument schema separate. The category tests exercise the registered tool and include a constant-command negative control. Related tests: 114 passed.
- Reproduced a missed normal continuation when the first manager in `with a, b` suppresses an exception entering the second manager. Normalize multi-manager statements to nested AST statements once, before flow analysis. Two/three-manager tests and a single-manager negative control were observed failing/passing before repair; related tests after repair: 103 passed.
- The first full run had 1124 passing tests and three integration failures: expected interface snapshots and the plan's directory/index placement. Updated the reviewed snapshots with explicit schema checks and moved this plan into the existing history index; no behavioral assertions were removed.

## Completion

The final read-only review of the current diff and associated callers found no further qualifying findings, including excessive defensive rejection paths. All original dirty changes were preserved; no commits or real model calls were made.

`uv run --no-sync pytest -p no:cacheprovider`: **1127 passed in 31.11s**. The new regression file contributes 20 parametrized cases, including safe/unsafe controls. `git diff --check` passed. This is bounded offline validation of the reviewed changes, not a proof that the project has no remaining bugs.

## Follow-up implementation and review loop

The next independent review demonstrated five additional issues. The user requested
repair followed by repeated inline review-agent passes. Preserve this historical
result and all dirty changes; do not commit or run live experiments.

**Goal:** Repair exceptional exit flow and unnecessary evidence rejection, then
finish a complete read-only review with no further actionable findings.

**Architecture:** Include context-manager exits and loop headers in exceptional
flow. Distinguish an observed unsafe path from complete safety coverage. Establish
numeric argv protection at the actual sink, not from unrelated sanitizer hits.
Ignore helper docstrings without weakening return-flow or binding checks.

**Tech Stack:** Python AST, existing command interpreter, offline pytest, uv.

- [x] Add `tests/test_review_exit_and_evidence.py` with positive/negative controls
  for manager exits (normal/return/break/continue), repeated loop headers,
  numeric argv, unsafe witnesses preceding unsupported syntax, and helper docstrings.
- [x] Run `uv run --no-sync pytest tests/test_review_exit_and_evidence.py -p no:cacheprovider`
  and observe the demonstrated regressions fail before implementation.
- [x] In `src/cv_agent/tools/analysis/python_flow.py`, collect each pending with-body
  exit before forwarding it and add its state to possible exit-method exceptions;
  repeat header exception collection using loop-carried states.
- [x] In `src/cv_agent/tools/analysis/commands.py`, retain numeric conversion provenance
  and add a sink-local argv protection fact. In
  `src/cv_agent/agents/evidence_policy.py`, use that affirmative fact for non-shell
  safety and allow a matching UNSANITIZED witness despite later interpretation issues.
- [x] In `src/cv_agent/tools/analysis/sanitizers.py`, skip only the leading string
  docstring before interpreting the helper's assignments and return.
- [x] Run the new tests plus all existing semantic/evidence regressions. Review
  the complete dirty diff and new files with the review-agent criteria, including
  over-defensive rejection paths. For any new demonstrated defect, add a failing
  test, repair it, and repeat the review.
- [x] Run `uv run --no-sync pytest -p no:cacheprovider` and `git diff --check`;
  record the final review outcome and test results below.

### Follow-up iterations

1. The initial regression run failed 15 cases and passed 17 controls. Repaired
   context-manager exit exceptions for normal/return/break/continue, repeated loop
   condition/iterator failures (including condition sinks), unsafe witnesses
   preceding unsupported syntax, numeric argv evidence, and helper docstrings.
   Added builtin-shadowing and executable/environment override controls. The
   first full suite passed 1166 tests.
2. The first inline read-only review reproduced unsafe evidence joining for two
   sinks on one candidate line and unnecessary rejection of ordinary positional
   Popen options. Added tests that failed before repair. Candidate safety now
   covers every sink; positional execution controls are read at their actual
   positions and preserved when interpreting command alternatives.
3. The next review reproduced lost numeric protection when a conditional chooses
   between numeric text and a literal, both for a single argument and whole argv.
   Added four branch tests (two failing positive cases, two passing raw-input
   controls), then preserved protection only when every alternative qualifies.
   The related semantic/evidence suite passed 505 tests.
4. The final inline read-only review covered the complete dirty source diff,
   new files, tests and call sites. No further actionable findings, including
   excessive defensive rejection paths. Additional checks covered reassignment,
   mixed safe/raw alternatives and positional executable overrides.

The new regression file contains 47 parametrized cases. All validation remains
offline; no model requests, commits or edits to historical experiment artifacts.

Final verification: `uv run --no-sync pytest -p no:cacheprovider --tb=short`:
**1174 passed in 30.90s**. `git diff --check` passed. Final review: **No findings.**
This is the result of the bounded change review, not a claim of exhaustive absence
of bugs across all Python semantics or external projects.

## Continued review: mixed command evidence and process input

The user authorized another inline repair/review loop. Baseline offline suite:
1174 passed. Preserve earlier changes, run no live experiments, and do not commit.

**Goal:** Preserve an observed unsafe command alternative and prevent unrelated
numeric argv from establishing safety for a process receiving external code.

**Architecture:** Join command facts existentially for an unsafe witness and
universally for safety. Extend the existing sink-local execution-input check to
explicit stdin/input; keep ordinary numeric argv and output options supported.

**Tech Stack:** Existing Python command interpreter, evidence policy, offline pytest.

- [x] Add `tests/test_review_command_inputs.py`: exercise two sinks on one line,
  command alternatives, ambiguous-only controls, and `input`/keyword `stdin`/
  positional `stdin` carrying executable Python source alongside numeric argv.
  Retain numeric argv with absent/None input and stdout-only options as controls.
- [x] Run `uv run --no-sync pytest tests/test_review_command_inputs.py -p no:cacheprovider`
  and observe failing behavioral tests before changing implementation.
- [x] In `src/cv_agent/tools/analysis/commands.py::_status_join` and
  `src/cv_agent/agents/evidence_policy.py::_command_status`, order
  `UNSANITIZED` before `AMBIGUOUS`; keep incomplete safe paths unresolved.
- [x] In `src/cv_agent/tools/analysis/commands.py::Interpreter.record_sink`, include
  `("stdin", 3)` in positional execution inputs and require
  `kwargs.get("input") is None` before emitting `numeric_argv`.
- [x] Rerun the targeted tests, then review the complete dirty source/test changes
  and callers. Reproduce and repair any additional actionable regressions.
- [x] Run `uv run --no-sync pytest -p no:cacheprovider --tb=short` and
  `git diff --check`; record the final bounded review outcome.

### Continued review result

The new regressions first produced **7 failed, 7 passed**. After the two focused
repairs, the related tests passed **101 cases**. The next complete read-only
review of the dirty source changes, new tests, and affected callers found no
further qualifying findings, including excessive defensive rejection paths.

Final offline suite: **1188 passed in 29.21s**. `git diff --check` passed.
Final bounded review: **No findings.** No live model requests or commits were
made. This does not establish absence of bugs outside the reviewed changes and
supported semantics.
