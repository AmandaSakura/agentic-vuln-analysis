# Bounded Witness Stage 2b/2c Implementation Plan

> **For agentic workers:** Implement the explicitly authorized scope below with independent module ownership, then integrate, test, commit and run one paired target invocation. No model or package requests.

**Goal:** Close the eight observed runtime obligations plus the benign control using generic, source-bound measurements.

**Architecture:** Three focused observers supply value, branch and preexec records to the existing isolated worker. A new explicit verification mode runs both probe and benign control with the same isolation policy and resources. Historical diagnostic mode remains observation-only. Only complete matching observations plus successful control and Bash expansion can confirm; literal observations remain unresolved.

**Tech Stack:** Existing UV environments, Python 3.12/3.13 sys.monitoring, AST/dis, raw dictionaries, seccomp/Landlock and fork/pipe/waitpid.

## 1. Raw value obligations

**Create:** `src/cv_agent/evaluation/diagnostics/witness_values.py`, `tests/test_witness_values.py`.

- [x] Write and reproduce synthetic failures for entry dictionary values, descriptor avoidance, module constant uniqueness, mismatches and stale source.
- [x] Implement `ValueAssumptionObserver(manifest)`, `observe_entry(frame)`, `verify_module_values()`, `result()` returning observations and specific gaps.
- [x] Read instance dictionaries through the genuine built-in dictionary descriptor; never execute a property, custom getattr or arbitrary equality. Bare constants need a unique admitted module-level definition and matching module/source identity.
- [x] Observe at the actual candidate entry; reread module constants at the command boundary. Tests must establish source binding and timing, not just dictionary lookup behavior.

## 2. Actual branches

**Create:** `src/cv_agent/evaluation/diagnostics/witness_branches.py`, `tests/test_witness_branches.py`.

- [x] Write failing actual sys.monitoring tests for true/false, repeated/multiple occurrences, unexecuted branches, unavailable/occupied dedicated tool, side effects, other threads and stale source.
- [x] Implement `BranchAssumptionObserver(manifest).install(expected_code, on_entry=callback)`, `report()`, `close()`.
- [x] Match canonical AST expression text exactly (quote spelling and redundant parentheses normalize); permit whole-test `not` with measured truth inverted. Never evaluate expression strings or match substrings.
- [x] Use a dedicated non-reserved tool ID. Discover verified runtime code through PY_START; use local LINE/BRANCH events for the relevant code only. Require actual candidate ancestry/thread and agree at every executed matching occurrence; no occurrence means unresolved. Record platform metadata separately.

## 3. Real preexec execution

**Create:** `src/cv_agent/evaluation/diagnostics/witness_preexec.py`, `tests/test_witness_preexec.py`.

- [x] Write failing real isolated-process controls: normal/caught ordinary exception, raised exception, exec, exit(0), caught exit/exec attempts, subprocess and fork, timeout.
- [x] At the authenticated Popen boundary, capture the actual preexec object from both trusted subprocess frames. Reject inconsistent capture; None is already verified.
- [x] Fork one explicitly tagged child in the same seccomp/Landlock worker. The inherited outer command hook yields only during this trusted verifier operation; a child hook records all audit events and refuses process actions.
- [x] Python os._exit/sys.exit have no audit event: additionally observe C calls by identity, refuse those lifecycle calls and reject profile disabling. A complete normal-return record plus exit code 0 is mandatory; early/native exit cannot count as success. Do not replace the target function or allow by name/source.
- [x] Bound child wall time, result bytes/events and cleanup. Record allowed ctypes loading; native escape coverage remains the existing declared limitation.

## 4. Integrate and preserve diagnostic behavior

**Modify:** `bounded_execution_witness.py`, `run_bounded_witness_diagnostic.py`, `compare_bounded_witness_diagnostics.py`. **Create:** `tests/test_bounded_witness_verification.py`.

- [x] Add regression controls before integration. Add an explicit `verify_obligations` API/CLI mode so prior diagnostic calls retain their unresolved-only behavior.
- [x] Configure observers before target import and activate branch/entry observation immediately before the real method invocation. Emit observer records before worker termination.
- [x] Merge observed gaps; never clear a declaration without successful runtime evidence. Probe and benign control use identical grants, resources, monitoring and preexec checks.
- [x] Validate both candidate frames/source/executable/selftests/argv and replay under a clean environment. Require the benign path to remain literal. Only then classify the probe as EXPANDED_OBSERVED/CONFIRMED or LITERAL_OBSERVED/UNRESOLVED.
- [x] Extend pair comparison to accept explicitly verified positive-only results while retaining historical observation-only validation. No label or case-specific branching.
- [x] Run targeted controls, complete `uv run --no-sync pytest` and `uv run --no-sync cv-agent harness-check`; commit implementation and tests before any hp003 run.

## 5. Stage 2c and stop

- [ ] Reuse the two v5 manifests, pinned existing Python 3.12 environments, original shared path/nonce, four exact read grants and unchanged heavy_target. No internal stubs, dependency installation, strace or model requests.
- [ ] Run each snapshot once in verification mode; that invocation includes one probe and its benign target control. Save complete source/branch/value/preexec/control/argv/replay records and machine-checked same-input differential.
- [ ] Preserve original artifacts; commit durable results. hp003_b literal remains unresolved. If hp003_a does not confirm, report its exact gaps and stop without additional modeling/runs.
- [ ] State that input manifest is human-authored; this measures tool verification, not autonomous system discovery.
