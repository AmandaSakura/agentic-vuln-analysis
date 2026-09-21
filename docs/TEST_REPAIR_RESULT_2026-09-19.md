# Test contract repair — acceptance result

The repair was implemented after adding failing behavioral tests. No real model API
requests were made. Existing uncommitted work and historical run artifacts were retained.

## Acceptance

| Check | Result |
| --- | --- |
| Initial new-contract run | 28 failed, 21 passed, 4 errors (gate module not implemented yet) |
| Additional alias/rebinding regressions before repair | 3 demonstrated failures |
| Complete pytest after repair | **345 passed**, 9.69 seconds |
| Actual standalone live gate | Launched full pytest: **345 passed**, 9.17 seconds; no API request |
| `cv-agent harness-check` | **PASS** |
| `git diff --check` | PASS |
| Offline usage reconciliation | 362 requests; 1,371,526 reported tokens; 1 missing usage |

The original suite had 301 tests. This change adds 44 test cases, including negative and
positive controls. Existing tests that treated static flow/guard/diff patterns as confirmed
vulnerabilities now assert the underlying facts as well as their UNRESOLVED validation.
The single-confirmation/quorum regression now uses a real supported concrete input probe;
it still requires abstention when two other experts abstain.

Acceptance logs:

- `artifacts/test_contract_repair_2026-09-19/initial_failures.txt`
- `artifacts/test_contract_repair_2026-09-19/additional_binding_failures.txt`
- `artifacts/test_contract_repair_2026-09-19/pytest.txt`
- `artifacts/test_contract_repair_2026-09-19/harness.json`
- `artifacts/pytest_gate/661ae0bdb72f4cfe8edfcaab4f454e9f/pytest.log`

## Implemented boundaries

- `AGENTS.md` and `docs/TEST_CONTRACT.md` preserve the user's rule: full pytest must pass
  before real model experiments. The transport checks source/test/config identity; any
  change after process startup or during pytest denies admission. Failed or timed-out
  pytest does not grant admission, and repeated attempts in that process remain blocked.
- Tests have a default HTTP denial and disallow external sockets/shared proxy access.
  Model tests use mocks; fixture tests retain local loopback operation. Gate tests exercise
  failure, timeout, source edits, test edits, config additions/deletions and successful reuse.
- Static analysis no longer confirms vulnerabilities just from may-taint, sensitive names,
  missing recognized guards or fewer sinks in a changed version. Flow paths, guard records
  and differences remain available for model predictions and inspection.
- Control-flow termination and known constant-infeasible branches no longer contribute
  the reviewed dead-code flow. Fixed executable argv with shell disabled is distinguished
  from shell command text.
- Qualified imports cannot fall through to unrelated bare names. Source slices retain
  import aliases and module bindings/reassignments. Aliased legitimate calls still work;
  module-shadowed eval and rebound imports do not become concrete witnesses.
- Confirming/refuting observations carry a typed subject. Final confirmation requires the
  same candidate, repository, entry and indexed-source digest. Fixtures are checked before
  execution; source changes produce a different subject. `candidate_subject()` provides
  one constructor for pipelines and fixture registration.
- LangChain detector IDs are neutral and checkout locators are explicitly runner-private.
  Differential controls require exact benign output and the intended invalid-variable
  ValueError. Dirty checkouts are rejected, child probes have a timeout, and orchestration
  negative tests do not depend on local LangChain environments.
- Raw received responses are journaled before parsing. Invalid choices/messages/tool JSON
  preserve known usage; received/reply/error events do not double count it. Legacy raw
  diagnostics are included only when no journal already accounts for them.
- The unsupported Google-safety root-cause assertion has been corrected in the handoff.
  No retry, model fallback or full-benchmark run was added.

## Scope still outstanding

This is a correctness and development-gating repair, not an end-to-end vulnerability
evaluation. Follow-up: the LangChain E1 runner and bound current-run pair evidence tool are now
implemented and the live pair subsequently succeeded; see `LANGCHAIN_AGENT_RESULT_2026-09-19.md`.
This report retains the earlier 345-test repair results; current acceptance is in
`CURRENT_REVIEW_RESULT_2026-09-19.md`. The scanner still lacks template-format sink discovery. The full development
matrix, verified held-out paired negatives, and held-out evaluation remain incomplete.

The static analyses are deliberately approximate and are not safety proofs. The Python
probe is a bounded function-slice interpreter under documented request/builtin assumptions,
not arbitrary Python execution or application exploit reproduction. New supported semantics
need their own positive/negative tests. The live gate enforces this repository's model
entrypoint policy; it is not an operating-system security boundary against someone replacing
the runtime or issuing unrelated shell HTTP requests.

For the next experiment, use the shared runtime, keep the declared request budget, and
record prediction, validation and failure costs separately. Passing the generic suite does
not substitute for a pair-specific prerequisite check when optional integration fixtures
are absent.
