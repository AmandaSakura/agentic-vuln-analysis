# Proof Routing Review Repair Implementation Plan

> **For agentic workers:** Use independent workers for the disjoint proof, plan policy, and workflow changes; review their combined behavior before a live run. The original scope and acceptance rules are in `.hermes/plans/2026-09-27_184252-proof-routing-handoff.md` and `docs/TEST_CONTRACT.md`.

**Goal:** Close the eight findings in `artifacts/proof_routing_review_2026-09-27/REVIEW.md`, then produce one new, auditable six-cell comparison.

**Architecture:** Keep candidate proof eligibility in the tool producer and consumer, derive required tasks from one policy, and allow model planning to add tasks only within an explicit patch scope. Preserve the original experiment and its invalid rule baseline for audit.

**Tech Stack:** Python 3, Pydantic, pytest, uv, JSONL journal, existing gated `OpenAICompatibleChatModel`.

---

### Task 1: Verify the review baseline and preserve recoverable source

**Files:** `artifacts/proof_routing_review_2026-09-27/test_handoff_review.py`, `artifacts/proof_routing_repair/`, `AGENTS.md`, `docs/TEST_CONTRACT.md`.

- [x] Read project constraints and the review. The review's seven failures were recorded before later worktree edits; running its ten tests on the current worktree yielded ten passes. Record this chronology rather than presenting that pass as the reviewed build's result.
- [x] Snapshot the final source, tests, config, launcher, and documentation files with SHA256 after edits stop. State that the original pre-implementation untracked contents cannot be reconstructed from a filename list.
- [x] Keep `artifacts/jev_v3_comparison/f9eadcf1d6334cbf9972e1bfcd021472/` intact as an invalid rule comparison.

### Task 2: Close proof contract failures

**Files:** `src/cv_agent/tools/analysis/commands.py`, `src/cv_agent/tools/validation/fixtures.py`, `tests/test_hp003_semantic_and_verdict_contract.py`, `tests/test_fixture_proof_scope.py`.

- [x] Add a failing end-to-end test for a helper returning a constant while an outer shell call uses its result; the helper must not be invented as tainted input.
- [x] Add a failing end-to-end test for a helper executing an unsafe shell call before returning a value that the outer caller quotes; the whole-function SAFE vote must be rejected.
- [x] Remove or constrain a download summary unless the selected repository implementation, return relation, and relevant side effects are verified from the bound source. Preserve direct constant, direct passthrough, and safe quoting positive controls.
- [x] With no fixture proof contract, wrong subject, local coverage, or unsupported status, expose `UNRESOLVED` as both observation `validation_status` and JSON `status`; retain the measured status in `raw_status`.
- [x] Apply the same scope principle to `run_loopback_http_case`: an HTTP two-request observation cannot prove an unrelated `command-execution` candidate merely because its subject was copied. Require an audited property-specific proof contract and an explicit producer whitelist at admission.
- [x] Confirm the hp002 guard-after-delete test actually changes the generated source and places the guard after the delete call. Run `uv run --no-sync pytest -q tests/test_fixture_proof_scope.py tests/test_hp003_semantic_and_verdict_contract.py`.

### Task 3: Close deterministic planning failures

**Files:** `src/cv_agent/agents/plan_policy.py`, `src/cv_agent/agents/workflow.py`, `tests/test_plan_policy.py`, `tests/test_jev_plan_composition.py`.

- [x] Derive fixture waiver eligibility from the same full subject and proof scope check used by `required_tasks`. Local and mismatched fixtures must leave both command-check obligations active.
- [x] Bind a qualifying fixture case ID to any mandatory fixture task and enforce it at runtime. When a strong and weak case share a subject, a plan or tool call selecting only the weak case must not waive command checks.
- [x] Topologically order composed tasks; use expert rank only to choose between currently ready tasks. Reject cycles and unresolved dependency references.
- [x] Construct `RoutingResult` with all required fields. Test a valid `E4_RULE_V1` workflow with `run_planner` replaced by a function that fails if called; expected planner requests: zero.
- [x] Feed a patch planner the locked required and accepted Jev tasks plus an explicit remaining gap. Reject a patch that removes or changes a locked task, then validate the merged DAG and task origins.
- [x] Run `uv run --no-sync pytest -q tests/test_plan_policy.py tests/test_jev_plan_composition.py tests/test_jev_decision_points.py tests/test_planner_dependencies.py`.

### Task 4: Execute the independent expert policy

**Files:** `src/cv_agent/agents/applicability.py`, `src/cv_agent/agents/workflow.py`, `src/cv_agent/evaluation/runners/run_jev_v3_comparison.py`, `tests/test_expert_applicability.py`.

- [x] Keep `fixed` as the default and as the six-cell experiment policy. Accept `applicable_v1` only through an explicit workflow option.
- [x] Record each skipped expert and reason without creating an ABSTAIN ballot. Keep a role when a required dependency needs it; keep unknown or compound scope undetermined.
- [x] Preserve quorum two. When fewer than two roles can vote, produce `insufficient_applicable_roles` and no invented vote.
- [x] Run `uv run --no-sync pytest -q tests/test_expert_applicability.py tests/test_agentic_workflow.py`.

### Task 5: Audit and run the bounded comparison

**Files:** `artifacts/proof_routing_repair/`, `src/cv_agent/evaluation/diagnostics/`, `scripts/jev_v3_comparison.sh`.

- [x] Classify each original and new model request by case, system, role, request ID, and step. Count valid delivered observations, truncation, repeat and budget rejection, and correction requests separately. Reconcile request and usage totals against `events.jsonl`.
- [x] Run `uv run --no-sync pytest` and `uv run --no-sync cv-agent harness-check`, save raw outputs, and inspect `git diff --check`. The live transport's own pytest gate must run on the unchanged snapshot.
- [x] Run the six cells once in a new `artifacts/jev_v3_comparison/<run-id>/` directory, under the existing 200-request and 1800-second bounds. Preserve all six rows including abstentions and failures.
- [x] Rewrite `artifacts/proof_routing_repair/handoff.md` to reflect source snapshot hashes, actual planner/Jev request counts, task origins, proof limitations, and the new raw run. Do not reuse the old 5/6 comparison as a valid three-arm result.
