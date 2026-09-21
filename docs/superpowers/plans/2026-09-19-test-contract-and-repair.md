# Test Contract and Evidence Repair Implementation Plan

> **For agentic workers:** Execute the checked tasks in this session. The writing-plans template recommends superpowers:executing-plans or superpowers:subagent-driven-development; neither is installed here. The user has already requested execution, so no additional execution-choice approval is needed.

**Goal:** Make candidate validation truthful and require a fresh full pytest pass before any real model request.

**Architecture:** Retain the existing harness, pipeline, and typed tools. Add semantic regression tests and a transport-level pytest gate, distinguish static findings from verified candidate evidence, and bind confirmation to a candidate/source identity. Keep all tests offline and keep historical experiment artifacts unchanged.

**Tech Stack:** Python 3.12+, uv, pytest, Pydantic, existing AST adapters and LangGraph.

All paths below are relative to `/home/joker/AAA_NUS_SEM2/cv_agent`. No commit of the pre-existing dirty worktree is part of this task. No real API experiments are part of this repair run.

## 1. Test contract before implementation

Files: create `AGENTS.md`, `docs/TEST_CONTRACT.md`, `tests/conftest.py`, `tests/test_security_contract.py`, `tests/test_live_gate.py`; extend `tests/test_model_runtime.py`, `tests/test_langchain_pair_reproduction.py` and `tests/test_benchmark_evaluation.py`.

- [x] Encode the invariant `observation.validation_status != CONFIRMED` for unreachable eval, fixed executable argv, ordinary dictionary updates, safe constant refactors, and shadowed eval. Pair these with reachable builtin-eval positive controls.
- [x] Test an imported `external.calculate` against an unrelated local `calculate`, and require `index.graph_neighbors(entry, direction="forward") == ()` when only the unrelated target exists.
- [x] Test mismatched candidate/source/fixture identities, malformed responses with usage, stale test gates and pytest failure. Use mocked transport and subprocess results only.
- [x] Run `uv run --no-sync pytest tests/test_security_contract.py tests/test_live_gate.py tests/test_model_runtime.py tests/test_langchain_pair_reproduction.py tests/test_benchmark_evaluation.py` and retain the initial failing cases as the repair baseline.

## 2. Pytest gate at the model boundary

Files: create `src/cv_agent/live_gate.py`; modify `src/cv_agent/model_runtime.py`, `scripts/probe_raw_proxy_response.py`; test `tests/test_live_gate.py`.

- [x] Implement `source_fingerprint(root: Path) -> str` covering source, tests, scripts, configs, `pyproject.toml` and `uv.lock`, including new/deleted files.
- [x] Implement `require_passing_tests() -> None`: run `["uv", "run", "--no-sync", "pytest"]` from the project root with inherited pytest selection options removed; require exit 0 and unchanged fingerprint. Keep the successful identity only in process memory. A later change fails closed and requires a new process.
- [x] Call the gate before `model_start` and before transport. Reuse approval only for the same unchanged process/source snapshot. Do not provide an environment bypass or trust a stale on-disk pass stamp.
- [x] Block network connections in pytest except the existing project-owned loopback fixture server; block model HTTP transport by default. Mock the gate only at the runtime test seam; test the real gate function independently.
- [x] Route the raw diagnostic through the same runtime, avoiding a second ungated HTTP implementation.

## 3. Static analysis and symbol correctness

Files: modify `src/cv_agent/python_flow.py`, `src/cv_agent/python_ast.py`, `src/cv_agent/python_probe.py`, `src/cv_agent/types.py`, `src/cv_agent/validation_tools.py`, `src/cv_agent/quorum_probe_smoke.py`; update affected semantic tests.

- [x] Stop flow propagation through return/raise and constant-infeasible branches; do not report fixed executable argv with `shell=False` as shell injection.
- [x] Make static dataflow report `validation_status=UNRESOLVED` plus an explicit `flow_status=MAY_REACH/NOT_ESTABLISHED`. Keep positive flow assertions so this does not erase functionality. Make guard and source-diff tools return observations rather than confirmations.
- [x] Preserve qualified imported call targets without adding a bare-name shortcut. Preserve module-bound names and import aliases in `CodeDocument`; use them to resolve probe calls and reject unsupported builtin shadowing.
- [x] Update scripted quorum examples to derive a prediction from static findings while retaining UNRESOLVED validation status. Keep genuine bounded-input probe positives confirmed.
- [x] Run targeted parser, flow, probe, validation and quorum suites before advancing.

## 4. Bind evidence to its subject

Files: modify `src/cv_agent/agent_types.py`, `src/cv_agent/agent_tools.py`, `src/cv_agent/agentic_workflow.py`, `src/cv_agent/react_engine.py`, `src/cv_agent/validation_tools.py`.

- [x] Add a typed subject with candidate identity, repository, entry path and source-content digest; attach it to execution scope and confirming observations.
- [x] Require matching subjects in final CONFIRMED/REFUTED conclusions. A matching status or citation alone must be insufficient.
- [x] Bind request probes/dataflow to the candidate entry. Bind registered fixture/loopback cases to their subject before execution; block missing or mismatched binding in candidate execution.
- [x] Test matching genuine evidence, same path/different contents, different candidate and unbound fixture cases.

## 5. LangChain pair integrity

Files: modify `configs/langchain_pair_eval.json`, `configs/langchain_pair_labels.json`, `scripts/langchain_template_probe.py`, `scripts/reproduce_langchain_template_pair.py`; extend `tests/test_langchain_pair_reproduction.py` and add a configuration-contract test.

- [x] Replace detector IDs with neutral values and keep label mapping evaluator-only. Explicitly classify checkout locators as runner-private, never prompt payload.
- [x] Require exact benign output and `success is True`; require the intended invalid-variable ValueError for blocked traversals. Check clean pinned checkouts and bound child execution with a timeout.
- [x] Test the orchestrator with wrong benign output, wrong rejection cause, changed checkout and child timeout, independently of optional local diagnostic checkouts.

## 6. Usage recording

Files: modify `src/cv_agent/model_runtime.py`, `src/cv_agent/benchmark_evaluation.py`, `scripts/probe_raw_proxy_response.py`, `scripts/summarize_live_usage.py`; test model/usage suites.

- [x] Record a sanitized response-received event before parsing final content/tools. Account for its usage once, whether parsing succeeds or fails; preserve compatibility with existing journals.
- [x] Add the saved raw diagnostic to the audit without modifying the historical artifact. New diagnostics use the common journal and are not double counted through raw files.
- [x] Test malformed tool JSON, absent message, empty reply, empty choices, invalid usage and success. Unknown remains unknown; no unmade request is counted.

## 7. Documentation and full acceptance

Files: update `README.md`, `docs/FULL_SYSTEM_SPEC.md`, `docs/PROJECT_STATUS_2026-09-19.md`, `docs/HANDOFF_2026-09-19.md`, `docs/TEST_CONTRACT.md`.

- [x] Correct the unsupported provider-safety root-cause claim and explain static evidence versus confirmation.
- [x] Record current completion limits: no end-to-end LangChain agent result, no final held-out claim, no automatic retry/fallback policy, no new live API calls in this repair.
- [x] Run `uv run --no-sync pytest` and `uv run --no-sync cv-agent harness-check`; rerun only affected checks if acceptance uncovers a defect, then finish with a full suite.
- [x] Recompute the usage audit offline. Report actual tests, repairs and remaining research limitations. Mark this plan's completed items with `[x]`.
