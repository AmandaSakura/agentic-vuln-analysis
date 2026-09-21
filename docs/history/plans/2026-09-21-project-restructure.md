# Project Restructure Implementation Plan

> **For agentic workers:** Execute the checked batches below in order. The recommended executing-plans/subagent-driven-development skills are not installed in this workspace; use the available collaboration tools with the same test-before-next-batch discipline. The user authorized execution without further consultation.

**Goal:** Make the E1–E5 candidate-analysis library and experiment execution understandable and reusable while preserving detector behavior, budgets, evidence requirements, existing launch commands, and historical experiment files.

**Architecture:** Shared source and evidence models underpin parsing, retrieval, tools, and agents. Runtime owns transport/admission/accounting; evaluation owns datasets, experiment execution, and reporting. Scripts become entry points and deterministic V1–V5 remains an explicit baseline.

**Tech Stack:** Python 3.12+, uv, pytest, Pydantic, LangGraph, existing AST/Tree-sitter parsers.

## Invariants and review boundaries

- No paid models, credential loading, transport bypass, artifact rewrite, reset, or cleanup.
- Do not mix the previously reported permission/shell semantic repairs into mechanical restructuring. Document those remaining issues separately.
- Preserve experiment IDs, source coordinates and hashes, neutral scope construction, selected cells, predictions, validation status semantics, budgets, stop conditions, raw usage accounting, and JSON field names.
- Existing command wrappers remain executable. Internal Python imports and test patch locations move to their owning modules; documented public imports receive explicit compatibility exports when needed.
- Every batch adds behavioral or architectural regression coverage, runs targeted tests, and passes the complete offline suite before the next implementation batch.
- No commits are required: preserve a reviewable working-tree diff. A copy of all original source/config/test/docs files and a stat manifest of every existing artifact have been saved outside the repository.

## Batch 0 — Baseline and characterization

**Files:** `tests/test_refactor_characterization.py`, `tests/fixtures/refactor_baseline.json`.

- [x] Read AGENTS.md and TEST_CONTRACT.md; record original source/artifact identities outside the repository.
- [x] Run `uv run --no-sync pytest`: 649 passed in 24.31s.
- [x] Record existing scripted end-to-end outputs and add comparisons that exercise the original public entry points:

```python
def test_scripted_agent_evaluation_matches_baseline():
    from cv_agent.agentic_eval import run_agentic_scripted_eval
    assert run_agentic_scripted_eval() == BASELINE["agentic_eval"]

def test_deterministic_baseline_matches_baseline():
    from cv_agent.experiment import run_synthetic_experiment
    assert run_synthetic_experiment() == BASELINE["synthetic"]
```

- [x] Run `uv run --no-sync pytest tests/test_refactor_characterization.py`, then full pytest.

## Batch 1 — Runtime infrastructure out of scripts

**Files:** `src/cv_agent/runtime/journal.py`, `budget.py`, `execution.py`, `snapshots.py`; `scripts/run_micro_benchmark.py`, `scripts/run_development_benchmark.py`; `tests/test_runtime_extraction.py`.

- [x] Add tests for interleaved request accounting, admission exhaustion, cancellation, durable partial results, source snapshots, and package imports without reading experiment config.
- [x] Extract Journal/Trial/RecordedTools, Budget classes, execute_trials and run_candidate without changing their event schemas or exception taxonomy.
- [x] Pass project root and model configuration explicitly in package functions; maintain old script defaults in thin adapters until callers migrate.
- [x] Keep runtime independent of dataset modules and scripts.
- [x] Run targeted runtime/runner/micro-benchmark tests and full pytest.

## Batch 2 — Agent/tool responsibilities

**Files:** `src/cv_agent/agents/evidence_policy.py`, `react.py`, `workflow.py`, `voting.py`; `src/cv_agent/tools/`; associated existing tests plus `tests/test_package_boundaries.py`.

- [x] Add checks that conclusion validation preserves error messages and evidence-role behavior using saved observations and scripted replies.
- [x] Move conclusion validation out of the ReAct loop without changing ordering or acceptance semantics.
- [x] Separate tool registry/admission from repository handlers and source identity. Preserve ToolRegistry class identity and tool names, schemas, serialization and observation limits.
- [x] Keep workflow harness overrides explicit and preserve planner dependencies, resumed budgets and one final vote per expert.
- [x] Run evidence, tool, planner, workflow and accounting tests, then full pytest.

## Batch 3 — Source, shared models and baselines

**Files:** `src/cv_agent/domain/`, `code_adapters/python.py`, `code_adapters/java.py`, `code_adapters/java_lexical.py`, `baselines/`, package imports and corresponding tests.

- [x] Add parser/graph characterization for source coordinates, module import roots, callers, and unrelated qualified symbols.
- [x] Move shared data models without changing model_dump output or enum values.
- [x] Integrate parser locations with the existing adapter interfaces; keep Java/Python loader policies explicit.
- [x] Isolate deterministic workflow/experts, remove eager baseline imports from the package, and retain shared voting/scanning behavior.
- [x] Update imports and test monkeypatch targets without weakening assertions; run the focused suites and full pytest.

## Batch 4 — Evaluation package and experiment lifecycle

**Files:** `src/cv_agent/evaluation/datasets/`, `runners/`, `results.py`, `metrics.py`, `acceptance.py`, `lifecycle.py`; experiment scripts and runner tests.

- [x] Add tests for gate/matrix configuration identity, cancellation, failed/abstained cells, finalization on exceptions, and immutable historical log summarization.
- [x] Move dataset-specific preparation/config/acceptance under evaluation; retain separate development-fixture and advisory protocols.
- [x] Replace duplicate heldout gate/matrix execution with a shared lifecycle accepting explicit configuration, task preparation and report policy.
- [x] Preserve legacy result/acceptance JSON; expose run-integrity and detection-quality checks separately without silently changing legacy acceptance.
- [x] Move operational implementations into importable package modules. Entry scripts invoke package main/run functions, retaining their current command behavior.
- [x] Run every runner/config/acceptance/usage test and full pytest.

## Batch 5 — Navigation, config reuse and final verification

**Files:** `README.md`, `docs/ARCHITECTURE.md`, `docs/CURRENT_STATUS.md`, `docs/EXPERIMENTS.md`, `docs/REFACTOR_2026-09-21.md`, configuration composition helpers/tests, public compatibility modules.

- [x] Provide one current navigation path, a historical-document index, and explicit canonical module ownership. Keep historical artifacts and frozen v2/v3/v4 configs intact.
- [x] Allow new experiment selections to reuse a dataset declaration while preserving the resolved existing v4 configurations; record fully resolved inputs in runs.
- [x] Remove residual package-to-script dependencies and import-time experiment config reads. Keep compatibility exports explicit; no wildcard imports or module-identity tricks.
- [x] Run full pytest, `uv run --no-sync cv-agent harness-check`, existing scripted smoke/evaluation commands, and `uv build --wheel`.
- [x] Inspect installed wheel imports/entry points without repository scripts on sys.path.
- [x] Compare the original artifact manifest and frozen protocol definitions, review the diff and document known unresolved semantic issues and every batch result.

## Completion record

Batch test counts, compatibility decisions and final checks are recorded in `docs/REFACTOR_2026-09-21.md`. A passing suite establishes regression coverage, not a new held-out result or semantic proof for unsupported analysis.
