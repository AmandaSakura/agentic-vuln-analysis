# Micro-benchmark repair implementation plan

**Goal:** Preserve real outcomes, failures, costs and evidence without predetermined conclusions.

**Architecture:** Keep the existing four fixtures and six systems. Add an optional model-call observer without changing runtime provenance, an instrumented tool registry, and one durable event journal per run. Save each result before proceeding and derive descriptive tables from saved outcomes only.

**Files:** `scripts/run_micro_benchmark.py`, `configs/micro_benchmark.json`, `src/cv_agent/model_runtime.py`, `tests/test_micro_benchmark.py`.

- [x] Add model request/response/error observation; preserve existing transport behavior.
- [x] Record attempted calls, full verdicts, failure categories and interrupted runs. Persist each case/variant immediately into a unique run directory.
- [x] Remove predetermined findings; report failures and abstentions separately and document the handcrafted fixture and unequal baseline limitations.
- [x] Exercise timeout, invalid model output, partial failure, interruption, full trace persistence and all-failure reporting offline; run the project regression suite (274 passed).

Execution is authorized in the current task; no live API run is part of this repair.
