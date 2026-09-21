# Micro-benchmark execution and evidence

This is a four-fixture Python integration diagnostic, not an independent held-out
benchmark or evidence for the historical recall/false-positive improvements.
Ground-truth labels concern attacker-controlled arbitrary code execution through
`eval`; they do not certify the absence of every other security issue.

The six systems are a full-source direct model and Harness variants E1–E5. The
direct model receives no fixture descriptions, reference labels or case-specific
decision rules. Its information and tool budgets still differ from E1–E5, so the
comparison does not isolate a single component. E4/E5 make independent model
requests; their cost difference alone does not establish the causal savings from
early exit. Inspect the recorded paths, votes and tools.

## Run

Edit `configs/micro_benchmark.json` for the intended endpoint/model and request
limits. Supply the existing proxy credential through `ANTIGRAVITY_API_KEY` in
the shell environment. No API key is embedded in the script or JSON config.

From `/home/joker/AAA_NUS_SEM3/cv_agent`:

```sh
uv run --no-sync python scripts/run_micro_benchmark.py
```

Every invocation creates a new `artifacts/micro_benchmark/<UTC-time>-<id>/`:

- `metadata.json`: source hashes, fixture sources and labels, Harness and model configuration.
- `events.jsonl`: synchronously flushed request starts, model replies/errors,
  tool starts/observations/errors, and per-trial results. Messages, tool schemas,
  returned model IDs and reported token usage are retained. Credentials are not logged.
- `results.json`: atomic snapshot of all recorded trial results, including full
  successful verdicts, Planner/ReAct traces and task executions.
- `report.md`: observations only, with failures and interruptions separated from
  abstentions and classification errors. Generated after each trial.

Ordinary trial exceptions are explicit failures, and the matrix continues without
retries, substitute models or fallback verdicts. Ctrl-C records the interrupted
trial, refreshes summaries and propagates the interruption. A hard process kill
cannot produce a final verdict: inspect unmatched start events in the durable
journal; never treat missing results as successful runs.

Call counts measure attempted model/tool invocations, including failed attempts.
Reported token usage is retained where available; missing usage is unknown, not
zero. All recorded trials remain in the overall correctness denominator. A failed
or unresolved trial is not automatically counted as a binary FP/FN.

## Offline verification

```sh
uv run --no-sync pytest tests/test_micro_benchmark.py
uv run --no-sync pytest
```

The repair was validated with 15 new offline tests and 274 passing total tests.
No live API evaluation was performed as part of the repair.
