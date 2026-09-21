# Fixed development evaluation

The four handcrafted Python cases remain integration diagnostics. The separate
OWASP development matrix freezes 66 cases from the existing 2,740-case
BenchmarkJava checkout: three positives and three negatives in each of 11
categories. Selection uses a fixed SHA256 ranking, before model evaluation.
`configs/development_manifest.json` records identities, candidates and
evaluator-only labels. No reference labels or category answers are supplied to
the agent. The public benchmark is synthetic and already used for development;
it is not a new real-project held-out set.

Actual pilot outcomes and the expansion decision are recorded in
`DEVELOPMENT_PILOT_2026-09-19.md`, including all failed revisions and the separate
offline parser-fix replay.

Subsequent successful bounded comparisons, real-source diagnostics, and the
remaining provider issue are recorded in [the current status](PROJECT_STATUS_2026-09-19.md).
The prepared 330-trial matrix is still not a completed run.

## Systems and reporting

E1 is the local single-expert baseline. E2/E3 compare lexical and graph retrieval
under the existing shared Harness budget. E3/E4 compare the combined planner and
specialist system. E4/E5 have independent model executions: compare label
disagreements and observed costs, but do not attribute all differences to early
exit or claim an equivalent scheduler unless equivalence is established.

All selected cases appear in reports, including not-yet-run, failed, interrupted,
and abstained cases. Summary JSON includes raw denominators, strict/covered recall,
precision, coverage, population/covered/conservative FPR, category breakdowns,
paired wins/losses/unavailable cases, request/tool counts, latency and returned
token usage. Conservative FPR treats every non-cleared negative as unresolved
risk. Wilson intervals are descriptive only: same-template dependence and
repository generalization are not accounted for.
Incomplete summaries are marked provisional; final code omits intervals while
there are unrun or interrupted cells. Earlier pilot artifacts retain their original
summaries and must be interpreted as incomplete diagnostics.

Every invocation writes to a unique `artifacts/development_benchmark/<id>/`.
Events are synced after each operation; summaries are updated after each trial.
New runs also snapshot source files, model configuration and the lockfile so an
uncommitted working tree can be inspected. The initial pilot predates source
snapshot support and is retained as a failed diagnostic, not rewritten.

## Commands

From `/home/joker/AAA_NUS_SEM3/cv_agent`, load the local proxy credential without
printing it:

```sh
source /home/joker/.config/cliproxyapi/client.env
export ANTIGRAVITY_API_KEY="$OPENAI_API_KEY"
uv run --no-sync python scripts/run_development_pilot.py
```

The pilot uses a fixed negative and positive from the `cmdi` stratum, interleaved
per system, with at most 30 model requests and a 600-second admission deadline.
An in-flight request may extend past that deadline up to its request timeout.
It is a capability/cost check, not an accuracy estimate.

The complete prepared matrix is executable separately:

```sh
uv run --no-sync python scripts/run_development_benchmark.py
```

That command has 330 scheduled trials, capped at 6,600 model requests and a
24-hour admission deadline. It has not been run as part of preparing the matrix.
Do not expand until pilot failures and observed cost have been reviewed.

The manifest preparation script refuses to overwrite an existing manifest.
Do not change the selection after reading outcomes and still call it the same
evaluation. Prompt/runtime changes produce a new run, never replace old results.

## Remaining requirements for overall-effect claims

A passing OWASP development run cannot establish overall real-project gains.
The repository's `FULL_SYSTEM_SPEC.md` additionally requires repository-separated
VulnGym evaluation, label-free candidate generation before evaluator matching,
verified fixed-commit negatives and repository/advisory-grouped uncertainty.
The existing three Python development repositories must remain excluded from
held-out results. An arbitrary later commit is not an acceptable safe label.
These requirements are separate from the now-executable fixed development matrix.
