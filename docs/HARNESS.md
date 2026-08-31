# Experiment harness constraints

The executable source of truth is `src/cv_agent/harness.py`. This document explains that contract; experiment modules must consume the typed specs rather than repeat budgets, expert orders, dataset roles, or claim rules. Every CLI command is registered as an experiment, diagnostic, data-preparation action, or harness action; an unregistered command cannot run. `cv-agent harness-check` validates and prints the active project contract.

## Scope

The deterministic slice validates retrieval and adjudication mechanics. It does not claim full ReAct reasoning, calibrated confidence, exploit execution, or end-to-end authorization verification.

## Data separation

- Detector prediction functions receive source code, repository identity, and candidate identity only.
- OWASP truth is loaded after predictions are complete.
- VulnGym `entry_point` and `critical_operation` may be used only by commands whose output says `oracle-seeded`; those results are retrieval coverage, not detector recall.

## Dataset lifecycle and declared scope

- OWASP BenchmarkJava 1.2beta is a development benchmark because its aggregate results were inspected while rules were changing. It is not eligible as a final unseen test set.
- Final claims require a different dataset or version that was held aside before rule and threshold tuning.
- Any primary category subset and candidate-seeding protocol must be declared with a rationale in experiment output. Overall metrics must still be reported.
- A final-test percentage intended to generalize beyond the benchmark must include a paired uncertainty estimate at the appropriate project/advisory unit. Development and oracle diagnostics are not claim eligible.

## Comparable retrieval variants

- Text and graph variants use the same `top_k` and total context-token budget.
- Context tokens use the repository's deterministic word-or-punctuation tokenizer; the budget is shared across ranked documents rather than applied once per document.
- Every system receives the same separately budgeted local candidate context. Text, graph, and hybrid retrieval may add evidence only through a second augmentation budget, and the candidate document is excluded from augmentation.
- OWASP uses one repository-wide method corpus containing every BenchmarkJava main-source file, including shared helpers. It must not rebuild a two-method index independently for each test case, because that makes the templated `doGet -> doPost` text and graph retrieval paths structurally non-discriminating.
- Pure graph retrieval starts only from the candidate and follows forward call edges.
- Lexical seeding plus graph expansion is a separate `hybrid` variant.
- Ambiguous unqualified symbols do not create graph edges.

## Adjudication attribution

- `V3 -> V4` is the specialist-ensemble comparison.
- `V4 -> V5` changes scheduling only. Labels must remain equivalent; report expert calls saved and fast/slow counts.
- A fast verdict must be produced before the third expert runs. Merely tagging a verdict after all votes is not a fast path.
- Report fast/slow paths crossed with verdict labels and calls by expert name. Expert-call counts are not token, latency, or monetary-cost claims.

## Ternary evaluation

- `VULNERABLE`, `SAFE`, and `ABSTAIN` remain distinct.
- Report coverage, abstain rate, strict recall, covered recall, population FPR, covered FPR, and precision.
- Any headline FPR change must include the associated recall and coverage changes.

## Evidence limitations

- Current taint and authorization specialists use ordered same-function evidence, not full def-use/CFG proof.
- Missing configured patterns prove neither safety nor absence of a vulnerability; experts abstain in that case.
- Heuristic confidence values are not calibrated probabilities.

Every experiment result records the code Git revision/dirty state and each dataset Git revision/dirty state. `uv.lock` is covered by the code revision; no second lock hash is added.

No output hashes, frozen result baselines, or unrelated execution gates are required. The import-time typed-contract validation is narrowly scoped to the demonstrated configuration-drift failures. Git, `uv.lock`, dataset revisions, types, and ordinary tests remain the underlying mechanisms.
