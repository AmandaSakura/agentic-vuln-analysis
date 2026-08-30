# Experiment harness constraints

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

## Comparable retrieval variants

- Text and graph variants use the same `top_k` and total context-token budget.
- Context tokens use the repository's deterministic word-or-punctuation tokenizer; the budget is shared across ranked documents rather than applied once per document.
- Pure graph retrieval starts only from the candidate and follows forward call edges.
- Lexical seeding plus graph expansion is a separate `hybrid` variant.
- Ambiguous unqualified symbols do not create graph edges.

## Adjudication attribution

- `V3 -> V4` is the specialist-ensemble comparison.
- `V4 -> V5` changes scheduling only. Labels must remain equivalent; report expert calls saved and fast/slow counts.
- A fast verdict must be produced before the third expert runs. Merely tagging a verdict after all votes is not a fast path.

## Ternary evaluation

- `VULNERABLE`, `SAFE`, and `ABSTAIN` remain distinct.
- Report coverage, abstain rate, strict recall, covered recall, population FPR, covered FPR, and precision.
- Any headline FPR change must include the associated recall and coverage changes.

## Evidence limitations

- Current taint and authorization specialists use ordered same-function evidence, not full def-use/CFG proof.
- Missing configured patterns prove neither safety nor absence of a vulnerability; experts abstain in that case.
- Heuristic confidence values are not calibrated probabilities.

No additional hashes, frozen contracts, or execution gates are required by this document. Git commits, `uv.lock`, dataset versions, exact subject commits, types, and ordinary tests remain the reproducibility mechanisms.
