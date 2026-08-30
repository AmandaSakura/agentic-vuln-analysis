# cv-agent

Deterministic research harness for two directional questions:

1. does forward AST/call-graph retrieval recover security context that a lexical retriever misses under the same retrieval budget?
2. can specialist evidence reduce false alerts, and can an early quorum preserve the full-review label while skipping an expert call?

This repository is not yet an LLM ReAct system or an exploit validator. The current experts are deterministic heuristics used to isolate retrieval, abstention, and adjudication behavior before an LLM/tool loop is introduced.

System variants:

- `V1`: candidate-local context + scan expert;
- `V2`: lexical retrieval + scan expert;
- `V3`: forward call-graph retrieval + scan expert;
- `V4`: forward call-graph retrieval + three experts + full majority review;
- `V5`: the same experts and majority policy, with a two-vote high-confidence early exit that skips the third expert when possible.

Interpretation rules:

- `V2` vs `V3` isolates retrieval under the same `top_k` budget.
- `V3` vs `V4` measures the combined specialist-ensemble effect.
- `V4` vs `V5` must have equivalent labels; it measures expert calls saved, not false-positive reduction.
- `ABSTAIN` remains a third label and is reported with coverage rather than being counted as `SAFE`.
- OWASP labels are loaded only after every system predicts all cases.
- OWASP BenchmarkJava 1.2beta is a development benchmark and is not eligible for a final unseen-test claim.
- The VulnGym retrieval command is explicitly oracle-seeded and is not end-to-end vulnerability recall.

The graph implementation keeps forward and reverse edges separate. Pure graph retrieval starts only from the candidate. A separate hybrid retriever is available when a lexical seed is intentionally desired. All variants share one deterministic context-token cap across their ranked evidence documents.

See `docs/HARNESS.md` for experiment constraints and metric attribution.
