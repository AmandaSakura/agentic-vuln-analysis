# cv-agent

Deterministic research harness for two directional questions:

1. does forward AST/call-graph retrieval recover security context that a lexical retriever misses under the same retrieval budget?
2. can specialist evidence reduce false alerts, and can an early quorum preserve the full-review label while skipping an expert call?

The repository contains the original deterministic retrieval/adjudication slice plus the audited foundation of the full agentic system: a provider-neutral model protocol, typed model/tool/observation ReAct loops, a dynamic planner, a LangGraph full/fast workflow, and AST Code-RAG adapters for Python, TypeScript/JavaScript, and Go. Explicit fallback documents cover the remaining declared suffixes. `agentic-smoke` is wiring-only and cannot produce research claims. The multi-language adapters currently pass cross-file fixtures but have not yet been profiled on independent real repositories. No live model or real-project exploit validator has run yet, so the end-to-end reproduction remains in progress.

Deterministic OWASP proxy variants:

- `V1`: candidate-local context + scan expert;
- `V2`: lexical retrieval + scan expert;
- `V3`: forward call-graph retrieval + scan expert;
- `V4`: typed forward call-graph retrieval + scan and taint experts + a dynamically routed flow/authz verifier + full majority review;
- `V5`: the same expert policy, with a two-vote high-confidence early exit that skips the routed verifier when possible.

Interpretation rules:

- `V2` vs `V3` isolates retrieval under the same `top_k` budget.
- `V3` vs `V4` measures the combined specialist-ensemble effect.
- `V4` vs `V5` must have equivalent labels; it measures expert calls saved, not false-positive reduction.
- `ABSTAIN` remains a third label and is reported with coverage rather than being counted as `SAFE`.
- Conservative FPR maps `ABSTAIN` to `VULNERABLE`; covered FPR is reported only on explicit `SAFE`/`VULNERABLE` decisions; population alert rate is reported separately.
- OWASP labels are loaded only after every system predicts all cases.
- OWASP BenchmarkJava 1.2beta is a development benchmark and is not eligible for a final unseen-test claim.
- The VulnGym retrieval command is explicitly oracle-seeded and is not end-to-end vulnerability recall.

The graph implementation keeps forward and reverse edges separate. Pure graph retrieval starts only from the candidate. A separate hybrid retriever is available when a lexical seed is intentionally desired. All systems receive the same fixed local base context; retrieval variants receive a separate shared augmentation budget. The OWASP experiment builds one repository-wide corpus from every BenchmarkJava main-source method, including shared helpers. Each servlet `doGet` remains its case-local candidate, while text and graph retrieval compete over that same corpus.

Budgets, dataset roles, candidate protocols, expert order, adjudication policy, early-exit position, and required metrics live only in the typed project contract at `src/cv_agent/harness.py`. Run `cv-agent harness-check` to inspect it. Experiment results include code and dataset Git identities without introducing separate lock hashes.

See `docs/HARNESS.md` for experiment constraints and metric attribution. The development-only OWASP v3 outcome, its real-safe adjudication result, and its limitations are recorded in `docs/OWASP_DEVELOPMENT_RESULT.md`. The accepted oracle-only cross-file retrieval result is recorded in `docs/VULNGYM_RETRIEVAL_RESULT.md`.

The deterministic slice is now the development precursor to the complete agentic implementation specified in `docs/FULL_SYSTEM_SPEC.md`. That specification defines genuine ReAct traces, dynamic planning, multi-language Code-RAG, typed validation tools, held-out data, paired negatives, and full/fast attribution.

## DeepSeek live-model configuration

Local regression checks use the existing WSL/uv environment:

```bash
uv run --no-sync pytest
uv run --no-sync cv-agent harness-check
```

Tests use scripted model replies and temporary local fixtures; no model API credential is needed.
The bug fixes and their regression coverage are described in `docs/BUGFIX_VERIFICATION.md`.
The clean-context Luna max workflow simulation is recorded in
`docs/LUNA_CLEAN_CONTEXT_SIMULATION.md`.
Agent input accounting now reports `context_accounting=utf8-byte-upper-bound` for retrieved
text and tool observations. Historical deterministic proxy experiments retain their lexical
counting units; provider-reported `usage` remains the source for actual model token consumption.

The local `.env.deepseek` file is preconfigured for the OpenAI-compatible DeepSeek endpoint and `deepseek-v4-flash`. Fill only `CV_AGENT_MODEL_API_KEY`; the file is Git-ignored. The default live settings disable DeepSeek thinking mode and cap each completion at 1,200 tokens.

Run an explicit live case through the wrapper so the local environment file is loaded:

```bash
./scripts/deepseek.sh agentic-live-owasp \
  --raw data/raw \
  --case-id BenchmarkTest00001 \
  --system E1
```

Repeat `--case-id` and `--system` for additional cases and ablations. The wrapper rejects an empty key before making a request. `.env.deepseek.example` is the tracked, secret-free template.
