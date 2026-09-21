# cv-agent

## Code organization

Core subsystems live in focused packages under `src/cv_agent/`:

| Package | Responsibility |
| --- | --- |
| `code_adapters/` | Language parsers, source spans, repository loading |
| `retrieval/` | Indexing, call graphs, focused context, token budgets |
| `experts/` | Deterministic scan, taint, flow and authorization experts |
| `validation_tools/` | Typed validators, source scope, isolated fixtures and tool registration |
| `harness/` | Experiment models, declared defaults, configuration and result checks |

The existing imports (`from cv_agent.retrieval import RepositoryIndex`, etc.)
remain the public entry points. See [the architecture guide](docs/ARCHITECTURE.md)
for dependency boundaries and where to make changes. Start with
[the test contract](docs/TEST_CONTRACT.md) before changing behavior.

## Research scope

Deterministic research harness for two directional questions:

1. does forward AST/call-graph retrieval recover security context that a lexical retriever misses under the same retrieval budget?
2. can specialist evidence reduce false alerts, and can an early quorum preserve the full-review label while skipping an expert call?

The repository contains the original deterministic retrieval/adjudication slice plus the audited foundation of the full agentic system: a provider-neutral model protocol, typed model/tool/observation ReAct loops, a dynamic planner, a LangGraph full/fast workflow, and AST Code-RAG adapters for Python, TypeScript/JavaScript, and Go. Explicit fallback documents cover the remaining declared suffixes. `agentic-smoke` is wiring-only and cannot produce research claims. Adapters have been profiled on 2,489 supported files in three pinned development repositories with no reported parse errors; this does not establish semantic correctness or held-out coverage. Bounded live development comparisons and Python validator integration checks now complete with durable traces. Real-source live checks still encounter provider responses with empty choices. Independent real-project exploit validation and held-out end-to-end reproduction remain incomplete.

**Latest status:** [2026-09-19 repairs, evaluation results, and remaining work](docs/PROJECT_STATUS_2026-09-19.md).

The latest review passes 403 tests and repairs evidence binding, acceptance,
concurrent cancellation, request accounting and transport diagnostics. Python
template candidates now cover the development reference sink; this is not
confirmed vulnerability recall. Java execution validation and held-out evaluation
remain incomplete. Use `configs/vulngym_heldout_inputs_v2.json` for the active
prepared split; v1 is historical. See [the complete review](docs/DEEP_REVIEW_RESULT_2026-09-19.md).

**Development gate:** Read [the test contract](docs/TEST_CONTRACT.md). Every real model
request uses the shared runtime, which runs the full offline pytest suite before the
first request in that process. A failing suite or any subsequent source/config/test
change blocks transport. There is no bypass environment variable or reusable pass file.
Run `uv run --no-sync python -m cv_agent.live_gate` to exercise admission without sending
an API request. Static flow/guard/diff findings remain `UNRESOLVED`; candidate confirmation
requires matching evidence bound to the candidate and indexed source contents.

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

Budgets, dataset roles, candidate protocols, expert order, adjudication policy, early-exit position, and required metrics live only in the typed project contract at `src/cv_agent/harness/`: `models.py` defines the schemas and `defaults.py` declares the active settings. Run `cv-agent harness-check` to inspect it. Experiment results include code and dataset Git identities without introducing separate lock hashes.

See `docs/HARNESS.md` for experiment constraints and metric attribution. The development-only OWASP v3 outcome, its real-safe adjudication result, and its limitations are recorded in `docs/OWASP_DEVELOPMENT_RESULT.md`. The accepted oracle-only cross-file retrieval result is recorded in `docs/VULNGYM_RETRIEVAL_RESULT.md`.

The fixed 66-case, 330-trial live development matrix and bounded API pilot are
documented in `docs/DEVELOPMENT_BENCHMARK.md`. This adds failure-aware metrics and
durable traces beyond the four-case micro-benchmark; development results remain
ineligible for held-out or historical improvement claims.

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

### Held-out experiment provider switch

Edit the Git-ignored `.env.experiments` file (template: `.env.experiments.example`).
Set `CV_AGENT_PROVIDER=deepseek` or `CV_AGENT_PROVIDER=gemini`.
DeepSeek reads `DEEPSEEK_MODEL` and `DEEPSEEK_API_KEY`; Gemini reads
`GEMINI_MODEL` and `GEMINI_API_KEY`. Quote Gemini model names containing parentheses.
The selected provider requires its own model name and key; no automatic fallback.
DeepSeek uses the official API; Gemini uses the existing local proxy and diagnostics.
Resolved model settings are recorded in metadata, with credentials passed separately.

Run `bash scripts/heldout_gate.sh`. After the new acceptance.json reports passed=true,
run `bash scripts/heldout_matrix.sh` with the same settings. Both launchers retain
full pytest admission and independent run artifacts. This switch applies to these
two held-out runners. Direct invocations without CV_AGENT_PROVIDER retain their
existing JSON configuration and legacy credential variable.

The held-out launchers now select the explicit v4 retrieval configs:
`configs/python_heldout_pair_gate_v4.json` and `configs/python_heldout_pairs_v4.json`.
They rank graph neighbors by distance before lexical score, use bidirectional
augmentation under the existing budgets, and declare Langflow's Python import
root separately from repository file paths. MLflow's paired scenario explicitly
declares external `model_uri` input and `enable_mlserver=true` on both revisions;
these assumptions bind to validation identity and do not count as witnesses.
The v2/v3 configs and artifacts are preserved. New outputs use `artifacts/python_heldout_pair_gate_v4/`
and `artifacts/python_heldout_pair_matrix_v4/`; the gate pointer is
`artifacts/python_heldout_pair_gate_v4.json`. These post-audit runs remain ineligible
for held-out claims. Run the source-only audit with
`uv run --no-sync python scripts/audit_heldout_evidence_v4.py`.
