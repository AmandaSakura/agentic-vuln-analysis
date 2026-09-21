# End-to-end reproduction contract

Current acceptance and remaining gaps are tracked in
[PROJECT_STATUS_2026-09-19.md](../history/records/PROJECT_STATUS_2026-09-19.md). This specification
describes the target; it does not assert that every requirement has been validated.

## Objective

Reproduce the architecture described in the resume as an executable vulnerability-hunting system:

1. a LangGraph planner dynamically decomposes each candidate into validation subtasks;
2. scanning, taint, and authorization specialists each run a genuine model/tool/observation ReAct loop;
3. Code-RAG supplies AST, symbol, forward/reverse call, import, data-flow, route, and guard context across files;
4. typed tools collect static observations and perform bounded tests or loopback HTTP checks without executing arbitrary model-generated shell commands;
5. a quorum-inspired full/fast adjudicator combines independent specialist evidence, preserves typed validator status, and skips the third specialist only when the first two form an irreversible high-confidence quorum;
6. project-level evaluation separates development, held-out positive, paired negative, and oracle-diagnostic data.

The target is architectural and methodological reproduction. The original prompts, model, repositories, thresholds, and raw predictions are unavailable, so the original 28% and 37% numbers cannot be reproduced exactly. This project reports the numbers produced by its own declared data and model configuration.

## Requirement traceability

| Resume capability | Required executable evidence |
| --- | --- |
| LangGraph three-expert chain | A compiled graph with planner, retrieval, scan, taint, authorization, validation, and adjudication nodes |
| ReAct reasoning | Every material expert result contains at least one model action, typed tool call, tool observation, and final structured vote |
| Dynamic validation planning | The planner emits candidate-specific subtasks, dependencies, assigned expert, and allowed validator; a fixed three-item list does not qualify |
| Code-RAG | Repository-scale retrieval over code documents plus typed graph edges; lexical-only or per-file retrieval does not qualify |
| AST and cross-file call graph | Python, TypeScript/JavaScript, and Go adapters emit function spans, definitions, imports, calls, routes, and guards; other formats use an explicit fallback tier |
| Scanning expert | Produces candidate locations and CWE/category hypotheses using scanner and repository tools |
| Taint expert | Produces source-to-sink steps or an explicit missing-edge reason; keyword order alone does not qualify |
| Authorization expert | Models principals, objects/tenants, actions, guards, and enforcement location; unrelated vulnerability families produce `ABSTAIN` |
| Vulnerability validation | A typed validator records `CONFIRMED`, `REFUTED`, or `UNRESOLVED` with reproducible observations |
| Quorum-fast adjudication | Full and fast modes share votes and final policy; every fast label must equal the counterfactual full-review label |
| Recall/FPR claims | Raw counts, coverage, recall, FPR, precision, paired deltas, and project/advisory-level uncertainty are reported together |

## Execution flow

```text
repository -> index -> candidate scan -> planner
                                      |
                         +------------+------------+
                         |            |            |
                     scan ReAct   taint ReAct   authz ReAct
                         |            |            |
                         +------ typed validators --+
                                      |
                              full / fast quorum
                                      |
                         finding + evidence + trace
```

The planner may omit an irrelevant specialist, but every experimental system variant has a declared scheduling policy. The full three-expert ablation always runs all three specialists. The fast variant considers an early exit only after the first two declared specialists have completed.

The runtime dispatches ready subtasks from the planner's dependency graph. The declared
expert order is a tie-breaker among ready tasks, not an override of dependencies. Each
subtask runs a ReAct loop and must complete its assigned typed validator; its result
and bounded observations are passed to dependent tasks. A task can complete with an
`UNRESOLVED` validation result, which is not interpreted as satisfying its success condition.
An expert can resume after another expert. Its last cumulative judgment becomes its
single ballot only after all its assigned tasks complete; earlier judgments remain
in `task_executions`. Observation budgets persist across that expert's subtasks.
Fast exit requires the first two declared experts' final ballots, and cost accounting
includes every executed task, including a partially completed third expert.

## Model contract

The runtime uses a provider-neutral chat-model protocol. A live model is configured at runtime with environment variables for endpoint, model name, and optional credential; secrets are never stored in Git or result files. Temperature is zero where supported. Every result records the provider protocol, model identifier returned by the endpoint, sampling parameters, and usage reported by the endpoint.

Every actual model transport is admitted by the full offline pytest suite in the current
process. Source, tests, scripts, configs and dependency declarations are fingerprinted;
an edit during/after admission blocks transport and requires a new process. Test failure
does not retry pytest on every remaining trial. Tests mock model transport and cannot
contact the shared proxy. No disk stamp or environment variable bypasses this gate.
Passing tests is a development prerequisite, not an effectiveness or safety claim.

Two runtime modes exist:

- `scripted`: deterministic responses for unit and wiring tests; never claim eligible;
- `live`: an actual local or remote model performs the ReAct loops; required for agent results.

The current host has an 8 GB RTX 4060 Laptop GPU and can run a quantized small code model for development. Final measurements should also be runnable against a stronger OpenAI-compatible endpoint without code changes. Model comparisons are separate experiments rather than silent substitutions.

## Tool and validation boundary

The model never emits an unrestricted shell command. It chooses from typed tools registered by the Harness:

- repository: `search_symbols`, `read_span`, `find_references`, `get_callers`, `get_callees`, `get_routes`, `get_guards`;
- taint: `find_sources`, `find_sinks`, `trace_dataflow`, `find_sanitizers`;
- authorization: `inspect_principal`, `inspect_resource_scope`, `inspect_guard`, `compare_route_and_service_guard`;
- validation: `run_static_check`, `probe_python_eval`, `run_fixture_test`, `run_loopback_http_case`, `compare_vulnerable_and_fixed`.

The scan specialist also performs applicable verification, rather than only reporting sink
presence. For supported Python eval candidates, the planner can assign scan `probe_python_eval`
and taint `trace_dataflow` without cross-expert dependencies. The former checks concrete input
values in a restricted interpreter; the latter tracks abstract taint through argument bindings.
Authz retains its permission-specific mandate and may abstain. Registered execution fixtures
remain an option for other supported cases. A lack of two applicable checks remains unresolved;
it does not lower quorum or turn an irrelevant expert into a supporting vote.

`probe_python_eval` operates only on admitted Python AST function slices. It supports plain
functions, positional/keyword argument binding, literal defaults, local assignments, returns,
simple branches and limited expressions. It looks for two distinct injected expressions reaching
the same eval argument, with a maximum of 256 interpreter steps and the declared call-hop limit.
It never executes repository code, imports modules, opens files, or invokes host callables.
Unsupported constructs, unresolved calls, decorators, argument expansion and unsuccessful probes
return `UNRESOLVED`, never `REFUTED`. Its `CONFIRMED` is a function-slice input-control witness
under a modeled request and builtin eval, not a full application exploit. Both validators share
the repository index, so distinct checks must not be described as statistically independent.

Validation adapters invoke registered, project-owned callbacks. Source indexing opens
repository files relative to directory descriptors and refuses symlinks, including
symlinked parent directories. Fixture and HTTP application callbacks run in disposable
Linux children with resource limits, a deadline, closed inherited descriptors, seccomp,
and Landlock ABI 3 or newer. Registered `read_roots` permit file reads; filesystem writes
are denied. With no read roots, callbacks have no ambient file-read access.
Unavailable isolation prevents callback execution. HTTP validation retains only the
pre-bound loopback listener in the child, and the parent driver disables proxies and
redirect following. Arbitrary package scripts and model-generated shell commands
are outside this callback interface. These are trusted fixture callbacks, not a sandbox
for executing arbitrary hostile Python inside the agent's process memory.

Material model predictions must cite retrieved evidence or runtime-generated tool
citation IDs. `CONFIRMED` and `REFUTED` additionally require a matching cited typed
validator observation bound to the same candidate identity, repository, entry path and
indexed-source digest; tool errors and truncated observations cannot establish those
states. Reading code can support a prediction with `validation_status=UNRESOLVED`,
but cannot manufacture a successful validation result.

`trace_dataflow` reports `MAY_REACH` or `NOT_ESTABLISHED` as an analysis fact and always
retains `UNRESOLVED` validation. Authorization-name/guard checks and source diffs likewise
do not confirm vulnerabilities. Registered fixtures use `candidate_subject(index, candidate)`
to bind their outcomes before execution. An unbound or wrong-subject fixture cannot validate
a candidate. Python import aliases and module assignments are retained so that unresolved
external calls and builtin shadowing cannot silently become concrete eval witnesses.

## Code-RAG tiers

The verified VulnGym entries are dominated by TypeScript, Python, and Go:

- TypeScript-to-TypeScript: 291 entries;
- Python-to-Python: 70 entries;
- Go-to-Go: 19 entries.

Tier 1 therefore provides AST and semantic graph adapters for Python, TypeScript/JavaScript, and Go, covering 380 of 393 verified entries. Tier 2 processes Swift, Vue, YAML, JSX, shell, Svelte, and cross-format cases with file, import, configuration, and trace-aware fallback documents. Metrics are always stratified by adapter tier; fallback results are not described as AST call-graph results.

Every retrieval system receives the same candidate-local base. Text, graph, and hybrid systems receive equal maximum augmentation `top_k` and context budgets. Context units, target rank, graph distance, selected evidence paths, and truncation status are recorded per entry.

Repository tools execute inside a per-ReAct scope derived only from those selected evidence paths. A tool may re-read, search, or traverse within that admitted set, but it cannot turn an E1 local run into repository-wide retrieval or expand an E2/E3 result beyond its selected context. Tool observations share a bounded token budget and are measured separately from the initially retrieved context.

Only an explicit candidate projection (`candidate_id`, repository, path, and line) is model-visible; caller metadata and the retrieval query are not copied into prompts. Initial context accounting measures the complete serialized projection, not just source text. Tool prompts contain the tool name, status, bounded content, a runtime-generated citation ID, and an optional typed validation status. Raw audit metadata and backend evidence identifiers stay in the trace. The complete serialized tool prompt is charged to the observation budget.

The Agent runtime uses UTF-8 byte upper bounds for those serialized text payloads,
reported as `context_accounting=utf8-byte-upper-bound`. Long unbroken identifiers
therefore cannot count as a single budget unit. Historical deterministic OWASP/VulnGym
proxy functions retain their lexical accounting; their existing artifacts are not
reinterpreted or recomputed. These text budgets do not measure total API billing:
system instructions, schemas, planning/dependency prompts, repeated messages and output
tokens are reflected in provider `usage` when a live model reports it.

Python taint transfer uses AST expressions, positional/keyword argument bindings and
branch joins. Formal parameter extraction also uses Tree-sitter for Java, JS/TS and Go.
The remaining non-Python flow rules are bounded line-based approximations. Dynamic
dispatch, aliases, heap state, arbitrary sanitizers and exploit feasibility are not
fully established by the static flow tool.

## Data lifecycle

### Development

- `google/adk-python`, `PrefectHQ/fastmcp`, and `jlowin/fastmcp` VulnGym entries;
- OWASP BenchmarkJava 1.2, whose aggregate labels and behavior have already been inspected;
- synthetic repositories used only for parser, planner, tool, and workflow tests.

These data are permanently development-only.

### Held-out positive evaluation

All other human-verified VulnGym advisories are grouped by repository and advisory. Ground-truth entry points, critical operations, traces, categories, and descriptions remain evaluator-only until the agent has emitted findings. Matching follows the benchmark's exact normalized paths and ±5-line entry/critical tolerance. Advisory-level recall is primary; entry-level recall is secondary.

### Paired negative evaluation

VulnGym contains vulnerable commits but no fixed commits. Fixed counterparts are accepted only when an OSV record supplies a matching-repository `GIT` range `fixed` event or an unambiguous matching-repository fix commit, and Git proves the vulnerable commit is an ancestor of the fixed commit. Multiple branches select the nearest verified descendant and retain all resolution evidence. Unresolved advisories are excluded with a reason; a parent or arbitrary later commit is never treated as fixed.

OWASP positive/negative executable cases provide a separate controlled FPR benchmark. PrimeVul paired samples may be used as an optional C/C++ discrimination benchmark, not as project-level retrieval evidence.

### Splits

No entry from a development repository can enter held-out results. Held-out reporting includes micro entry/advisory metrics and macro repository metrics so the largest TypeScript repository cannot silently dominate the result. Prompt, rule, hop, rank, and quorum changes after a held-out run create a new exploratory run; they do not replace the original artifact.

## Systems and attribution

- `E1`: local context, one scan ReAct expert;
- `E2`: text Code-RAG, one scan ReAct expert;
- `E3`: graph Code-RAG, one scan ReAct expert;
- `E4`: graph Code-RAG, planner plus three specialists, full review;
- `E5`: the same planner, retrieval, specialists, votes, and full-review policy with an irreversible two-vote fast path.

`E2 -> E3` isolates retrieval. `E3 -> E4` measures planner/specialist/validation adjudication as a bundle and must not be attributed to quorum scheduling. `E4 -> E5` measures scheduling and expert calls only; labels must match.

Full review requires the declared quorum for material votes, including `CONFIRMED` votes.
Typed validator status remains attached to each ballot for evidence inspection; it does not
give one expert a quorum exemption. Static dataflow now always remains `UNRESOLVED`;
historical artifacts retain their old statuses and must not be reinterpreted as exploit proof.
A single material vote with two abstentions
therefore produces `ABSTAIN`, while retaining the supporting validator observation.

The concrete-probe integration check is documented in `QUORUM_APPLICABLE_VERIFICATION.md`.

## Metrics

Every result contains raw denominators and, where applicable:

- candidate and advisory recall;
- precision, population FPR, covered FPR, coverage, abstain rate, and strict/covered recall;
- entry/critical localization and full-trace coverage;
- graph-versus-text paired wins, losses, ties, ranks, distances, and token use;
- validation confirmed/refuted/unresolved counts;
- per-expert calls, model calls, tool calls, tokens, latency, fast/slow paths, and label crossings;
- paired vulnerable/fixed deltas;
- project/advisory-clustered bootstrap intervals for held-out claims.

No target improvement percentage is encoded as a gate or baseline. A negative or null result remains a valid result.

## Narrow Harness protections

The executable Harness rejects only failures already demonstrated in this project:

- a scripted heuristic run cannot be labeled as a live ReAct result;
- a material expert vote cannot omit its model/tool/observation trace;
- repository tools cannot read or traverse paths that retrieval did not admit, and their observations cannot exceed the declared context budget;
- a planner cannot assign a validator to an expert that does not expose that validator;
- development or oracle data cannot become claim eligible;
- local configuration cannot override shared retrieval or scheduling contracts;
- result summaries must recompute from per-entry records and bind to actual Git revisions;
- E4/E5 label divergence invalidates the fast-path ablation.

Git revisions, `uv.lock`, typed schemas, ordinary tests, and result manifests remain the primary reproducibility mechanisms. No output hash, frozen metric baseline, or desired-result gate is added.

## Completion criteria

Architectural reproduction is complete when:

1. all graph nodes, ReAct loops, tools, validators, and E1-E5 variants are executable;
2. Python, TypeScript/JavaScript, and Go Tier-1 adapters pass cross-file fixtures;
3. a live model completes the development suite with replayable traces;
4. held-out VulnGym findings are emitted before evaluator labels are loaded;
5. paired negative and OWASP results report FPR with recall and coverage;
6. full and fast adjudication labels are identical and call savings are measured;
7. every artifact passes the central result validator and records model, code, and data provenance.
