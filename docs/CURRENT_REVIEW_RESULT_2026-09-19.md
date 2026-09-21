# Current-version review and repair — 2026-09-19

## Outcome

Follow-up bug repair: full suite **377 passed in 9.64s**, Harness check PASS.
R7 below records the additional demonstrated generator defect and its repair.
The 371-test result below describes the preceding review.

The review found additional correctness gaps despite the earlier 363-test pass
and successful E1 pair. Demonstrated defects were reproduced before repair;
the updated full suite has **371 passing tests (9.49s)**. Harness check passes.
No model API requests were made during this review. Existing uncommitted work,
historical experiments and the original frozen held-out split were preserved.

## Scope

Reviewed current candidate construction/rendering, Python concrete probes,
evidence subjects and final validation, planner/expert task scheduling,
full/fast adjudication, benchmark accounting, held-out preparation, scanner
coverage reporting, native proxy diagnostics and current status documentation.
Existing tests cover the scheduling, tool-budget and evidence boundaries.
This is a targeted semantic review of the research pipeline, not exhaustive
verification of every adapter, third-party dependency or possible Python program.

## Findings and implemented repairs

### R1: probe evaluated arguments before resolving the callable

`missing(eval(request.args["x"]))` returned `CONFIRMED` even though resolving
`missing` would fail before the nested argument executes. The interpreter now
establishes a supported callable before evaluating arguments. A supported local
`identity(eval(...))` remains a positive witness. Unknown external semantics
stay unresolved rather than producing evidence of execution.

Files: `src/cv_agent/python_probe.py`, `tests/test_current_review.py`.

### R2: local import binding was omitted

An `eval(...)` followed by `import math as eval` in the same function returned
`CONFIRMED`; Python instead treats `eval` as a local name and raises an unbound
local error at the earlier call. Local names now come from Python's symbol
table, including import and function bindings. A nested-definition negative
control and existing alias/builtin positive controls remain passing.

### R3: declared LangChain analysis scope never reached the model

The two-hypothesis limitation was stored in `Candidate.query`, which the model
renderer intentionally omits to prevent retrieval hints/labels leaking into
prompts. New optional `Candidate.analysis_scope` is explicitly model-visible,
included in context budgeting, and incorporated into `ValidationSubject`.
The pair runner sets the scope independently of private query/metadata. Tests
check both positive and negative fixture paths through the Agent pipeline,
budget rejection and identity changes when the hypothesis changes.

The earlier successful pair is retained as historical evidence. Its tools
already exposed limited traversal evidence, but that run did not contain the
new explicit candidate scope; it is not a live validation of the updated prompt.

Files: `types.py`, `agent_types.py`, `agent_tools.py`, `agentic_workflow.py`,
`scripts/run_langchain_pair_eval.py`, and related tests.

### R4: the frozen held-out inputs still included development-used LangChain

The old split excluded only the three initial development repositories. Since
LangChain now informs fixtures and prompts, continuing to use that split would
contaminate held-out claims. A new explicit preparation configuration excludes
all four repositories plus shared advisories, generating version 2 without
overwriting version 1. No held-out model runs had been performed.

- Active inputs: `configs/vulngym_heldout_inputs_v2.json`.
- Preparation: `configs/heldout_preparation_v2.json`.
- Evaluator-only labels/config/summary: `artifacts/vulngym_heldout_preparation_v2/`.
- 19 repositories, 174 advisories, 379 positive records, 157 source checkouts.
- Verified paired fixed negatives: 0; no held-out effectiveness claim.

`scripts/prepare_heldout_inputs.py` now targets the explicit v2 configuration and
continues to reject overwriting an existing frozen output.

### R5: coverage profiling counted any nearby filename match as sink coverage

A candidate on an unrelated line in `prompt.py` made `covered_reference_sink`
true. This was reproduced through the actual profiler with a controlled scanner
result. Reference matching now requires the exact source path and sink line.
The hardcoded candidate-count explanation was removed; counts/verdicts are
computed from the current run. This repairs evaluation, not scanner capability.

Fresh real-checkout profile:
`artifacts/langchain_scanner_coverage/b15dcd056f2148fc997b221ff29067f2/`.
Each checkout has 327 source files and 7 candidates; neither hits the reference
template sink. The scanner still lacks template-formatting discovery.

### R6: default native block enum was misclassified as an explicit block

`BLOCK_REASON_UNSPECIFIED` was normalized to `UNKNOWN`, causing an otherwise
normal native response to be classified as `upstream_blocked`. It now becomes
no established block. An explicit `OTHER` remains an established block.
The default enum semantics were checked against the
[Google GenerateContent reference](https://ai.google.dev/api/generate-content#BlockReason).

### R7: calling a generator incorrectly executed its body

The probe confirmed `eval(request.args['x'])` before a later `yield`, even though
calling a Python generator only creates a generator object. Four regressions
failed before repair: ordinary yield, yield-from, unreachable yield and a
cross-file generator helper. Fixed project-owned fixtures also check actual
Python behavior without executing repository code.

`python_probe.py` now checks compiled function flags before interpreting a body.
Compilation does not execute the source. Generator iteration is unsupported and
returns UNRESOLVED. Compiler flags distinguish nested scopes and recognize even
unreachable yields. Two positive controls preserve witnesses in generator-call
arguments and ordinary outer functions containing nested generator definitions.

Validation: six added cases; full suite **377 passed in 9.64s**, Harness PASS,
`git diff --check` clean. No model API calls or proxy changes in this follow-up.

## Verification (preceding R1–R6 review)

- Eight additional cases, including positive controls; full suite **371 passed**.
- `uv run --no-sync cv-agent harness-check`: PASS.
- Real six-probe pair reproduction rerun: normal formatting preserved; vulnerable
  traversal succeeds and fixed traversal is blocked for both declared hypotheses.
  Artifact: `artifacts/langchain_pair_reproduction/192bf6ab497c432a9a39e82b1c3a811b/`.
- Real scanner coverage rerun and new held-out preparation completed offline.
- No model calls, credentials or shared proxy changes were needed for this review.

## Remaining work and current handoff

Automatic template-sink discovery, the complete 330-trial development matrix,
independently verified held-out paired negatives and held-out model evaluation
remain unfinished. The updated analysis scope has not had a fresh live model run.
Intermittent upstream blocking and the proxy's removal of `maxOutputTokens`
are not repaired by better logging.

`PROJECT_STATUS_2026-09-19.md` and `HANDOFF_2026-09-19.md` are now synchronized;
their prior versions are archived with `BEFORE_CURRENT_REVIEW` in the filename.
The older review is explicitly historical. No claim of universal code correctness
or general safety follows from this acceptance result.
