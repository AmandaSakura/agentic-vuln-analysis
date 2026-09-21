# Full development matrix result — 2026-09-19

This is the completed OWASP BenchmarkJava development matrix for the current agentic harness. It is a development benchmark result, not a held-out or real-project generalization claim.

## Final run

- Full run directory: `artifacts/development_benchmark/523853f48f434210960ede9948d5cce9/`
- Scope: 66 frozen BenchmarkJava cases × E1-E5 = 330 cells
- Entry method: `doPost`
- Model config: `gemini-3.8-flash-high(low)`, `max_tokens=6000`, `thinking_mode=disabled`, timeout 180s
- Concurrency: 1
- Offline gate before live calls: full pytest passed inside the live process
- Total wall time: about 155.5 minutes

## Current-source admission gate

The full run was admitted by the latest current-source ten-trial gate:

- Gate directory: `artifacts/development_benchmark/a4643644fd3a40dab01f15cbba68b4ca/`
- Result: 10/10 completed with expected labels
- `acceptance.json`: `passed: true`, `issues: []`
- Requests: 63
- Reported tokens: 253,870
- Native diagnostics: 63/63 `upstream_response`; output limit status 63/63 `matched`
- Max observed reasoning tokens: 528

Earlier passing gates using `gemini-3.8-flash-high` and/or higher concurrency are historical after the later source/config changes.

## Full run status counts

| Status | Count |
| --- | ---: |
| completed | 319 |
| abstained | 10 |
| failed | 1 |
| not_run/interrupted | 0 |

Per system:

| System | completed | abstained | failed |
| --- | ---: | ---: | ---: |
| E1 | 64 | 2 | 0 |
| E2 | 63 | 2 | 1 |
| E3 | 66 | 0 | 0 |
| E4 | 64 | 2 | 0 |
| E5 | 62 | 4 | 0 |

The single failed cell is `BenchmarkTest00954/E2`. Its error was `upstream_blocked: OTHER` after 8 model calls and 7 tool calls. Native diagnostics classify it as one Gemini upstream block with reported usage and matched output-token limit. A single-cell diagnostic rerun of the same case/system completed without transport failure:

- Rerun directory: `artifacts/development_benchmark/single_rerun_8c3e7b6d399c45c2a9505ea76f30d14d/`
- Rerun status: `completed`
- Rerun prediction: `VULNERABLE`
- Frozen label: `SAFE`
- Rerun requests: 7, diagnostics 7/7 `upstream_response`

Therefore the full-run failure is best recorded as a transient upstream empty response. The rerun does not overwrite the formal full run; it only diagnoses the failure mode. If interpreted as the model outcome rather than transport failure, this cell would be a false positive.

## Usage and transport diagnostics

- Model requests: 2,054
- Responses with provider usage: 2,053 normal responses plus 1 invalid/blocked response with reported usage
- Reported total tokens: 7,018,656
- Requests without reported usage: 0
- Usage conflicts: 0
- Orphaned responses: 0
- Duplicate request starts: 0
- Native diagnostics: 2,053 `upstream_response`, 1 `upstream_blocked`
- Block reason: `OTHER` × 1
- Output-token limit status: 2,054/2,054 `matched`
- Max observed reasoning tokens: 1,980
- Monetary cost: unknown; pricing was not available and is not treated as zero

## System metrics

| System | TP | FP | TN | FN | Abstain | Failed | Coverage | Strict recall | Population FPR | Requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| E1 | 29 | 15 | 17 | 3 | 2 | 0 | 0.9697 | 0.8788 | 0.4545 | 288 |
| E2 | 27 | 13 | 18 | 5 | 2 | 1 | 0.9545 | 0.8182 | 0.3939 | 288 |
| E3 | 27 | 2 | 31 | 6 | 0 | 0 | 1.0000 | 0.8182 | 0.0606 | 165 |
| E4 | 26 | 5 | 28 | 5 | 2 | 0 | 0.9697 | 0.7879 | 0.1515 | 781 |
| E5 | 26 | 5 | 28 | 3 | 4 | 0 | 0.9394 | 0.7879 | 0.1515 | 532 |

Paired summary:

| Pair | Left wins | Right wins | Ties | Unavailable | Completed label disagreements |
| --- | ---: | ---: | ---: | ---: | ---: |
| E2 vs E3 | 1 | 13 | 51 | 1 | 14 |
| E3 vs E4 | 5 | 1 | 60 | 0 | 6 |
| E4 vs E5 | 2 | 2 | 62 | 0 | 4 |

## Fixes made before the final run

The final full run used the following stability repairs:

- Added candidate-bound Java command-boundary fixture support for the fixed cmdi development pair.
- Wired the same registered fixture tools into ten-trial and full development runners.
- Fixed acceptance revalidation so `local:`, `text:`, `graph:`, and `hybrid:` retrieved evidence can be cited as initial evidence.
- Restricted planned expert subtasks to the assigned validator instead of exposing every validator to every expert.
- Compacted planner prompts to candidate identity and retrieved-evidence indexes instead of embedding full retrieved code in the planner prompt.
- Added compact planner-output schema bounds and a short final-JSON contract.
- Added expert final-rationale schema bounds to prevent long final JSON truncation.
- Raised live output budget to 6,000 tokens and timeout to 180 seconds.
- Switched the long full run to `gemini-3.8-flash-high(low)` and concurrency 1 after high-strength concurrency 2 exhausted the local upstream/auth pool during a previous full attempt.

These repairs do not add automatic retry/fallback behavior to the experiment logic.

## Local verification commands

Latest offline verification before the final full run:

```sh
uv run --no-sync pytest
# 410 passed in 21.69s

uv run --no-sync cv-agent harness-check
# status: PASS
```

Current-source ten-trial gate:

```sh
set -a
source /home/joker/.config/cliproxyapi/client.env
export ANTIGRAVITY_API_KEY="$OPENAI_API_KEY"
set +a
uv run --no-sync python scripts/run_development_ten_trial.py
```

Full development matrix:

```sh
set -a
source /home/joker/.config/cliproxyapi/client.env
export ANTIGRAVITY_API_KEY="$OPENAI_API_KEY"
set +a
uv run --no-sync python scripts/run_development_benchmark.py
```

Do not paste local API keys into chat or result documents.
