# Python repository discovery and bounded evaluation

This change connects source-only Python discovery to the live agent pipeline and a separate reference scorer. It also repairs expert evidence handling. Historical E1–E5 development results are preserved; new code does not retroactively improve their metrics.

## Detector input and discovery

- `src/cv_agent/repository_discovery.py` parses a configured Python source root, includes function and module-level operations, records every parsed file's SHA-256 and all parse errors, and produces a complete candidate inventory.
- `src/cv_agent/scanner.py` classifies Python AST calls for command execution, dynamic evaluation, database operations, template operations, dynamic attribute access and process control, and emits authorization-boundary candidates for decorated routes. These are hypotheses, not vulnerability confirmations.
- Imports and aliases are recognized. Comments and literal strings do not become operations. Overlapping nested-function spans produce one candidate at the smallest enclosing span. Indented methods containing unindented multiline string contents retain their original source lines.
- Candidate hypotheses are derived from source rules. Model-visible identities are neutral and contain no checkout role, commit hash, advisory ID or expected label.
- Configure `source_prefix` at a package's parent so absolute package imports retain their module names. The complete source inventory is persisted before any model request; a pilot selects the first N candidates by source path, line and rule.

## Expert evidence changes

- A planner-assigned task retains its expert's repository inspection tools and its assigned validator. Other validators remain excluded for that task.
- A dependent expert receives its peers' tool observations and provenance, without their prediction labels, confidence or rationale. Its own previous judgments remain available for cumulative tasks.
- A material prediction cannot ignore a contradictory, complete, candidate-and-source-bound concrete validator result, even if its declared validation status is UNRESOLVED. Unrelated or truncated evidence cannot veto a prediction; conflicting evidence can lead to ABSTAIN.
- The quorum API rejects duplicate ballots from the same expert. Fixed-vote fast/full equivalence tests remain in the suite.

These changes address implementation and evidence-handling problems. They do not establish that multiple experts improve accuracy over E3.

## Running and scoring

The completed live check contained 8 development cells: two source-discovered candidates from each pinned LangChain checkout, evaluated with E3 and E5; and 2 independent-input cells from the pinned NLTK checkout. NLTK was selected as a Python repository from the frozen input manifest without consulting its advisory labels or locations. Its subsequent reference score exposed the missing process-control rule; after using that finding for development, NLTK is excluded from future independent claims.

Current configuration: `configs/python_repository_pilot.json` retains the 8-cell LangChain pilot; `configs/python_nltk_development_pilot.json` records NLTK as development. `configs/python_heldout_pilot.json` now selects a pinned MLflow subject from the new v3 independent manifest for a future two-cell pilot. No MLflow model evaluation was run in this turn. The historical live runs preserve their original config and exact implementation snapshots.

The two pilots together contain at most 10 cells. They are integration checks with source-only selection, not a replacement for the earlier label-verified ten-trial admission gate. They cannot authorize an automatic full-matrix expansion.

```sh
# Prepare the explicit independent source checkout; no labels or API calls.
uv run --no-sync python scripts/prepare_python_heldout_pilot.py

# Offline verification; no credentials required.
uv run --no-sync pytest
uv run --no-sync cv-agent harness-check

# Runtime credentials are loaded only into the process environment.
set -a
source /home/joker/.config/cliproxyapi/client.env
export ANTIGRAVITY_API_KEY="$OPENAI_API_KEY"
set +a

uv run --no-sync python scripts/run_python_repository_pilot.py
uv run --no-sync python scripts/run_python_heldout_pilot.py
```

Both live entrypoints use the existing full-pytest transport gate and journal. The first failed/interrupted cell stops further work; remaining cells retain `not_run`. No automatic retry or provider fallback is added. Results are written incrementally, and completed run directories are never overwritten.

The evaluator runs only after detector results have been written:

```sh
uv run --no-sync python scripts/score_python_repository_pilot.py \
  artifacts/python_repository_pilot/RUN_ID \
  artifacts/vulngym_heldout_preparation_v3/labels.json
```

For development discovery coverage, use `data/raw/VulnGym/data/entries.jsonl` as the reference file instead. The scorer joins by exact repository, commit, critical-operation path and source line; nearby calls or the same function do not count as a hit. It reports entry and advisory detection separately. Unreviewed candidates remain visible and make recall provisional. Positive-only references cannot define a negative population, so false-positive rate is explicitly unavailable; unmatched predictions are never automatically labeled false positives.

## Verification record

- Full offline suite before live checks: **444 passed in 21.65 seconds**; both live processes also passed their own full-pytest admission.
- Final offline suite after the reflection/process-control and split-isolation repairs: **452 passed in 20.51 seconds**. This includes real LangChain benign/attribute/dunder pair probes and source-discovery-to-LangGraph tests with a real bounded eval validator and scripted model.
- `cv-agent harness-check`: PASS.
- Real source discovery: 321 files per LangChain revision and 369 NLTK files; all parsed successfully.

| Check | Run directory under `artifacts/` | Outcome | Requests | Reported tokens |
| --- | --- | --- | ---: | ---: |
| Development live pipeline | `python_repository_pilot/640671c08eec46839689b374f5ad70f1` | 8/8 completed, all SAFE predictions | 56 | 110,982 |
| Independent-input pilot before NLTK tuning | `python_repository_pilot/714c0c9e9f474e7f9e34055a467a3d94` | 2/2 completed, both SAFE predictions | 10 | 42,580 |
| LangChain discovery after repair | `python_discovery_audit/6ccf1f9619084640991633d574fa52aa` | 453 total candidates; 3/3 reference locations matched | 0 | 0 |
| NLTK discovery after repair, now development | `python_discovery_audit/73f491a143a040809b53407c6b588543` | 299 candidates; 1/1 reference location matched | 0 | 0 |

Total live usage: **66 requests, 153,562 reported tokens**; 66/66 native diagnostics `upstream_response`, 66/66 output limits matched, no invalid responses or missing usage. Monetary cost remains unknown.

All ten live cells reached a material prediction. Their selected candidates were not reference-labeled vulnerability cases; this is an integration result, not ten verified correct vulnerability classifications. The complete initial inventory matched two of three LangChain reference locations and zero of one NLTK reference locations. The later two scanner rules close these observed discovery gaps in offline checks. That post-repair discovery coverage is development evidence, not held-out model recall, and no additional live cells were run after those rule additions.

The effective independent split is now `configs/vulngym_heldout_inputs_v3.json`: **18 repositories, 173 advisories, 378 positive entries, 156 source commits**. `configs/heldout_preparation_v3.json` and `artifacts/vulngym_heldout_preparation_v3/` preserve the exclusion reasons and evaluator-only labels. The Harness development-repository list includes both LangChain and NLTK. Historical v2 artifacts remain unchanged.

## Further evaluation protocol

Freeze code and detector configuration before scoring independent data. NLTK is now development data under v3. The next declared independent check uses MLflow and the same E3/E5 two-cell limit; it is configured but not run, preserving this turn's ten-cell limit. Full candidate review and independently verified fixed counterparts are still required before reporting independent recall and false-positive rate. A source-derived hypothesis match and an LLM prediction must not be presented as a reproduced exploit. The final source revision must pass a new live admission before further calls; the 10-cell live results above precede the last scanner extensions.
