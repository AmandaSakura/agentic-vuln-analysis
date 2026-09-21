# Python held-out advisory pair experiment result (2026-09-20)

## Latest offline re-review: recorded pass does not establish validator correctness

The subsequent [result review](PYTHON_PAIR_RESULT_REVIEW_2026-09-20.md) independently confirmed 28 label-matching decisions, two declared E1 abstentions, 269 requests and 1,218,464 reported tokens in the final matrix below. The unchanged implementation still passes 547 tests. However, additional offline counterexamples reproduced unsound permission confirmations/refutations, unsafe command construction reported as SANITIZED that rejects VULNERABLE conclusions, and duplicate result rows silently overwritten by acceptance. These are known unresolved defects; the earlier no-known-blockers conclusion is withdrawn. This does not establish that the 28 original predictions are wrong. Original artifacts and their configured acceptance are preserved. No additional model requests were made; the review contains reproductions and concrete repair/acceptance requirements.

## Final corrected run: accepted 30-cell matrix (2026-09-20)

This section supersedes the earlier failed gate/full-run notes below. The historical artifacts remain preserved, but the current implementation and v2 acceptance criteria are the ones described here.

Implemented final fixes after the failed full run:

- E2 text retrieval now keeps textually retrieved `get_cmd` command-construction helpers in the initial command-injection context instead of allowing same-file backend spans to crowd them out. This fixed hp003 E2 on both vulnerable and fixed sides without giving E2 graph retrieval.
- Planner validation now uses both retrieved evidence and the model-visible `analysis_scope` for command-construction requirements, requires scan and taint `inspect_command_construction`, and rejects redundant scan validators that delay the final ballot. This fixed the hp003_b E4 ReAct-budget exhaustion.
- Full-matrix acceptance now supports explicit `expected_abstentions` in config. Only `hp003_a/E1` and `hp003_b/E1` are declared expected abstentions, because E1 has only the local `serve` span and cannot inspect `mlflow/pyfunc/mlserver.py::get_cmd`. Other abstentions or failures still fail acceptance.

Verification before live expansion:

```sh
uv run --no-sync pytest
uv run --no-sync cv-agent harness-check
git diff --check
```

Result: **547 passed**, harness-check **PASS**, and diff check passed.

The final 10-cell gate was `artifacts/python_heldout_pair_gate_v2/cb817f80abe94e0a9f5fb9ab7c60df72`: **10/10 completed correctly**, `passed: true`, no issues. The gate included `hp003_b E4`, which completed SAFE after the planner repair.

The final full matrix was `artifacts/python_heldout_pair_matrix/17fadccd191d4d71bdb74483cbe5a28b`: **passed**, no issues, no automatic expansion. It planned 30 cells at concurrency 2. Results by hp003 row, the previously failing cluster:

| Cell | Status | Prediction | Ground truth | Note |
| --- | --- | --- | --- | --- |
| `hp003_a E1` | abstained | ABSTAIN | VULNERABLE | Expected E1 local-only limitation |
| `hp003_a E2` | completed | VULNERABLE | VULNERABLE | Text retrieval now admits `mlserver.py::get_cmd` |
| `hp003_a E3` | completed | VULNERABLE | VULNERABLE | Graph retrieval |
| `hp003_a E4` | completed | VULNERABLE | VULNERABLE | Planner + multi-expert path repaired |
| `hp003_a E5` | completed | VULNERABLE | VULNERABLE | Fast quorum |
| `hp003_b E1` | abstained | ABSTAIN | SAFE | Expected E1 local-only limitation |
| `hp003_b E2` | completed | SAFE | SAFE | Text retrieval now admits quoted helper |
| `hp003_b E3` | completed | SAFE | SAFE | Graph retrieval |
| `hp003_b E4` | completed | SAFE | SAFE | No ReAct-budget exhaustion |
| `hp003_b E5` | completed | SAFE | SAFE | Fast quorum |

System metrics from the accepted full run:

| System | TP | TN | FP | FN | Abstained | Failed | Coverage | Strict recall | Population FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| E1 | 2 | 2 | 0 | 0 | 2 | 0 | 0.667 | 0.667 | 0.000 |
| E2 | 3 | 3 | 0 | 0 | 0 | 0 | 1.000 | 1.000 | 0.000 |
| E3 | 3 | 3 | 0 | 0 | 0 | 0 | 1.000 | 1.000 | 0.000 |
| E4 | 3 | 3 | 0 | 0 | 0 | 0 | 1.000 | 1.000 | 0.000 |
| E5 | 3 | 3 | 0 | 0 | 0 | 0 | 1.000 | 1.000 | 0.000 |

Usage for the accepted full run: **269 requests**, **269 responses**, **0 invalid responses**, **0 requests without reported usage**, **1,218,464 reported tokens**, returned model `gemini-3.8-flash`.

Reproduce the final full run, after setting the local API environment without printing secrets:

```sh
set -a
source ~/.config/cliproxyapi/client.env
set +a
export ANTIGRAVITY_API_KEY="${ANTIGRAVITY_API_KEY:-$OPENAI_API_KEY}"
export PYTHONUNBUFFERED=1
uv run --no-sync python scripts/run_python_heldout_pair_matrix.py
```


## Latest correction: validation semantics and quorum (2026-09-20)

The later gate `027a919a39a94276825cf5f2b17773f8` recorded 10/10 accepted
cells. The following full run `1c49acb1a7294a1f893988dabd42c50f` attempted
30 cells: 28 met its then-configured checks; `hp003_a E5` and `hp003_b E4`
failed with `upstream_blocked: OTHER`. It used 215 requests and 728,120
reported tokens. No process remained running when progress was checked.

Those apparent passes are not valid correctness acceptance for the current
implementation. Review found that intervening edits had promoted regex matches
for chmod and MLserver command construction to CONFIRMED/REFUTED, and allowed
one typed vote to bypass the declared quorum. The MLserver shortcut also read
helpers outside admitted retrieval paths. These violated the test contract.
Historical artifacts remain unchanged; do not use them to substantiate safety
or comparative gains.

The corrective changes restore UNRESOLVED static signals, remove the hidden
MLserver helper scan, and require the declared number of independent ballots.
The chmod signal also now parses decimal Python integer literals as decimal.
New regression checks reproduced the invalid confirmations, refutations,
unadmitted helper access, literal parsing error and quorum bypass before repair.

The most recent Planner restriction also broke five offline tests: scripted
planners still requested get_callees after only read_span was exposed. Scripted
workflows now read the candidate span, and the Planner prompt explicitly requires
that read; it previously asked for direct planning despite the mandatory tool
observation contract. Full offline verification and a new cross-pair 10-cell gate
are required before any further expansion. All three pairs have now guided
repairs and are development/regression material, regardless of historical
`heldout` filenames.

Verification after these corrections: `uv run --no-sync pytest` reported
**526 passed in 24.34s**, `uv run --no-sync cv-agent harness-check` returned
**PASS**, and `git diff --check` passed. The new live gate is
`artifacts/python_heldout_pair_gate_v2/60fdb76321d44683b9b0186449aa083a`,
10 cells across the three pairs, concurrency 2. Its own pre-request full suite
also passed (526 tests); completed results follow.

### Completed corrected gate

The corrected 10-cell gate completed with **6 correct predictions, 2 false
positives, 1 abstention and 1 transport failure**. Acceptance is **FAIL**; no
subsequent full matrix was launched. It recorded 107 requests, 106 valid
responses, 1 invalid response and 441,552 reported tokens, including the failed
response. Every request reported usage. There were no retries or substituted
predictions.

|Cell|Outcome|Observed cause / remaining limitation|
|---|---|---|
|`hp001_b E1`|Failed|Native response `bYmvapmSH47PjuMP4PffyQE`, request `fa953a32312b4549adbcfa039ac2ca5a`: `promptFeedback.blockReason=OTHER`, zero candidates, requested and upstream max-output tokens both 6000. This was the first request for the cell; it was not caused by a long correction loop. No keyword or concurrency cause is established.|
|`hp001_b E5`|Abstained|Scan observed mode `0o750` but had only UNRESOLVED static evidence; taint was inconclusive and authz considered the mechanism outside its scope. No two material votes existed. Retaining ABSTAIN is correct under the current capability and quorum contract.|
|`hp003_b E4`|False positive|Scan and taint voted VULNERABLE/UNRESOLVED from the shell execution sink. The complete `mlserver.py::get_cmd` span, including `shlex.quote(model_uri)`, was present in both experts' initial context. They did not inspect that counter-evidence with their tools. This is an evidence-use failure, not missing retrieval in this run.|
|`hp003_b E5`|False positive|The same two expert hypotheses formed a fast quorum despite visible quoting counter-evidence. Counting two experts does not establish independent reasoning or correctness.|

The other six cells matched the configured labels. No cell in this gate
establishes whole-project exploitability or safety. Earlier 10/10 and 28/30
figures remain historical results under the invalidated semantics described
above; they are not the current acceptance status.

### Concrete remaining repair proposal

1. **Cross-file counter-evidence review** (`src/cv_agent/agent_types.py`,
   `agentic_workflow.py`, `react_engine.py`, and corresponding evidence/workflow
   tests): give material expert conclusions explicit supporting observations,
   counter-observations and unresolved call edges. Require scan/taint tasks to
   inspect the admitted construction/transform span before claiming that a
   downstream shell command is unsanitized. Record tool-backed checks of that
   span without adding paths outside the shared retrieval budget. A contradictory
   sanitizer signal requires an explained dataflow relation or ABSTAIN; its
   presence alone must not manufacture SAFE/REFUTED. Offline controls must include
   unquoted input, correctly quoted input, quoting an unrelated variable,
   overwritten sanitized values and unavailable callees. Keep quorum unchanged.
2. **Permission-specific bounded validation** (`src/cv_agent/validation_tools.py`,
   `agent_types.py`, a new permission probe module and its tests): model the
   actual candidate operation and its target under explicit environment/branch
   assumptions. Observe resulting mode and include a restrictive positive
   control, a world-writable control, dead code, shadowed chmod, multiple targets
   and later permission changes. Bind observations to the exact source digest
   and hypothesis. A test of the non-Databricks directory branch may establish
   that branch's permission behavior; it cannot refute every environment or
   prove/refute an end-to-end race exploit. Unsupported semantics stay unresolved.
   Do not reuse regex matches as candidate proof or lower quorum to get a pass.
3. **Provider diagnostic disposition**: preserve the already correlated native
   block and request above. The current provider supplied no more specific reason
   than OTHER. Local parsing, logging and output-budget forwarding are working
   for this request; no confirmed local transport fix follows from this evidence.
   Do not relabel this result, automatically retry it until successful, or
   declare a keyword/concurrency explanation without controlled evidence.

After implementation, require complete offline tests and harness-check, then
one versioned gate of at most 10 cells with declared request/elapsed-time limits.
Only a passing gate permits another full matrix. Retain unsuccessful runs in
the ledger. These are regression cases used to guide repairs; an untouched split
is still needed for comparative research claims.

## Post-run audit correction (2026-09-20)

The metrics below preserve the original run and its configured labels. A subsequent source audit found that at least two configured fixed-side SAFE labels are unsupported. These metrics must not be used as verified false-positive rates or evidence of comparative research gains. Raw results, labels and run artifacts have not been rewritten; no additional model requests were made for this audit.

|Case|Source evidence|Consequence|
|---|---|---|
|`hp003_b`|Commit `1d7c8d4cf0a67d407499a8a4ffac387ea4f8194a` changes permissions in `get_or_create_tmp_dir`, whereas this case targets `get_or_create_nfs_tmp_dir`. The latter retains `os.chmod(tmp_nfs_dir, 0o777)` at `mlflow/utils/file_utils.py:796` in the configured fixed checkout.|A fix for another function does not establish that this candidate is SAFE. Its VULNERABLE predictions cannot currently be counted as verified false positives.|
|`hp004_b`|Commit `5bf2ec2bd4222a18d78631183ac7f6b752afe8a4` fixes artifact path traversal, while this candidate concerns default administrator credentials. Its `basic_auth.ini:5` still contains a hardcoded default password, which `read_auth_config` reads and `create_app` passes into `create_admin_user`.|The configured negative is not a verified repair of the scoped weakness. E4/E5's SAFE predictions on this side do not establish true negatives.|

The preparation script selects the first same-repository commit reference on an advisory page (`scripts/prepare_python_heldout_pairs.py:167`). Repository identity, ancestry and source-file existence do not verify that a commit repairs the exact candidate. Candidate-specific repair validation is missing. The two findings above are source audits, not newly executed exploit reproductions; the other pairs still require semantic validation.

Additional conclusions from the stored traces and source:

- The 7 pairs cover only 5 distinct advisories across 3 repositories. `hp002`/`hp003` and `hp006`/`hp007` share advisories. Seventy cells are repeated system evaluations of 14 snapshots, not 70 independent vulnerabilities. Models receive advisory-derived titles, entry/sink snippets and candidate locations; this evaluates seeded candidate analysis, not repository-wide discovery.
- `build_package_index` indexes only `*.py`. It omits `basic_auth.ini`, the source of the default-password weakness in `hp004`. In `hp004_a` E4, scan and taint vote SAFE with UNRESOLVED validation and local negative findings; their majority overrides authz's VULNERABLE vote. Missing relevant evidence must not be treated as evidence of safety.
- For `hp006_b`, the actual repair is `shlex.quote(model_uri)` in `mlflow/pyfunc/mlserver.py::get_cmd`. The E3 trace repeatedly retrieves `PyFuncBackend.serve` instead; later observations are budget-blocked. This is a concrete failure to surface the relevant cross-file repair under the admitted retrieval scope and observation budget, not proof that increasing total model tokens alone fixes the problem.
- The summary records 98 expert votes, all UNRESOLVED, with zero CONFIRMED and zero REFUTED validator statuses. Labels are model judgments without matching validator confirmation; they are not 55 successful vulnerability reproductions.
- Under the original, disputed labels, E3 finds 6/7 positives versus E2's 5/7. E4/E5 have 2 false positives versus E3's 3, but find 5/7 positives and explicitly miss `hp004_a`. These small, label-sensitive differences do not support the proposed +28% recall or -37% false-positive claims.
- E5 uses 186 requests versus E4's 194 (4.1% fewer). Different failed/abstained cells and independent model executions prevent attributing that difference solely to fast quorum. Shared-vote replay is needed to isolate stopping-policy effects; repeated matched runs are needed for live cost estimates.
- All 70 cells were attempted; 55 produced binary decisions, 6 abstained and 9 failed. This is 78.6% decision coverage. Eight failures report `upstream_blocked: OTHER`, and one exhausts the 8-step ReAct limit. `OTHER` does not identify a keyword trigger or demonstrate a concurrency cause.

Recommended repair order and acceptance criteria:

1. Audit each candidate's source, actual repair and bounded behavior; quarantine unsupported negatives in a new versioned manifest. Add regressions for unrelated advisory commit links and partial fixes. Preserve this run as historical evidence.
2. Admit relevant configuration files and resolve the cross-file caller/callee context within equal E2/E3 retrieval budgets. Verify that the default-credential configuration and quoted command construction are actually retrievable. Keep patch/label knowledge in the evaluator, outside detector prompts.
3. Make expert applicability and evidence sufficiency explicit: an expert that cannot inspect the scoped mechanism must not cast a SAFE vote based solely on no local pattern matches. Keep vulnerable and genuinely repaired controls in regression tests; retain separate prediction and validation statuses.
4. Repair unproductive repeated tool use and budget exhaustion; preserve and correlate local proxy diagnostics for blocked responses. Count failures without silent retries or relabeling.
5. Pass the complete offline suite, then run at most 10 targeted live cells covering these failures. After that gate passes, run a versioned matrix. Cases used to guide fixes are development/regression cases for those fixes; final generalization claims require a fresh untouched advisory-level test split and repeated measurements.

## Post-audit repairs implemented (2026-09-20)

The repair plan is saved at `docs/superpowers/plans/2026-09-20-heldout-pair-audit-repair.md`. No model API requests were made during this repair.

Implemented changes:

- `scripts/prepare_python_heldout_pairs.py` now writes a versioned v2 config and manifest. It no longer selects the first advisory commit blindly; it evaluates same-repository commits for candidate-specific repair evidence and quarantines unsupported fixed sides.
- The regenerated v2 set is `configs/python_heldout_pairs_v2.json` with manifest `artifacts/python_heldout_pair_preparation_v2/manifest.json`. Config SHA-256 from the preparation run is `0652618d2b17c30173084efe290659a6171dca2ccea1963d367650e6017dfcd4`.
- The v2 set contains 3 pairs / 30 cells across MLflow and Langflow. The known bad negatives are excluded: `entry-00102` is rejected as `fixed_candidate_not_repaired`, and `entry-00171` is rejected as `fixed_commit_does_not_touch_candidate_or_scope`.
- `src/cv_agent/python_heldout_pair_source.py` now indexes Python plus security-relevant config/text files such as `.ini`, `.toml`, `.yaml`, `.json`, `.env.example` and `.env.sample`. Non-Python files are indexed as fallback documents, so `basic_auth.ini` is searchable and hashed.
- The held-out retrieval query now includes the existing `analysis_scope`, which was already model-visible, so entry-point snippets can help retrieval find config files without adding labels or commit identities to detector prompts.
- `src/cv_agent/python_ast.py` now resolves simple local module alias assignments such as `server_implementation = mlserver if ... else scoring_server`, allowing graph retrieval to reach `mlflow/pyfunc/mlserver.py::get_cmd`.
- `src/cv_agent/react_engine.py` now rejects `SAFE / UNRESOLVED` conclusions that cite only source reads, empty searches, missing graph neighbors, static no-finding results or unestablished dataflow. These must become `ABSTAIN / UNRESOLVED` unless affirmative counter-evidence is cited.
- `scripts/run_python_heldout_pair_matrix.py` now reads the v2 config by default. Historical `configs/python_heldout_pairs.json` and the 70-cell run artifacts remain preserved as the disputed original run.

Verification:

```sh
uv run --no-sync pytest tests/test_python_heldout_pair_config.py tests/test_python_heldout_pair_source.py tests/test_prepare_python_heldout_pairs.py tests/test_python_ast.py tests/test_react_engine.py tests/test_python_heldout_pair_runner.py -q
uv run --no-sync pytest tests/test_agentic_eval.py tests/test_evidence_validation.py tests/test_react_engine.py -q
uv run --no-sync pytest
```

Results: targeted suites passed, then the full suite passed with `489 passed in 23.61s`.

## Follow-up correctness review (2026-09-20)

The previous statement that all weak-SAFE admission bugs were repaired was too broad. The 489-test suite passed again, but new regressions exposed 16 failing cases across two remaining admission gaps:

- The SAFE evidence check accepted observations not covered by its weak-result blacklist, including empty guard results, unresolved probes, a positive sink/search result, another revision's repair, and unrelated or truncated typed refutations.
- Repair preparation accepted changed files even when candidate snippets did not match the vulnerable checkout, and accepted mentioned helper paths without checking that their contents differed between the selected snapshots.

Both gaps are now addressed. SAFE/UNRESOLVED requires an explicit guard/sanitizer signal or a nontruncated typed refutation bound to the current candidate and source snapshot. Static signals remain hypotheses and cannot establish REFUTED. The expert prompt explains this requirement before execution. Preparation requires a source-bound snippet and either a changed candidate snippet or an actually changed scoped helper. These checks establish source-level relevance, not behavioral proof that the fixed revision is safe.

Added 22 regression/positive-control cases. Existing scheduling tests now obtain real sanitizer/guard observations for their scripted SAFE votes; SAFE-majority, resumed-expert and fast-quorum assertions remain covered. Irrelevant authorization analysis abstains rather than predicting SAFE from no findings.

Final verification: `uv run --no-sync pytest` passed with **511 passed in 23.28s**; `uv run --no-sync cv-agent harness-check` returned **PASS**; `git diff --check` passed.

The frozen v2 config and original manifest remain unchanged. All three pairs passed the new source-level audit, recorded separately at `artifacts/python_heldout_pair_preparation_v2/repair_reaudit.json`. Reproduce this local audit with:

```sh
uv run --no-sync python scripts/audit_python_heldout_pair_repairs.py
```

The preparation command intentionally refuses to overwrite a different frozen manifest. Use the audit command above to recheck the existing v2 set; a newly generated selection protocol/manifest requires a new version.

No model API requests were made during this follow-up. A <=10-cell live gate is still required to evaluate the changed model behavior, abstention rate and runtime failures before any full rerun. No claim of bug-free operation or improved vulnerability metrics follows from offline success.

## Scope

This run freezes the independently held-out Python subset that can be paired with GitHub Advisory Database fixed commits. It is a candidate-level paired advisory experiment, not automatic repository-wide vulnerability discovery and not a final claim-eligible benchmark.

The frozen set contains 7 vulnerable/fixed pairs, 14 cases and 70 system cells over E1-E5. The selected repositories are MLflow, Open WebUI and Langflow. Selection required all of the following:

- the source entry comes from `artifacts/vulngym_heldout_preparation_v3/labels.json`;
- the repository is not one of the development repositories;
- the critical operation is in a Python source file;
- the GitHub advisory page contains a same-repository fixed commit;
- the fixed commit is a Git descendant of the vulnerable commit;
- both vulnerable and fixed checkouts contain the target source path.

Frozen config: `configs/python_heldout_pairs.json`.
Preparation manifest: `artifacts/python_heldout_pair_preparation/manifest.json`.
Final run directory: `artifacts/python_heldout_pair_matrix/68d12f1d3a0e4f68beca201c3aa4a448`.

## Repairs made before the final run

Two runner issues were fixed during admission:

1. Full-matrix runners no longer stop the whole matrix on `ABSTAIN` or a single failed model cell. Those outcomes are kept in the denominator and the remaining cells continue. Gate runs remain strict.
2. Held-out fixed-side candidate binding now reuses the vulnerable-side selected symbol before falling back to stale line hints. This fixed a concrete binding bug where Open WebUI's fixed side previously mapped the old line number to `SafePlaywrightURLLoader.alazy_load` instead of the intended `SafeWebBaseLoader._fetch`.

The request budget was raised from 420 to 900 after a completed partial run showed 420 requests were insufficient for 70 cells. Final run used 620 requests.

## Validation before live requests

Commands run before the final live run:

```sh
uv run --no-sync pytest
uv run --no-sync cv-agent harness-check
```

Result: `481 passed` and `harness-check` returned `PASS`.

The live runner also executed its own full pytest gate before model requests:

`artifacts/pytest_gate/fa9b5cd7b5124f13b48c31a421e15d5d/pytest.log`

## Final live result

Acceptance did not pass: all 70 cells were attempted and there were no `not_run` cells. This confirms matrix execution, but the post-run audit above identifies evaluation-label defects as well as model/system failures.

Usage:

- requests: 620
- responses: 612
- invalid responses: 8
- requests without reported usage: 0
- reported total tokens: 2,610,599
- model id: `gemini-3.8-flash`

Status counts:

- completed: 55
- abstained: 6
- failed: 9
- not_run: 0

Eight failed cells were `upstream_blocked: OTHER`; one failed cell exhausted the ReAct 8-step budget.

The following counts are against the original configured labels, including the disputed negatives documented above.

|System|TP|FP|TN|FN|Abstain|Failed|Coverage|Strict recall|Population FPR|Precision|Requests|
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
|E1|6|3|2|0|1|2|0.786|0.857|0.429|0.667|74|
|E2|5|5|2|0|1|1|0.857|0.714|0.714|0.500|90|
|E3|6|3|1|0|3|1|0.714|0.857|0.429|0.667|76|
|E4|5|2|3|1|0|3|0.786|0.714|0.286|0.714|194|
|E5|5|2|3|1|1|2|0.786|0.714|0.286|0.714|186|

## Pair-level observations

- `hp002` is the cleanest pair: all vulnerable cells were VULNERABLE and all fixed cells were SAFE.
- `hp003`, `hp006` and `hp007` were often labeled VULNERABLE on the configured fixed side. The audit invalidates treating `hp003` as a verified negative and identifies missing repair context in `hp006`.
- `hp004` exposes a recall issue for multi-expert systems: E4 and E5 labeled the vulnerable side SAFE.
- `hp005` is mostly correct when cells complete, but several cells were blocked upstream.
- `hp001` still has fixed-side VULNERABLE/ABSTAIN predictions after symbol binding was corrected. Exact repair semantics and retrieved context must be audited before attributing these solely to model behavior.

## Re-run commands

Load the local proxy credentials without printing secrets:

```sh
set -a
source ~/.config/cliproxyapi/client.env
set +a
export ANTIGRAVITY_API_KEY="$OPENAI_API_KEY"
```

Prepare/freeze pairs:

```sh
uv run --no-sync python scripts/prepare_python_heldout_pairs.py
```

Run the held-out pair matrix:

```sh
uv run --no-sync python scripts/run_python_heldout_pair_matrix.py
```

The runner now uses `configs/python_heldout_pairs_v2.json` by default. Start with a <=10-cell live gate before running the full 30-cell v2 matrix.

## Practical conclusion

The original 70-cell run is useful as a diagnosis artifact, but its metrics remain disputed. The known label, retrieval and weak-SAFE bugs found in the audit have now been repaired offline and locked by regression tests. The next valid step is a small live v2 gate, not a claim update: run at most 10 v2 cells, inspect failures and traces, then decide whether the 30-cell v2 matrix is stable enough to run.

## 10-cell gate attempts after repair

A dedicated gate entrypoint was added:

```sh
uv run --no-sync python scripts/run_python_heldout_pair_gate.py
```

It uses `configs/python_heldout_pair_gate_v2.json`, a fixed 10-cell subset: `hp002` vulnerable/fixed cases across E1-E5, with concurrency 2. Each attempt runs the live pytest gate before model requests. The latest offline verification before live calls was:

```sh
uv run --no-sync pytest
uv run --no-sync cv-agent harness-check
```

Result: `516 passed`; `harness-check` returned `PASS`.

Repairs made during gate debugging:

- Added a dedicated held-out gate config and runner so the <=10-cell protocol cannot accidentally run the full 30-cell matrix.
- Reduced model-visible held-out scope text to neutral source-span instructions while retaining the richer advisory text for retrieval query.
- Skipped oversized non-Python fallback assets from held-out source indexing to avoid large irrelevant JSON observations.
- Recognized ownership guards such as `api_key.user_id != user_id` in `get_guards` and `compare_route_and_service_guard`.
- Added `get_guards` to the scan expert so scan-only systems can collect affirmative guard evidence before SAFE/UNRESOLVED.
- Added path-aware ranking for explicit file/path queries such as `api_key.py`, without changing ordinary semantic query ranking.
- Stopped replaying invalid final JSON drafts into ReAct correction prompts; only compact validation errors are sent back.

Latest gate run:

`artifacts/python_heldout_pair_gate_v2/daffaa2b15b14775a0492e0aa3798236`

Result: acceptance failed with 9/10 correct cells. The only failed cell was `hp002_a E5`, caused by a provider malformed-function-call response with no assistant text and no tool call. Usage was 105 requests, 104 responses, 1 invalid response, and 275,972 reported tokens. No request in this latest run was classified as `upstream_blocked`.

The gate therefore does not authorize the full 30-cell matrix yet. The code path now produces the expected fixed-side SAFE decisions for all five systems in the latest run, but live provider response stability remains a blocker under the current no-retry experiment contract.
