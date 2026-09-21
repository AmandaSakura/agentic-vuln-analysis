# Python Paired Admission Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a strict Python paired-evidence gate: one LangChain pair must pass a 10-cell E1-E5 admission before the two-pair 20-cell controlled matrix can run.

**Architecture:** Model-visible configs hold only neutral repository/candidate descriptors. Evaluator labels live in a separate validation file and are loaded only after trials complete. Each final verdict must cite current-run fixture evidence bound to the exact candidate, source digest, checkout commit, path, line, and analysis scope; matrix expansion revalidates the saved admission against current source, model config, pair descriptors, and external checkout identities.

**Tech Stack:** Python 3, pytest, pydantic, existing `AgenticPipeline`, `run_candidate`, `LockedBudget`, `LockedJournal`, `execute_trials`, `RepositoryIndex`, `full_agent_tools`, native OpenAI-compatible Gemini transport, JSON configs, local git checkouts under `data/diagnostics`.

---

## Boundaries

This is an engineering admission and controlled development diagnostic. The 10-cell gate and 20-cell matrix must not be used to claim broad automatic-discovery recall, real-project false-positive rate, or the original 28%/37% numbers.

Run order:

1. `configs/python_pair_gate.json`: LangChain vulnerable and fixed revisions × E1-E5 = 10 cells.
2. `configs/python_pair_matrix.json`: LangChain plus Jinja vulnerable and fixed revisions × E1-E5 = 20 cells.
3. A larger held-out study is a later project after the controlled matrix is stable.

Concurrency stays at `1`. Observed baselines imply about 60-70 requests and 5-10 minutes for the gate, and about 120-140 requests and 10-20 minutes for the matrix. Keeping concurrency fixed avoids mixing rate-limit, filter, or proxy behavior into the system comparison.

## File Map

- Create `configs/python_pair_gate.json` for the exact 10-cell gate.
- Create `configs/python_pair_matrix.json` for the exact 20-cell matrix.
- Create `validation/python_pair_labels_v1.json` for evaluator-only labels and fixture expectations.
- Create `src/cv_agent/python_pair_config.py` for typed config parsing.
- Create `src/cv_agent/python_pair_fixture.py` for full-package indexing, candidate construction, checkout identity, source hashing, and fixture tool binding.
- Create `src/cv_agent/python_pair_acceptance.py` for gate and matrix artifact validation.
- Create `scripts/prepare_jinja_pair.py`, `scripts/jinja_attr_probe.py`, and `scripts/reproduce_jinja_attr_pair.py`.
- Create `scripts/run_python_pair_gate.py` and `scripts/run_python_pair_matrix.py`; both are no-argument runners.
- Add tests in `tests/test_python_pair_config.py`, `tests/test_python_pair_fixture.py`, `tests/test_python_pair_acceptance.py`, `tests/test_python_pair_runner.py`, and `tests/test_jinja_pair_reproduction.py`.
- Create `docs/PYTHON_PAIR_EXPERIMENT_2026-09-20.md` after the runs.

## Task 1: Freeze Configs And Labels

**Files:**

- Create: `configs/python_pair_gate.json`
- Create: `configs/python_pair_matrix.json`
- Create: `validation/python_pair_labels_v1.json`
- Create: `src/cv_agent/python_pair_config.py`
- Test: `tests/test_python_pair_config.py`

- [ ] **Step 1: Add the gate config**

`configs/python_pair_gate.json` contains exactly one pair, two revisions, five systems, and `concurrency: 1`.

```json
{
  "dataset_name": "Python paired development gate",
  "dataset_role": "paired_development_gate",
  "claim_eligible": false,
  "model_config": "configs/micro_benchmark_gemini_native.json",
  "systems": ["E1", "E2", "E3", "E4", "E5"],
  "concurrency": 1,
  "limits": {"max_requests": 90, "max_seconds": 900},
  "label_file": "validation/python_pair_labels_v1.json",
  "pairs": [
    {
      "pair_id": "langchain_template_traversal",
      "fixture_id": "template_traversal",
      "repository_url": "https://github.com/langchain-ai/langchain",
      "advisory": "GHSA-6qv9-48xg-fc7f",
      "cve": "CVE-2025-65106",
      "source_root": "libs/core",
      "exclude_path_parts": ["tests", "__pycache__"],
      "entry_symbol": "PromptTemplate.from_template",
      "source_scope": "PromptTemplate.from_template f-string attribute and dunder traversal only",
      "analysis_scope": "Assess only f-string attribute and dunder traversal through PromptTemplate.from_template. Use registered template_traversal fixture evidence and preserve the benign control. A negative result applies only to these traversal hypotheses, not general safety.",
      "cases": [
        {
          "case_id": "langchain_template_vulnerable",
          "revision_role": "vulnerable",
          "commit": "b7d1831f9d3560ed4fb45134861eef3f4544eff3",
          "checkout": "data/diagnostics/langchain-vulnerable",
          "file_path": "libs/core/langchain_core/prompts/prompt.py",
          "line_hint": 251
        },
        {
          "case_id": "langchain_template_fixed",
          "revision_role": "fixed",
          "commit": "c4b6ba254e1a49ed91f2e268e6484011c540542a",
          "checkout": "data/diagnostics/langchain-fixed",
          "file_path": "libs/core/langchain_core/prompts/prompt.py",
          "line_hint": 251
        }
      ]
    }
  ]
}
```

- [ ] **Step 2: Add the matrix config**

`configs/python_pair_matrix.json` has the same systems and the same LangChain pair, plus the Jinja pair.

```json
{
  "dataset_name": "Python paired controlled development matrix",
  "dataset_role": "paired_development_matrix",
  "claim_eligible": false,
  "model_config": "configs/micro_benchmark_gemini_native.json",
  "systems": ["E1", "E2", "E3", "E4", "E5"],
  "concurrency": 1,
  "limits": {"max_requests": 180, "max_seconds": 1800},
  "requires_gate_pointer": "artifacts/python_pair_gate.json",
  "label_file": "validation/python_pair_labels_v1.json",
  "pairs": [
    {
      "pair_id": "langchain_template_traversal",
      "fixture_id": "template_traversal",
      "repository_url": "https://github.com/langchain-ai/langchain",
      "advisory": "GHSA-6qv9-48xg-fc7f",
      "cve": "CVE-2025-65106",
      "source_root": "libs/core",
      "exclude_path_parts": ["tests", "__pycache__"],
      "entry_symbol": "PromptTemplate.from_template",
      "source_scope": "PromptTemplate.from_template f-string attribute and dunder traversal only",
      "analysis_scope": "Assess only f-string attribute and dunder traversal through PromptTemplate.from_template. Use registered template_traversal fixture evidence and preserve the benign control. A negative result applies only to these traversal hypotheses, not general safety.",
      "cases": [
        {"case_id": "langchain_template_vulnerable", "revision_role": "vulnerable", "commit": "b7d1831f9d3560ed4fb45134861eef3f4544eff3", "checkout": "data/diagnostics/langchain-vulnerable", "file_path": "libs/core/langchain_core/prompts/prompt.py", "line_hint": 251},
        {"case_id": "langchain_template_fixed", "revision_role": "fixed", "commit": "c4b6ba254e1a49ed91f2e268e6484011c540542a", "checkout": "data/diagnostics/langchain-fixed", "file_path": "libs/core/langchain_core/prompts/prompt.py", "line_hint": 251}
      ]
    },
    {
      "pair_id": "jinja_attr_format_escape",
      "fixture_id": "jinja_attr_format",
      "repository_url": "https://github.com/pallets/jinja",
      "advisory": "GHSA-cpwx-vrp4-4pq7",
      "cve": "CVE-2025-27516",
      "source_root": "src",
      "exclude_path_parts": ["tests", "__pycache__"],
      "entry_symbol": "do_attr",
      "source_scope": "sandbox attr filter access to string format only",
      "analysis_scope": "Assess only whether the sandbox attr filter exposes string format access covered by GHSA-cpwx-vrp4-4pq7. Use registered jinja_attr_format fixture evidence and preserve the benign control. A negative result applies only to this attr-format sandbox hypothesis, not general template safety.",
      "cases": [
        {"case_id": "jinja_attr_vulnerable", "revision_role": "vulnerable", "commit": "877f6e51be8e1765b06d911cfaa9033775f051d1", "checkout": "data/diagnostics/jinja-vulnerable", "file_path": "src/jinja2/filters.py", "line_hint": 1410},
        {"case_id": "jinja_attr_fixed", "revision_role": "fixed", "commit": "15206881c006c79667fe5154fe80c01c65410679", "checkout": "data/diagnostics/jinja-fixed", "file_path": "src/jinja2/filters.py", "line_hint": 1410}
      ]
    }
  ]
}
```

- [ ] **Step 3: Add evaluator-only labels**

`validation/python_pair_labels_v1.json`:

```json
{
  "version": 1,
  "labels": {
    "langchain_template_vulnerable": {"pair_id": "langchain_template_traversal", "revision_role": "vulnerable", "label": "VULNERABLE", "required_validation_status": "CONFIRMED", "required_fixture_status": "EXPLOITED"},
    "langchain_template_fixed": {"pair_id": "langchain_template_traversal", "revision_role": "fixed", "label": "SAFE", "required_validation_status": "REFUTED", "required_fixture_status": "BLOCKED"},
    "jinja_attr_vulnerable": {"pair_id": "jinja_attr_format_escape", "revision_role": "vulnerable", "label": "VULNERABLE", "required_validation_status": "CONFIRMED", "required_fixture_status": "EXPLOITED"},
    "jinja_attr_fixed": {"pair_id": "jinja_attr_format_escape", "revision_role": "fixed", "label": "SAFE", "required_validation_status": "REFUTED", "required_fixture_status": "BLOCKED"}
  }
}
```

- [ ] **Step 4: Add typed config parsing**

`src/cv_agent/python_pair_config.py` defines `PythonPairCase`, `PythonPair`, `PythonPairExperimentConfig`, `PythonPairLabel`, and `PythonPairLabels`. Enforce relative paths, exactly E1-E5, gate size 10, matrix size 20, and `concurrency == 1`.

```python
class PythonPairExperimentConfig(FrozenModel):
    dataset_name: str
    dataset_role: Literal["paired_development_gate", "paired_development_matrix"]
    claim_eligible: Literal[False]
    model_config: str
    systems: tuple[AgentSystemVersion, ...]
    concurrency: Literal[1]
    limits: PythonPairLimits
    label_file: str
    pairs: tuple[PythonPair, ...]
    requires_gate_pointer: str | None = None

    @model_validator(mode="after")
    def validate_experiment(self):
        if self.systems != tuple(AgentSystemVersion):
            raise ValueError("Python pair experiments must run E1 through E5 exactly once")
        cells = len(self.pairs) * 2 * len(self.systems)
        if self.dataset_role == "paired_development_gate" and cells != 10:
            raise ValueError("Gate must contain exactly ten cells")
        if self.dataset_role == "paired_development_matrix" and cells != 20:
            raise ValueError("Matrix must contain exactly twenty cells")
        if self.dataset_role == "paired_development_matrix" and not self.requires_gate_pointer:
            raise ValueError("Matrix requires a gate pointer")
        return self
```

- [ ] **Step 5: Add config tests and run them**

Tests assert exact 10/20 cells, duplicate systems rejected, path escapes rejected, and label fields absent from detector config JSON.

Run:

```bash
uv run --no-sync pytest tests/test_python_pair_config.py -q
```

Expected: all config tests pass.

## Task 2: Add Full-Package Candidate And Fixture Binding

**Files:**

- Create: `src/cv_agent/python_pair_fixture.py`
- Test: `tests/test_python_pair_fixture.py`

- [ ] **Step 1: Build production package indexes**

Do not index only `prompt.py` or `filters.py`. Build an index from the configured production source root, excluding tests and caches. For LangChain this should retain thousands of `libs/core` documents and let graph retrieval see `PromptTemplate.from_template` neighbors such as template-variable parsing helpers.

Core helper shape:

```python
def build_package_index(root: Path, pair: PythonPair, case: PythonPairCase) -> tuple[RepositoryIndex, dict[str, str]]:
    checkout = root / case.checkout
    source_root = checkout / pair.source_root
    documents: list[CodeDocument] = []
    source_sha256: dict[str, str] = {}
    for path in sorted(source_root.rglob("*.py")):
        relative_parts = path.relative_to(checkout).parts
        if set(relative_parts) & set(pair.exclude_path_parts):
            continue
        relative = path.relative_to(checkout).as_posix()
        raw = read_source_bytes(checkout, relative)
        source_sha256[relative] = hashlib.sha256(raw).hexdigest()
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        spans = parse_python_source(case.case_id, relative, raw.decode(encoding))
        documents.extend(span.document for span in spans)
    return RepositoryIndex(documents), source_sha256
```

- [ ] **Step 2: Create neutral candidates from the full index**

Find the configured `entry_symbol` inside the full index, then create a `Candidate` with neutral `case_id`, source path, entry line, query, and `analysis_scope`. Do not include commit IDs, checkout paths, revision roles, labels, or local filesystem paths in the candidate.

- [ ] **Step 3: Bind fixture tools to candidate subject and source snapshot**

The fixture tool must block wrong candidate/path/line/source digest/scope and raise if the checkout changed. The model can only see sanitized fixture observations. It cannot see evaluator labels.

The validation status is derived from current-run probe invariants:

```python
def fixture_validation_status(pair_id: str, role: str, observations: dict) -> str:
    if pair_id == "langchain_template_traversal":
        benign = observations["benign"]["status"] == "BENIGN_OK"
        exploited = (
            observations["attribute_access"]["status"] == "EXPLOITED"
            and observations["dunder_access"]["status"] == "EXPLOITED"
        )
        blocked = (
            observations["attribute_access"]["status"] == "BLOCKED"
            and observations["dunder_access"]["status"] == "BLOCKED"
        )
    elif pair_id == "jinja_attr_format_escape":
        benign = observations["benign"]["status"] == "BENIGN_OK"
        exploited = observations["attr_format"]["status"] == "EXPLOITED"
        blocked = observations["attr_format"]["status"] == "BLOCKED"
    else:
        raise ValueError("Unknown pair id")
    if role == "vulnerable" and benign and exploited:
        return "CONFIRMED"
    if role == "fixed" and benign and blocked:
        return "REFUTED"
    raise ValueError("Current-run fixture invariants failed")
```

- [ ] **Step 4: Add fixture tests and run them**

Tests cover wrong fixture id, wrong subject, changed source, dirty checkout, labels absent from candidate JSON, full-package graph positive control, and E2 BM25 built from the same document set.

Run:

```bash
uv run --no-sync pytest tests/test_python_pair_fixture.py tests/test_langchain_agent_eval.py -q
```

Expected: all fixture tests pass.

## Task 3: Add The Jinja Pair

**Files:**

- Create: `scripts/prepare_jinja_pair.py`
- Create: `scripts/jinja_attr_probe.py`
- Create: `scripts/reproduce_jinja_attr_pair.py`
- Test: `tests/test_jinja_pair_reproduction.py`

- [ ] **Step 1: Prepare pinned Jinja checkouts**

`scripts/prepare_jinja_pair.py` clones or updates `https://github.com/pallets/jinja.git` into:

- `data/diagnostics/jinja-vulnerable` at `877f6e51be8e1765b06d911cfaa9033775f051d1`
- `data/diagnostics/jinja-fixed` at `15206881c006c79667fe5154fe80c01c65410679`
- `data/diagnostics/jinja-env`

The script takes no arguments, uses fixed paths, and stops on any failure.

- [ ] **Step 2: Add the isolated Jinja probe**

`scripts/jinja_attr_probe.py` accepts `--checkout` and `--scenario` because it is called by the reproducer, not by users. It supports only `benign` and `attr_format`; arbitrary exceptions become probe output with `status: BLOCKED` only when the fixed advisory rejection path is reached by the attr-format probe. Process failures and parse failures remain failures in the reproducer.

- [ ] **Step 3: Add current-run Jinja reproduction**

`scripts/reproduce_jinja_attr_pair.py` checks clean commits, runs vulnerable and fixed probes, writes `metadata.json`, `results.json`, and `raw_subprocesses.json`, and returns `verified_differential_security: true` only when benign control passes on both revisions, vulnerable attr-format is exploited, and fixed attr-format is blocked.

- [ ] **Step 4: Run Jinja checks**

Run:

```bash
uv run --no-sync python scripts/prepare_jinja_pair.py
uv run --no-sync pytest tests/test_jinja_pair_reproduction.py -q
uv run --no-sync python scripts/reproduce_jinja_attr_pair.py
```

Expected: reproduction summary reports `verified_differential_security: true`.

## Task 4: Add Pair-Specific Acceptance

**Files:**

- Create: `src/cv_agent/python_pair_acceptance.py`
- Test: `tests/test_python_pair_acceptance.py`

- [ ] **Step 1: Validate cell evidence and usage**

Implement `pair_acceptance_issues(rows, usage, config, labels, subjects)`. It must reject missing, duplicate, expanded, failed, abstained, interrupted, and incorrect cells. It must also reject votes without candidate-bound executed validator evidence, usage mismatches, invalid responses, missing usage, conflicts, orphaned responses, and duplicate request starts.

- [ ] **Step 2: Validate gate artifacts before matrix**

Implement `require_python_pair_gate(root, matrix_config)`. It must:

- read `artifacts/python_pair_gate.json`;
- reject absolute or escaping pointer paths;
- require the pointer to be under `artifacts/python_pair_gate/`;
- read durable `events.jsonl`, not a saved boolean;
- require the final event to be `run_end` with `interrupted: false`;
- compare source fingerprint, model config, systems, concurrency, and admitted pair descriptors;
- compare checkout commits and relevant source hashes saved by the gate;
- require the gate pair descriptors to be a subset of matrix pair descriptors;
- run `pair_acceptance_issues` and `transport_issues`.

- [ ] **Step 3: Add acceptance tests and run them**

Tests cover exact 10/20 cross-products, private labels absent from model-visible data, wrong subject/path/source/scope, failed new gate invalidating an old pass, stale source/model/concurrency/case descriptor/commit, escaping pointer, missing `run_end`, transport diagnostic failure, and zero model calls after failed gate.

Run:

```bash
uv run --no-sync pytest tests/test_python_pair_acceptance.py tests/test_experiment_acceptance.py -q
```

Expected: all acceptance tests pass.

## Task 5: Implement The 10-Cell Gate Runner

**Files:**

- Create: `scripts/run_python_pair_gate.py`
- Test: `tests/test_python_pair_runner.py`

- [ ] **Step 1: Add the no-argument gate runner**

The runner loads `configs/python_pair_gate.json`, creates `artifacts/python_pair_gate/<uuid>/`, and immediately writes `artifacts/python_pair_gate.json` pointing to this new directory before pytest, preflight, or model calls. That means a failed fresh attempt cannot leave an older passing gate active.

Execution order:

1. create run directory;
2. write latest pointer;
3. run `require_passing_tests()`;
4. reproduce the LangChain pair in `run_dir/pair_preflight/langchain`;
5. build full-package indexes and source hashes;
6. create candidate-bound fixture tools;
7. execute exactly 10 cells using `execute_trials` with concurrency 1;
8. write `results.json`, `usage.json`, `acceptance.json`, `metadata.json`, and `events.jsonl`;
9. append `run_end`.

- [ ] **Step 2: Use the existing runner primitives**

Reuse `LockedBudget`, `LockedJournal`, `execute_trials`, `run_candidate`, `snapshot_sources`, `source_fingerprint`, `provider_usage`, `candidate_subject`, `full_agent_tools`, and `transport_issues`. Do not reuse `run_python_repository_pilot.py`; it is source-discovery smoke infrastructure and lacks paired fixture evidence, `run_end`, and admission linkage.

- [ ] **Step 3: Add runner tests and run them**

Tests assert pointer invalidation before model calls, exactly 10 scheduled cells, failed/abstained row creates failed acceptance, labels absent from prompts/candidates, and no expansion marker is written.

Run:

```bash
uv run --no-sync pytest tests/test_python_pair_runner.py -q
```

Expected: all runner tests pass.

## Task 6: Implement The 20-Cell Matrix Runner

**Files:**

- Create: `scripts/run_python_pair_matrix.py`
- Test: `tests/test_python_pair_runner.py`

- [ ] **Step 1: Add the no-argument matrix runner**

The runner loads `configs/python_pair_matrix.json`, calls `require_python_pair_gate(project_root, config)` before any model call, reproduces both LangChain and Jinja pairs in the current run, then executes exactly 20 cells. It writes artifacts under `artifacts/python_pair_matrix/<uuid>/` and never writes a pointer that authorizes a larger run.

- [ ] **Step 2: Add matrix tests and run them**

Tests assert missing/stale/failed gate stops before model calls, failed Jinja preflight stops before model calls, valid mocked gate schedules exactly 20 cells, and failures remain in `results.json`.

Run:

```bash
uv run --no-sync pytest tests/test_python_pair_runner.py tests/test_python_pair_acceptance.py -q
```

Expected: all matrix tests pass.

## Task 7: Run Offline Verification

**Files:**

- No source edits in this task.

- [ ] **Step 1: Run focused tests**

```bash
uv run --no-sync pytest tests/test_python_pair_config.py tests/test_python_pair_fixture.py tests/test_python_pair_acceptance.py tests/test_python_pair_runner.py tests/test_jinja_pair_reproduction.py tests/test_langchain_agent_eval.py -q
```

Expected: all focused tests pass.

- [ ] **Step 2: Run full suite and harness check**

```bash
uv run --no-sync pytest
uv run --no-sync cv-agent harness-check
```

Expected: full pytest passes and harness-check reports PASS.

## Task 8: Run The Gate

**Files:**

- Outputs: `artifacts/python_pair_gate/<uuid>/`
- Pointer: `artifacts/python_pair_gate.json`

- [ ] **Step 1: Load the API key without printing it**

```bash
set -a
source /home/joker/.config/cliproxyapi/client.env
set +a
test -n "${ANTIGRAVITY_API_KEY}"
```

Expected: exit code 0, no secret printed.

- [ ] **Step 2: Execute the gate**

```bash
uv run --no-sync python scripts/run_python_pair_gate.py
```

Expected: 10/10 completed, `acceptance.json` has `"passed": true`, `usage.json` has positive requests/responses and zero invalid responses.

- [ ] **Step 3: Stop on any gate failure**

Preserve the artifact directory, inspect `events.jsonl`, `acceptance.json`, `usage.json`, and native diagnostics, then repair the demonstrated local issue. After any edit, rerun offline verification and rerun the full 10-cell gate. Do not replace the failed gate by running only the failed cell.

## Task 9: Run The Matrix

**Files:**

- Outputs: `artifacts/python_pair_matrix/<uuid>/`

- [ ] **Step 1: Execute the matrix only after a valid gate**

```bash
uv run --no-sync python scripts/run_python_pair_matrix.py
```

Expected: gate revalidated, both pair preflights pass, 20/20 cells complete, and the summary records labels, evidence binding, request counts, tokens, E4/E5 disagreements, and E4-prefix replay diagnostics.

- [ ] **Step 2: Preserve matrix failures**

If any cell fails, preserve the run directory and report the matrix as failed. Diagnostic reruns use separate artifact paths and do not overwrite formal matrix results.

## Task 10: Report Results

**Files:**

- Create: `docs/PYTHON_PAIR_EXPERIMENT_2026-09-20.md`

- [ ] **Step 1: Write the report**

Include code snapshot, model config path, gate artifact, matrix artifact, pass/fail decisions, per-system confusion table, request/response/token totals, invalid-response totals, E4/E5 label differences, and the limitation that these are development diagnostics. State that a formal held-out result needs a separate frozen sample, with 50 independent advisory pairs for exploratory estimation and around 100 pairs for a stronger study.

- [ ] **Step 2: Final verification**

```bash
uv run --no-sync pytest
uv run --no-sync cv-agent harness-check
```

Expected: full tests pass and harness-check reports PASS.

## Self-Review

- The gate is exactly 10 cells, and the matrix is exactly 20 cells.
- The model cannot see evaluator labels or revision roles.
- LangChain and Jinja use production package indexes, so retrieval and graph systems have real cross-file context.
- Fixture validation status is derived from current-run probe behavior, not from pair order.
- A failed fresh gate invalidates older passing gates by updating the pointer immediately.
- The matrix cannot begin model calls without a revalidated gate artifact.
- The report cannot use these development diagnostics as broad recall or false-positive evidence.
