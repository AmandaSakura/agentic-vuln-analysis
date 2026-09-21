# Python Paired Gate And Matrix Result

Date: 2026-09-20

This run implements and executes the controlled Python paired-evidence path described in `docs/superpowers/plans/2026-09-20-python-paired-admission.md`.

## What Changed

- Added strict pair configs:
  - `configs/python_pair_gate.json`
  - `configs/python_pair_matrix.json`
  - `validation/python_pair_labels_v1.json`
- Added typed pair config, fixture binding, and acceptance modules:
  - `src/cv_agent/python_pair_config.py`
  - `src/cv_agent/python_pair_fixture.py`
  - `src/cv_agent/python_pair_acceptance.py`
- Added Jinja CVE-2025-27516 reproduction:
  - `scripts/prepare_jinja_pair.py`
  - `scripts/jinja_attr_probe.py`
  - `scripts/reproduce_jinja_attr_pair.py`
- Added fixed no-argument live runners:
  - `scripts/run_python_pair_gate.py`
  - `scripts/run_python_pair_matrix.py`
- Updated the legacy LangChain pair runner so real checkouts use a production package index instead of only the entry file.
- Updated planner validation so later non-fixture subtasks must depend on `run_fixture_test` when a fixture subtask is present. This prevents unresolved static checks from contradicting candidate-bound concrete validator evidence they could not see.

## Offline Verification

Focused tests:

```bash
uv run --no-sync pytest tests/test_langchain_agent_eval.py tests/test_python_pair_runner.py tests/test_python_pair_config.py tests/test_python_pair_fixture.py tests/test_python_pair_acceptance.py tests/test_jinja_pair_reproduction.py -q
```

Result: 19 passed.

Full suite before live reruns:

```bash
uv run --no-sync pytest
uv run --no-sync cv-agent harness-check
```

Result: 467 passed; harness-check PASS.

Each live runner also ran the mandatory in-process full pytest gate before its first model request.

## Pair Preflights

LangChain CVE-2025-65106 / GHSA-6qv9-48xg-fc7f:

- Vulnerable commit: `b7d1831f9d3560ed4fb45134861eef3f4544eff3`
- Fixed commit: `c4b6ba254e1a49ed91f2e268e6484011c540542a`
- Vulnerable behavior: benign preserved, attribute traversal exploited, dunder traversal exploited.
- Fixed behavior: benign preserved, both traversal probes blocked with the expected invalid variable-name rejection.

Jinja CVE-2025-27516 / GHSA-cpwx-vrp4-4pq7:

- Vulnerable commit: `877f6e51be8e1765b06d911cfaa9033775f051d1`
- Fixed commit: `15206881c006c79667fe5154fe80c01c65410679`
- Vulnerable behavior: benign preserved, `attr('format')` exposes string format traversal.
- Fixed behavior: benign preserved, `attr('format')` returns sandbox undefined output and is classified as the expected block.
- Reproduction artifact: `artifacts/jinja_pair_reproduction/f8b251801d4f4ef4a538e84c4a4aafe5/`

## Gate Result

Artifact: `artifacts/python_pair_gate/0e0a41f87cb2447ca65f6ff0a33e622a/`

Acceptance:

```json
{"passed": true, "issues": [], "automatic_expansion": false}
```

Usage:

| Requests | Responses | Invalid | Missing usage | Tokens |
| ---: | ---: | ---: | ---: | ---: |
| 50 | 50 | 0 | 0 | 128128 |

Per-system result:

| System | TP | FP | TN | FN | Abstain | Failed | Not run | Requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| E1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 5 |
| E2 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 4 |
| E3 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 5 |
| E4 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 24 |
| E5 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 12 |

The gate pointer now points to this accepted run:

```json
{"run_directory": "artifacts/python_pair_gate/0e0a41f87cb2447ca65f6ff0a33e622a"}
```

## Matrix Result

Artifact: `artifacts/python_pair_matrix/00691755ac62487ab16cd0ddda4abc7d/`

Acceptance:

```json
{"passed": true, "issues": []}
```

Usage:

| Requests | Responses | Invalid | Missing usage | Tokens |
| ---: | ---: | ---: | ---: | ---: |
| 106 | 106 | 0 | 0 | 256874 |

Per-system result:

| System | TP | FP | TN | FN | Abstain | Failed | Not run | Strict recall | Population FPR | Requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| E1 | 2 | 0 | 2 | 0 | 0 | 0 | 0 | 1.0 | 0.0 | 10 |
| E2 | 2 | 0 | 2 | 0 | 0 | 0 | 0 | 1.0 | 0.0 | 9 |
| E3 | 2 | 0 | 2 | 0 | 0 | 0 | 0 | 1.0 | 0.0 | 10 |
| E4 | 2 | 0 | 2 | 0 | 0 | 0 | 0 | 1.0 | 0.0 | 45 |
| E5 | 2 | 0 | 2 | 0 | 0 | 0 | 0 | 1.0 | 0.0 | 32 |

Cell-level outcomes:

| Case | E1 | E2 | E3 | E4 | E5 |
| --- | --- | --- | --- | --- | --- |
| `langchain_template_vulnerable` | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| `langchain_template_fixed` | SAFE | SAFE | SAFE | SAFE | SAFE |
| `jinja_attr_vulnerable` | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE | VULNERABLE |
| `jinja_attr_fixed` | SAFE | SAFE | SAFE | SAFE | SAFE |

Paired comparisons:

| Comparison | Ties | Left wins | Right wins | Unavailable | Label disagreements |
| --- | ---: | ---: | ---: | ---: | ---: |
| E2 vs E3 | 4 | 0 | 0 | 0 | 0 |
| E3 vs E4 | 4 | 0 | 0 | 0 | 0 |
| E4 vs E5 | 4 | 0 | 0 | 0 | 0 |

E5 matched E4 labels for all four matrix cases. E5 used 32 requests while E4 used 45 requests in this matrix. The offline E4-prefix replay was label-equivalent for all four cases, with replay-estimated savings of 3-4 model calls and 3 tool calls per E4 case. The observed E5 request count is an independent live run, not a direct replay of E4.

## Failed Attempts Preserved

Two failed gate attempts are intentionally preserved:

- `artifacts/python_pair_gate/220470be5c744a7faf93a9e61b8fed92/`: local summary bug after the first completed cell; fixed by filling missing cells as `not_run` in progress summaries.
- `artifacts/python_pair_gate/b5a1a0acfcfa424280fcd5ff41dee37e/`: E5 abstained on the vulnerable LangChain case because later planned checks did not depend on the fixture observation; fixed by enforcing fixture-subtask dependencies in planner validation.

These failed attempts were not overwritten and did not authorize the matrix.

## Interpretation Limit

This is a paired development diagnostic with two advisory pairs. It proves the current workflow, evidence binding, gate, matrix runner, request accounting, and two concrete pair reproductions work on these declared cases. It does not establish broad automatic-discovery recall, real-project false-positive rate, or the original 28 percent / 37 percent claims.

For a formal held-out result, use a separately frozen sample. A practical next stage is 50 independent advisory pairs for exploratory estimation, and around 100 pairs for a stronger study with repository-clustered uncertainty and exact McNemar comparisons.
