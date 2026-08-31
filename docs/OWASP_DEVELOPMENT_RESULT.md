# OWASP development result

This is a development-only result, not a final or generalizable claim.

## Run identity

- Harness: `owasp-development-v2`
- Code: `c6b96334855b7648fabe2ba4c2e922973d96f372` (clean)
- BenchmarkJava: `2734ae486356765ea4e45393a28e20bcb5047f8c` (clean)
- Cases: 2,740 overall; 1,117 in the predeclared primary categories
- Artifact: `artifacts/owasp-development-v2-c6b9633.json`
- Verification before the run: 49 tests passed

## Primary-subset metrics

| System | Coverage | Strict recall | Population FPR | Precision | Abstain rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| V1 local scan | 0.00% | 0.00% | 0.00% | n/a | 100.00% |
| V2 global text scan | 100.00% | 100.00% | 100.00% | 51.30% | 0.00% |
| V3 forward-graph scan | 55.60% | 55.32% | 55.88% | 51.05% | 44.40% |
| V4 graph full review | 46.20% | 50.96% | 41.18% | 56.59% | 53.80% |
| V5 graph early quorum | 46.20% | 50.96% | 41.18% | 56.59% | 53.80% |

V4 versus V3 reduced population FPR by 14.71 percentage points, or 26.32% relative, while strict recall fell by 4.36 percentage points and coverage fell by 9.40 percentage points. Covered recall and covered FPR are both 100% because the current adjudicator emits `VULNERABLE` or `ABSTAIN` on this benchmark, but never establishes `SAFE`. The FPR change is therefore selective alert filtering through abstention, not correct safe classification.

V5 exactly matched every V4 label and skipped 882 authorization-expert calls. That is 32.19% of possible third-expert calls and 10.73% of V4's 8,220 total expert calls. It supports a scheduling/call-count result only; it is not a latency, token, or monetary-cost result.

## Retrieval-origin diagnosis

The global lexical baseline is degenerate on this templated repository:

| System | Candidate file | Other benchmark case | Shared helper/framework | Total matched sink evidence |
| --- | ---: | ---: | ---: | ---: |
| V1 | 0 | 0 | 0 | 0 |
| V2 | 1 | 2,739 | 0 | 2,740 |
| V3 | 1,103 | 0 | 42 | 1,145 |
| V4 | 1,103 | 0 | 42 | 1,145 |
| V5 | 1,103 | 0 | 42 | 1,145 |

V2 predicted every case as vulnerable because nearly every matched sink came from another independent Benchmark test. Its apparent 100% recall is not useful detector recall. The V3-minus-V2 strict-recall value of -44.68 percentage points must not be used as evidence against or in favor of graph retrieval. On this dataset it measures candidate-directed graph retrieval against a polluted global lexical baseline.

The retrieval hypothesis therefore moves to the separately declared VulnGym oracle-seeded diagnostic, which uses real project entry points and critical operations. OWASP remains useful for the selective multi-expert and fast-path mechanics described above.
