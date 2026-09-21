# VulnGym oracle retrieval result

This is an oracle-seeded retrieval diagnostic over selected verified positive entries. It is not end-to-end vulnerability recall, a held-out estimate, or a generalization claim.

## Run identity

- Harness: `vulngym-oracle-retrieval-v2`
- Code: `7cbaf96c6d6c7360f4c1a52de806b4a6a1d390ce` (clean)
- VulnGym: `cd69f7e163e08485ab5496115ae03439cda6e27e` (clean)
- google/adk-python: `d1121317ef4e1ac559f4ae13855ac1af28eef8f6` (clean)
- PrefectHQ/fastmcp: `c861862aededc7294cea5634d77e6926444ca101` (clean)
- jlowin/fastmcp: `6bade1cbd973cbbbca26a84ed7c4cc58ecfda5b3` (clean)
- Entries: 11 total, comprising 6 cross-file and 5 same-file entries
- Resolution: 11/11 entry points and 11/11 critical operations
- Artifact: `artifacts/vulngym-oracle-retrieval-v2-7cbaf96.json`
- Verification before the run: 57 tests passed

All three repository profiles reported zero Python parse errors. Three `SyntaxWarning` messages from subject test files did not prevent `ast.parse` from returning trees and did not change the parse-error counts.

## Retrieval coverage

| Mode | Overall | Cross-file | Same-file | Average context tokens | Maximum context tokens |
| --- | ---: | ---: | ---: | ---: | ---: |
| Local | 2/11 (18.18%) | 0/6 (0.00%) | 2/5 (40.00%) | 389.91 | 512 |
| Text | 3/11 (27.27%) | 1/6 (16.67%) | 2/5 (40.00%) | 3,760.36 | 4,000 |
| Graph | 4/11 (36.36%) | 2/6 (33.33%) | 2/5 (40.00%) | 1,824.64 | 3,034 |
| Hybrid | 2/11 (18.18%) | 0/6 (0.00%) | 2/5 (40.00%) | 2,999.55 | 4,000 |

Graph exceeded text by 9.09 percentage points overall and 16.67 percentage points on cross-file entries. Pairwise, text and graph both hit two entries, graph alone hit `entry-00430` and `entry-00433`, text alone hit `entry-00394`, and neither hit six entries. The net overall difference is one entry, so percentages must always be accompanied by the 4/11 and 3/11 counts.

The same-file result is identical for every mode. The observed graph advantage is confined to the cross-file stratum. It is descriptive evidence that candidate-directed call edges can recover some critical context missed by lexical retrieval under this fixed budget; the sample is too small and selected to estimate population performance.

## Miss interpretation

- `entry-00431` has a valid four-hop call route, but other nearer and lexically stronger dynamic-dispatch targets occupy the shared top-eight ranked prefix. This is a ranking-budget miss, not a missing edge.
- `entry-00432` requires five hops through nested `forward_events`, so it is outside the predeclared four-hop budget.
- `entry-00394` is the cross-file text-only hit; its critical operation is connected through object state rather than a direct forward call path.
- Remaining misses depend on object lifecycle, persistence, callbacks, or state relationships outside this function-call graph.
- Hybrid adds one lexical seed and its forward neighborhood, then ranks the combined candidate and lexical neighborhoods under the same top-eight and token budgets. That competition displaced candidate-path evidence and produced no cross-file hits.

Changing graph hops, `top_k`, or ranking after observing this artifact would be post-hoc tuning. Any such variant must be declared as a separate exploratory experiment and cannot replace this result.
