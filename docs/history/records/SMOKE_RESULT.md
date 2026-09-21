# First implementation smoke result

> Historical wiring result only. The original graph retriever mixed a lexical seed into graph expansion, the original fast path ran all experts before adjudication, and binary metrics collapsed `ABSTAIN` into non-vulnerable. These figures are superseded and must not be used as benchmark evidence.

Environment: WSL2 Ubuntu 22.04, uv 0.9.28, CPython 3.13.5.

- Dependency sync: success (41 packages resolved, 40 installed)
- Tests: 6 passed in 0.62 seconds
- Dataset: two controlled cases used only to validate wiring and attribution

| System | Retrieval | Experts | Recall | FPR | Verdict path |
|---|---|---:|---:|---:|---|
| V1 | local | 1 | 0.0 | 1.0 | single |
| V2 | lexical | 1 | 0.0 | 1.0 | single |
| V3 | call graph | 1 | 1.0 | 1.0 | single |
| V4 | call graph | 3 | 1.0 | 0.0 | slow |
| V5 | call graph | 3 | 1.0 | 0.0 | fast |

Interpretation: the graph edge recovers the cross-file sink that local/text context misses; quorum rejects a guarded-delete false positive. This is a smoke test, not a public-benchmark estimate and not evidence for any claimed percentage.
