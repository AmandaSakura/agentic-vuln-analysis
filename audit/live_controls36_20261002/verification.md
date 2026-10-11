# 36-control live static evidence review — 2026-10-02

The user-authorized batch completed all 36 existing owned synthetic controls. The original admission gate ran the full suite in the actual experiment process: **2948 passed in 433.63 seconds**. Credentials were loaded afterward. Transport used `OpenAICompatibleChatModel`, with no tools, target-source execution, retries or fallback.

The frozen protocol allowed 36 requests and 120,000 reported tokens. Actual use was **36 requests / 36 responses / 42,267 reported tokens** (35.2% of the token cap; 1,174.1 tokens per request). All returned model IDs were `deepseek-flash`. Provider monetary cost was not reported and is not treated as zero. Every raw reply and reported usage was retained before parsing; the journal audit found no missing usage, conflicts, duplicates or orphan responses.

All 36 source packages were verified before admission. Selection came from the unique source AST chmod call, with source hash and exact operation line checks. Case IDs remained local; prompts used neutral `entry.py` source paths. Reference labels were read only by the post-run scorer, which checked the frozen reference hash and exact source/line membership. The full static observation records were retained while the model projection used the single producer-observation reference namespace.

## Two separate comparisons

Model-versus-canonical observation consistency was **36/36**. Protocol rejections, candidate/reference failures and unsupported strong proposals were all zero. This measures compliant consumption of supplied bounded observations, not independent detection improvement.

Both static output and model proposals had the following comparison with the frozen development reference:

| Reference state | SUPPORTED output | REFUTED output | UNKNOWN output | Total |
| --- | ---: | ---: | ---: | ---: |
| SUPPORTED | 5 | 0 | 7 | 12 |
| REFUTED | 0 | 5 | 7 | 12 |
| UNKNOWN | 0 | 0 | 12 | 12 |
| Total | 5 | 5 | 26 | 36 |

Exact matches were **22/36 (61.1%)**. The 14 remaining named-mode cases were unchanged UNKNOWN results, accounting for 38.9% of all controls. Strong output coverage was 10/36 (27.8%); abstention was 26/36 (72.2%). These are descriptive counts for this development corpus, not population false-positive or recall estimates. Model proposals never replaced the canonical evidence state.

## Reproducibility and limits

- [Fixed protocol](protocol.json), [runner](run.py), [post-run scorer](analyze.py) and [reference byte freeze](reference-freeze.json).
- [Reconciliation receipt](result.json) binds the prompt, source manifest, raw events, summary and gate receipt by SHA256. The run directory is `artifacts/live_controls36_20261002/d41fc419b14946deae44646d2840aa6f`; gate log is `artifacts/pytest_gate/bbeed1c4de2a43c9b529276449de2526/pytest.log`.
- The historical failed v1 reply and the three-input v2 pilot remain separate and unchanged. This new batch is not pooled into their protocol success rate or the original M0 ledger.
- Controls are agent-designed development inputs, not human-independent or held-out data. No human benefit, whole-project safety, third-party exploitability or complete E1–E5 loop was measured. Target-source executions were zero; production R17 and G-A remain unchanged.
