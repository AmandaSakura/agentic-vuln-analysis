# OWASP development result

This is a development-only proxy result. It is not a held-out or generalizable claim, and it does not by itself establish the full live ReAct system.

## Run identity

- Harness: `owasp-development-v3`
- Code: `d2fe562a2686145cd93e730ad4a8a57cdddaa1ff` (clean)
- BenchmarkJava: `2734ae486356765ea4e45393a28e20bcb5047f8c` (clean)
- Cases: 2,740 overall; 1,117 in the predeclared primary categories
- Primary categories: command injection, LDAP injection, path traversal, SQL injection, and XPath injection
- Artifact: `artifacts/owasp-development-v3-d2fe562-typed-code-rag.json`
- Verification before the run: 173 tests passed

## Primary-subset metrics

| System | Coverage | Strict recall | Population alert rate | Conservative FPR | Covered FPR | Precision | Abstain rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| V1 local scan | 0.00% | 0.00% | 0.00% | 100.00% | n/a | n/a | 100.00% |
| V2 global text scan | 0.00% | 0.00% | 0.00% | 100.00% | n/a | n/a | 100.00% |
| V3 typed forward-graph scan | 55.60% | 55.32% | 55.88% | 100.00% | 100.00% | 51.05% | 44.40% |
| V4 graph full review | 54.61% | 55.32% | 33.09% | 79.23% | 61.43% | 63.78% | 45.39% |
| V5 graph early quorum | 54.61% | 55.32% | 33.09% | 79.23% | 61.43% | 63.78% | 45.39% |

The three negative-sample metrics have different meanings and must not be substituted for one another:

- Population alert rate is `FP / all negatives`; abstentions do not count as alerts.
- Conservative FPR maps every abstention to `VULNERABLE`, so only an explicit `SAFE` clears a negative.
- Covered FPR is `FP / (FP + TN)` among resolved predictions.

V4 versus V3 produced 113 real `VULNERABLE -> SAFE` transitions, 11 `VULNERABLE -> ABSTAIN` transitions, and left 180 negative cases vulnerable. Positive transitions were unchanged: 317 remained vulnerable and 256 remained abstained. Consequently:

- covered FPR fell from 100.00% to 61.43%, a 38.57% relative reduction;
- conservative FPR fell from 100.00% to 79.23%, a 20.77% relative reduction;
- population alert rate fell from 55.88% to 33.09%, a 40.79% relative reduction;
- strict recall changed by 0.00 percentage points;
- coverage changed by -0.98 percentage points.

Unlike the earlier v2 result, the covered-FPR improvement is backed by true negatives rather than only by abstention.

## Retrieval and adjudication changes

The v3 proxy uses typed Java call symbols, overload selection, qualified nested types, interface-dispatch expansion, and four forward graph hops. `top_k` is 10, while the total context limit remains 2,000 tokens. Ranked augmentation gives the entry callee more of the existing shared budget so source, branch, and complete multiline sink statements survive together.

For the injection-focused primary subset, the routed third specialist is an independent backward-flow refuter. `SAFE` requires both forward taint and backward flow evidence, producing a two-of-three majority against the scan candidate. Authorization remains available in the deterministic router for authorization-shaped candidates, but it was not applicable to this OWASP injection run.

V5 exactly matched all V4 labels. It formed 468 early vulnerable quorums and skipped 468 third-specialist calls, or 17.08% of possible third calls. This is a scheduling/call-count result only, not a latency, token, or cost measurement. The largest model-visible context was 1,393 tokens, below the 2,000-token contract.

## Limitations

- `claim_eligible` is false because OWASP BenchmarkJava was used during development.
- V1 and V2 abstain on every case in this candidate protocol, so the 55.32-point V3-over-V2 retrieval gain is dataset- and baseline-specific. It is not a final Code-RAG recall claim.
- The predeclared primary subset matches the supported injection sink families. Across all OWASP categories, V4 has 15 false negatives in unsupported crypto and hash categories; those categories must not be hidden or used as evidence for this specialist configuration.
- No authorization-focused public evaluation has yet established the Authz expert's contribution. This artifact therefore supports the injection flow-adjudication proxy, not the exact resume-level three-expert authorization claim.
- The deterministic experts are development proxies. A final reproduction still requires a held-out live-model ReAct evaluation with validation tools and an authorization dataset.
