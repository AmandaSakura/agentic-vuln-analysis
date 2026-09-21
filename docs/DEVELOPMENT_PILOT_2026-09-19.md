# Development pilot, 2026-09-19

## Prepared evaluation

- Frozen OWASP selection: 66 cases from 2,740, balanced across 11 categories and both labels.
- E1–E5 matrix: 330 scheduled trials; full expansion was not executed.
- Pilot identities: safe `BenchmarkTest00827`, vulnerable `BenchmarkTest02244`.
- No reference labels were passed to the model. All failures and unrun cells remain visible.

## Preserved live runs

| Run directory under artifacts/development_benchmark | Scope | Requests | Reported tokens | Outcome |
|---|---|---:|---:|---|
| 47a093d98ee748df8aa566773f9b7344 | Initial case-first pilot | 30 | 138458 | Negative E1/E2 exhausted steps; E3 identity drift; E4 request cap; remaining cells not run |
| f24a142cd30149949772d40a22a188e7 | System-first pilot after identity correction | 30 | 143693 | Negative E1/E2 exhausted steps; positive E1 serialization error; positive E2 request cap; remaining cells not run |
| 21a5871ad4a54128b58dc39bcc5d41d0 | Positive E1 serialization check | 8 | 16377 | Step budget exhausted on a fenced final JSON answer |

Total: **68 live model requests**, **298,528 provider-reported tokens**. Monetary
cost is unknown; no pricing or free-service claim is made. The later runs report
returned model ID `gemini-3.8-flash`, while the requested alias is
`gemini-3.8-flash-high`. Runs are different revisions/scopes, not interchangeable
replicates. No live trial completed successfully in these three records, so they
do not support accuracy or component-improvement claims.

## Defects exposed and repaired

1. The original pilot spent its budget on all variants of the negative before
   reaching the positive. Subsequent scheduling interleaves both labels per system.
2. Expert-identity validation occurred after the ReAct correction loop. It now
   runs inside the existing step budget, and the assigned identity is explicit.
3. Both experiment runners incorrectly accessed `.value` on a string verdict
   label. They now serialize the actual type. Regression tests use a real
   `AgenticVerdict`, replacing the misleading enum-shaped sentinel.
4. Complete JSON code fences caused otherwise parseable final objects to be
   rejected. The parser now accepts bare JSON or one complete JSON code block;
   prose, incomplete fences, schema errors and unsupported evidence still fail.

The last parser fix was verified **without more API requests** by replaying the
eight recorded responses. Every generated request message and tool schema matched
the original live request exactly. The replay completed with **ABSTAIN**, and is
stored separately as `offline_replay_after_parser_fix.json` in the third run.
Its provenance remains **scripted**, not live. Original failure records were not
replaced, and this abstention is not a successful vulnerability detection.

## Expansion decision

Do not spend the full 330-trial budget yet. The negative traces repeatedly request
REFUTED without matching validator evidence; the positive E1 context contains a
delegating `doGet`, while the implementation lies outside local scope, so the
observed final answer is appropriately unresolved. These are concrete findings
about the current model/tool/context contract, not proof that a model or language
is generally unsuitable. Keep the source/evidence constraints; investigate
successful material decisions and stable abstention termination before expanding.

The prepared development matrix does not replace the independent real-project,
verified-fixed-negative evaluation specified in `FULL_SYSTEM_SPEC.md`.
