# Applicable verification and quorum

The initial C01 workflow had one material vote: scan found a sink and abstained, taint supported
injection, and authz was not applicable. Requiring two votes was behaving as configured. The
missing capability was a second applicable check; accepting one vote would change the experiment.

## Implementation

- Scan retains candidate discovery and gains `probe_python_eval`, automatically registered for
  indexes containing Python AST functions. It probes two concrete request-input values in a
  restricted interpreter over admitted function slices. It does not reuse `python_flow` or
  another expert's vote, and never executes repository code or host callables.
- Taint retains `trace_dataflow`, using abstract propagation and argument binding.
- Planner capabilities include each expert's mandate and guidance to choose distinct applicable
  checks. For Python eval injection, scan can probe the entry while taint analyzes the same entry;
  neither task needs the other's conclusion. Registered fixtures remain available where supplied.
- Authz continues to abstain outside permission semantics. No specialist is forced to agree.
- Quorum remains two material votes. No single-validator override was reintroduced.

The probe supports plain synchronous Python functions, positional and keyword arguments, literal
defaults, local assignments, returns, simple branches and limited scalar expressions. It enforces
admitted paths, a call-depth limit, a 256-step limit and bounded function/string sizes. It does not
support decorators, arbitrary globals, dynamic call targets, loops, variadic arguments, general
Python execution or full application initialization. Unknown behavior means `UNRESOLVED`.

Two different request values must reach the same eval argument. A hardcoded expression matching
only one probe is insufficient. The finding is an input-control witness under modeled request
and builtin-eval semantics, not a full application exploit. An unsuccessful probe never proves
`SAFE`. Both checkers share the AST index/call graph, so their errors can still be correlated.

## Verification

`uv run --no-sync pytest`: **259 passed**.
Project Harness validation: **PASS**.

Regression cases cover actual argument positions and keywords, constants, early returns, branch
selection, unknown transforms, shadowed eval, recursion, missing admitted callees and unsupported
syntax. A subset compares probe observations with CPython running fixed project-owned test
functions whose eval is replaced by an argument recorder.

The workflow check derives scripted expert replies from actual tool observations. It does not
hand-select a final vote by case ID. Planner tasks are scripted, so this verifies capability,
evidence propagation, scheduling and adjudication rather than live-model planning quality.

| Case | E4 full | E5 | E4 model/tool calls | E5 model/tool calls |
| --- | --- | --- | --- | --- |
| C01: input is eval expression | VULNERABLE / slow | VULNERABLE / fast | 8 / 4 | 6 / 3 |
| C02: input is unused audit argument | ABSTAIN / slow | ABSTAIN / slow | 8 / 4 | 8 / 4 |

In C01, scan cites its concrete probe and taint cites its dataflow observation. E5 skips authz
only after these two final votes agree. In C02, neither applicable checker establishes a witness;
the system retains uncertainty rather than declaring the case safe.

Run with `uv run --no-sync python -m cv_agent.quorum_probe_smoke`.
Recorded output: `artifacts/quorum-probe-20260905.json`.
All results have scripted provenance and `claim_eligible=false`.

## Remaining empirical work

The original Luna sessions are preserved. A fresh clean-context Luna max run of C01 and C02
has now completed; `LUNA_POSTFIX_VERIFICATION.md` records the genuine model choices, evidence
correction and matching E4/E5 results. That two-case development check does not establish
reliability across unsupported cases or repositories. This repair addresses the supported
Python eval path; other vulnerability families still depend on their available validators
and registered fixtures. Held-out live-provider evaluation remains outstanding.
