# Luna clean-context workflow simulation

Later implementation update: `QUORUM_APPLICABLE_VERIFICATION.md` records a new scan-side
concrete Python probe and its scripted integration check. The Luna observations below remain
historical and are not relabeled as results from that new capability.
Fresh Luna max verification of the new capability is recorded separately in
`LUNA_POSTFIX_VERIFICATION.md`.

This note records a development-only simulation of the agentic workflow using clean-context
Codex Luna max subagents as the model component. It is not a DeepSeek live-model run, not a
held-out benchmark, and not evidence for recall or false-positive claims.

## Scope

- Sessions: `artifacts/luna-clean-C01-v4` and `artifacts/luna-clean-C02-v3`.
- Model component: clean-context Luna max subagents with `fork_turns="none"`.
- Execution: each subagent read only its session `pending.json` and returned one JSON model
  response. The coordinator executed declared tools through the real `ToolRegistry`.
- Replay mode: recorded replies were replayed through `AgenticPipeline` with
  `runtime_mode="scripted"` and `claim_eligible=false`.
- Cases: two artificial Python development cases built by `scripts/luna_flow_simulation.py`.

The subagents did not receive resume text, metric claims, prior experiment summaries, or labels.
They did share the local filesystem and tool permissions available to Codex, so this is a clean
conversation-context simulation rather than a process sandbox isolation proof.

## Cases

`C01` is a positive source-to-sink case:

```python
def endpoint(request):
    payload = request.args['expression']
    return calculate(payload)

def calculate(expression: str):
    return eval(expression)
```

`C02` is an argument-mapping negative-style case:

```python
def endpoint(request):
    payload = request.args['expression']
    return calculate("1 + 1", payload)

def calculate(expression: str, audit_tag: str):
    return eval(expression)
```

The request-controlled value is passed to `audit_tag`, while `eval` receives the constant
`expression` argument.

## Bugs and fixes found by the simulation

1. Planner capability prompts originally did not expose the legal validator names with enough
   precision. Earlier sessions therefore requested invalid or unavailable validators. The planner
   prompt now includes `allowed_validators_by_expert`, validator descriptions, and the maximum
   subtask count. Plan validation runs inside the ReAct correction loop.
2. Tool registration and tool availability were conflated. Fixture and HTTP validators were
   advertised even when their backing cases were not configured. Tool metadata now separates
   registered tools from currently available validators.
3. Agent conclusions could carry `validation_status`, but the consensus-level `ExpertVote` dropped
   that field. Full review therefore could not distinguish an uncontested validator-confirmed vote
   from an ordinary unresolved model judgment. Consensus votes now preserve `validation_status`.
4. An initial change also let a single high-confidence `CONFIRMED` vote bypass quorum. The
   subsequent review removed this exception: static validator confirmation is not a dynamic
   exploit proof, and dropping below quorum is a policy change rather than a field-propagation
   fix. With `quorum=3`, the exception could even accept one confirmed vote despite a conflicting
   material vote. Validator status propagation is retained.
5. Availability was initially enforced by planner prompts and expert allowlists only. The review
   added the missing execution check: `ToolRegistry.invoke` blocks an unavailable tool before
   calling its handler, including when a caller retains it in an allowlist.

## Observed behavior

| Case | System | Final label | Path | Model calls | Tool calls | Expert votes |
| --- | --- | --- | --- | ---: | ---: | --- |
| C01 | E4 | ABSTAIN | slow | 10 | 7 | scan ABSTAIN/UNRESOLVED; taint VULNERABLE/CONFIRMED; authz ABSTAIN/UNRESOLVED |
| C01 | E5 | ABSTAIN | slow | 10 | 7 | scan ABSTAIN/UNRESOLVED; taint VULNERABLE/CONFIRMED; authz ABSTAIN/UNRESOLVED |
| C02 | E4 | ABSTAIN | slow | 10 | 7 | scan ABSTAIN/UNRESOLVED; taint ABSTAIN/UNRESOLVED; authz ABSTAIN/UNRESOLVED |
| C02 | E5 | ABSTAIN | slow | 10 | 7 | scan ABSTAIN/UNRESOLVED; taint ABSTAIN/UNRESOLVED; authz ABSTAIN/UNRESOLVED |

This table reflects the review replay in `artifacts/luna-review-20260905-C01` and
`artifacts/luna-review-20260905-C02`. Those sessions reuse the original Luna replies; no fresh
model inference was performed. The earlier sessions and their pre-review outputs are preserved.

The evidence validator rejected over-strong intermediate conclusions:

- Scan attempted to mark `eval` sink presence as `CONFIRMED`; the correction loop forced
  `UNRESOLVED` because static sink presence alone does not prove exploitability.
- Taint on `C01` initially omitted the validator citation for a `CONFIRMED` conclusion; the
  correction loop required the `taint/tool:1` citation.
- Taint on `C02` inferred a likely false positive from the source code, but the validator returned
  `UNRESOLVED`, not `REFUTED`; the correction loop forced `ABSTAIN/UNRESOLVED`.

## Interpretation

The simulation supports the workflow implementation claim: Planner, ReAct tool calls, typed tool
validation, correction loops, task scheduling, and final consensus all executed end to end with
real subagent-generated JSON replies.

It does not support performance claims. The cases are artificial development fixtures, the model
replies are replayed in scripted mode, and there is no held-out live-model denominator.

Two limitations remain visible. In `C01`, only taint supplies a material vote: the scan specialist
abstains after its unsupported confirmation is rejected, and authz is outside scope. The positive
case thus lacks quorum and finishes `ABSTAIN`; this is an unresolved coverage limitation of the
expert workflow, not a reason to silently lower the adjudication threshold. In `C02`, the current
dataflow validator avoids confirming a false source-to-sink trace but does not emit a strong
`REFUTED` argument-binding proof. The safe-looking case also remains `ABSTAIN` rather than `SAFE`.

## Review verification (2026-09-05)

- Before the review fixes, five regression cases failed: single confirmed vote bypass, a
  conflicting vote below configured quorum, unavailable handler execution, and the single-vote
  scenario through each of the E4/E5 workflows.
- After the fixes, `uv run --no-sync pytest` reports **233 passed**. The unavailable fixed-pair
  test now expects a blocked invocation instead of executing the unconfigured validator.
- `uv run --no-sync cv-agent harness-check` reports **PASS**.
- All four review replays complete with matching recorded model inputs, 10 model calls and
  7 tool calls per run. E4 and E5 agree on `ABSTAIN` for both cases.
- These checks cover the reviewed regressions and workflow replay; they do not establish
  vulnerability-detection quality or the absence of other implementation defects.
