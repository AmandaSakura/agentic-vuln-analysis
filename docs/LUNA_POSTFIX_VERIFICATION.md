# Luna max verification after the applicable-check repair

## Method

Date: 2026-09-05. Cases: the existing C01 and C02 artificial development fixtures in
`scripts/luna_flow_simulation.py`. Sessions:

- `artifacts/luna-postfix-20260905-C01`
- `artifacts/luna-postfix-20260905-C02`

Eight fresh `gpt-5.6-luna` agents with reasoning effort `max` and `fork_turns="none"`
served the planner, scan, taint and authz roles separately for each case. Each role read
only its current workflow request, selected its own next response, and received actual
typed tool observations or validation feedback from the coordinator. No expert received
another role's conversation history outside what the workflow itself supplies. No expected
label, old reply, resume claim or previous experiment result was supplied to the agents.

The workflow's normal prompts include capability descriptions and guidance recommending
distinct applicable checks, including the new probe for Python eval candidates. The result
therefore demonstrates following that guidance, not discovering the architecture unaided.
The agents share filesystem permissions; clean conversation context is not OS isolation.

The coordinator records the actual Luna replies and replays them through `AgenticPipeline`
and `ToolRegistry`. Thus artifact `runtime_mode` remains `scripted`, while the reply origin
is genuine fresh Luna inference, not the deterministic responder used in the preceding
smoke check. All artifacts retain `claim_eligible=false`.

E4 ran through all three specialists. E5 reused the same recorded replies, checking that
every consumed model request matched the recorded request. This isolates fast scheduling
from model-sampling variation; it is not a second independently sampled E5 conversation.

## Results

| Case | System | Verdict | Path | Model calls | Tool calls |
| --- | --- | --- | --- | ---: | ---: |
| C01: input reaches eval argument | E4 | VULNERABLE | slow | 8 | 8 |
| C01: input reaches eval argument | E5 | VULNERABLE | fast | 6 | 4 |
| C02: input goes to unused audit argument | E4 | ABSTAIN | slow | 9 | 8 |
| C02: input goes to unused audit argument | E5 | ABSTAIN | slow | 9 | 8 |

Both planners selected scan `probe_python_eval` and taint `trace_dataflow`, with no
dependencies between their conclusions. They recognized authz as outside the candidate's
scope. The declared full-review policy nevertheless runs the fallback authz specialist.

In C01, scan and taint separately returned `VULNERABLE / CONFIRMED`, each at confidence
0.99, citing its own validator observation. Scan explicitly limited its claim to the
admitted function slices and did not claim full application exploitability. Authz returned
`ABSTAIN / UNRESOLVED`. E5 skipped that final specialist, saving two model calls and four
tool calls. The larger tool saving reflects authz requesting four tools in one model turn.

In C02, scan predicted `SAFE / UNRESOLVED` at confidence 0.91 from explicit argument
mapping; it did not claim a successful typed refutation. Taint initially submitted
`SAFE / REFUTED`, despite its dataflow tool returning `UNRESOLVED`. Evidence validation
rejected the over-strong status. Luna corrected to `ABSTAIN / UNRESOLVED`. Authz also
abstained. A single SAFE vote did not reach quorum, so both systems abstained.

The C02 taint role also encountered a reply-file transport-path error before a successful
submission; this did not become a workflow observation or extra model call in the record.
The one evidence-correction turn is included in the reported nine workflow model calls.

## Interpretation

The newly implemented path now has fresh model-in-the-loop evidence: Luna followed the
capability guidance, planned two applicable checks, invoked the new tool, supplied the
necessary citations and reached a two-vote positive decision. Fast and full agreed in both
cases without changing quorum. No implementation or prompt was changed during these runs.

The negative case still exposes uncertainty and a model tendency to overstate refutation;
the existing evidence validator caught it. The experiment does not establish reliable SAFE
classification, generalization across repositories or stable success rates. It contains one
fresh run of each of two known development cases. The probe covers a restricted Python
subset, and both validators share the AST index/call graph. These observations cannot be
used to substantiate the historical 28% or 37% metrics or a DeepSeek held-out result.
