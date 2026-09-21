# LangChain Agent integration result

Historical note: the subsequent [semantic review](CURRENT_REVIEW_RESULT_2026-09-19.md)
found that the candidate's scope text in `query` was not model-visible. The runner
now uses explicit, budgeted `analysis_scope`, bound to validation identity. The
successful live run below predates that fix. A later scoped pair,
`615ca84226fd4c08b701575dc54dcb6e`, completed with 6 requests / 15,698 tokens.
For the current implementation and limits, see the [deep review](DEEP_REVIEW_RESULT_2026-09-19.md).

## Latest rerun: complete pair succeeded

User-requested single rerun after automatic proxy logging integration:
`artifacts/langchain_agent_eval/b24820ebdb2848f1a1854f01bf89db6a/`.

- Full offline gate: **363 passed in 9.55s**; all six real preflight probes passed.
- Vulnerable side: **VULNERABLE / CONFIRMED**, two model requests, two tool calls.
- Fixed side: **SAFE / REFUTED**, four model requests, three tool calls.
- **6 actual requests, 6 valid replies, 0 invalid replies, 15,769 reported tokens**;
  no missing usage. All six native proxy responses were automatically matched;
  none reported an upstream block.

This run completes the two-candidate, oracle-seeded E1 development pair for the
attribute/dunder traversal hypotheses. It does not establish general safety,
automatic discovery, held-out performance, or resolution of intermittent
provider filtering. Earlier failed runs below are retained as historical evidence.

Implemented `scripts/run_langchain_pair_eval.py`. It uses E1, two oracle-seeded neutral candidates, the configured 20-request / 300-second admission budget, recorded tools and the shared gated model runtime. A provider call still has its configured 90-second timeout; the admission deadline does not cancel an in-flight request.

Before any model call, mandatory real pair reproduction executes benign, attribute and dunder scenarios on both pinned clean checkouts. The registered `run_fixture_test` exposes sanitized observations from that current-run preflight, not another subprocess per invocation. It rechecks checkout revision/cleanliness, source digest and candidate subject on invocation. Fixed-side evidence refutes only the two declared traversal hypotheses. This is a trusted local fixture, not a sandbox for arbitrary model-supplied code.

Model inputs omit checkout locators, commits and evaluator labels. Pair mapping is checked against pinned reproduction commits. Existing recorded-tool defaults remain unchanged. Usage auditing includes the new experiment family.

Validation: five new tests cover neutral candidate inputs, candidate mismatch, source mutation, invalid fixture IDs, both typed conclusions through the offline Agent pipeline, and actual checkout entry lookup. Full suite: **350 passed in 9.59s**; live gate rerun: **350 passed in 9.04s**. Real six-probe preflight verified the differential security invariants.

Attempt artifacts: `artifacts/langchain_agent_eval/dc7b4407230d4273b1fb66ebd3c933cf/`. Both trials failed before transport with missing `ANTIGRAVITY_API_KEY`. **Zero API requests; no live Agent predictions.** Raw pair subprocess records, package versions, metadata, source snapshots, events and results are retained there. No credentials were accessed or printed.

After configuring `ANTIGRAVITY_API_KEY` in the execution environment, rerun from the project root:

```sh
uv run --no-sync python scripts/run_langchain_pair_eval.py
```

The gate and preflight rerun automatically. This is development evidence, not held-out validation, scanner recall, general safety or multi-expert E4/E5 comparison. Missing credential configuration is the remaining blocker to actual model evaluation.


## Live rerun after loading local proxy credentials

Loaded `~/.config/cliproxyapi/client.env` and mapped `OPENAI_API_KEY` to `ANTIGRAVITY_API_KEY` in the experiment process environment.

Run: `artifacts/langchain_agent_eval/600f45a8e9b847728666fb55fc2119de/`.
Full offline gate: **350 passed in 9.50s**. Mandatory real pair preflight passed.

- `template_case_01` (vulnerable): failed after one request, `model response contains no choices`; no prediction.
- `template_case_02` (fixed): completed with `SAFE` / `REFUTED`, four model requests and three tool calls. This applies only to the declared attribute/dunder traversal hypotheses, not general safety.
- Total: **5 actual API requests**, four valid responses, one invalid response, **12,425 provider-reported tokens**, no requests with missing usage. Configured model: `gemini-3.8-flash-high`; returned model ID: `gemini-3.8-flash`.

Credential configuration is no longer blocking. The incomplete vulnerable-side response remains unresolved; the pair has not achieved a complete successful model evaluation. Historical failed attempts remain preserved.

Reproduction in a fresh shell:

```sh
source ~/.config/cliproxyapi/client.env
export ANTIGRAVITY_API_KEY="$OPENAI_API_KEY"
uv run --no-sync python scripts/run_langchain_pair_eval.py
```

## Follow-up: native empty-response diagnosis

See [the transport diagnosis](LANGCHAIN_TRANSPORT_DIAGNOSIS_2026-09-19.md).
Six additional bounded first-turn diagnostic requests consumed 12,724 reported
tokens. Four replies were valid and two were empty. Native logs for the second
batch prove that one empty reply was an upstream Gemini filter block (`OTHER`)
whose explanatory `promptFeedback` was discarded during proxy conversion.
The original failed request has no native log and remains individually unresolved.

The proxy also removes `maxOutputTokens` for these Gemini requests, so prior
client-side token-budget variations were not an effective upstream comparison.
Offline diagnostic classification and usage accounting are now covered by four
new tests; **354 tests pass**. Full-pair success remains unestablished. No further
model calls were made after the explicit upstream block was identified.

## Automatic logging integration

The shared runtime now automatically correlates local native proxy logs with
each configured Gemini request and records `model_proxy_diagnostic`. Confirmed
blocks produce explicit `upstream_blocked` failures. Logging is persistently
enabled with private file permissions. **363 tests passed**; one benign live
request verified automatic correlation (**92 reported tokens**). See
[implementation and verification](PROXY_LOGGING_INTEGRATION_2026-09-19.md).
No blocked vulnerability request was resubmitted; the paired evaluation remains
incomplete.
