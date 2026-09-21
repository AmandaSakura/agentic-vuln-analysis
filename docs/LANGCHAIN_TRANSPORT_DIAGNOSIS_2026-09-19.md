# LangChain empty-response diagnosis

## Confirmed finding

The second diagnostic batch captured a native upstream response with
`promptFeedback.blockReason = OTHER`, no candidates, and 488 reasoning tokens.
The upstream message explicitly attributed the block to Gemini's filters.
The downstream OpenAI-compatible response with the **same response ID** contained
`choices: []` and 2,311 total tokens, but omitted the native feedback.

This establishes an upstream filter block for that captured request and loss of
the explanatory feedback during proxy conversion. It does not establish why the
filter fired. Historical empty responses without native logs remain unresolved;
they are not retroactively classified as blocked.

CLIProxyAPI v7.3.6, commit `8c664b2fede5c83b919be1df9b01057ec4e4c950`, was checked
against the installed binary's reported version and commit. Its non-stream
Antigravity translator passes the native `response` to the Gemini/OpenAI
translator. The latter copies usage and candidates but not `promptFeedback`.
No proxy implementation was changed.

Relevant pinned source:

- [Antigravity non-stream response conversion](https://github.com/router-for-me/CLIProxyAPI/blob/8c664b2fede5c83b919be1df9b01057ec4e4c950/internal/translator/antigravity/openai/chat-completions/antigravity_openai_response.go)
- [Gemini/OpenAI response conversion](https://github.com/router-for-me/CLIProxyAPI/blob/8c664b2fede5c83b919be1df9b01057ec4e4c950/internal/translator/gemini/openai/chat-completions/gemini_openai_response.go)

## Output-budget correction

All three captured native requests had `generationConfig = {"temperature": 0}`.
The configured client `max_tokens: 1200` did not reach upstream as
`maxOutputTokens`. The installed proxy version explicitly removes that field
for non-Claude Antigravity requests in
[antigravity_executor_request.go](https://github.com/router-for-me/CLIProxyAPI/blob/8c664b2fede5c83b919be1df9b01057ec4e4c950/internal/runtime/executor/antigravity_executor_request.go).

Therefore prior client-side 1200/8192 probes do not establish a controlled
upstream output-budget comparison. This is not evidence that increasing the
client budget fixes the failures. Request-count and admission-time limits are
separate and remain enforced by the project runtime.

## Bounded experiments

Both batches replayed the first recorded request without executing tools:
two predeclared samples of `template_case_01`, then one `template_case_02` control.
Model, prompts and tools were unchanged. All requests used
`OpenAICompatibleChatModel` and the full offline pytest gate.

| Run under `artifacts/langchain_transport_probe/` | Requests | Valid | Empty | Reported tokens |
| --- | ---: | ---: | ---: | ---: |
| `7a861083912943488c2f83ac20ea8858` | 3 | 2 | 1 | 6,235 |
| `d8a1e7683da44c5dbe2d635a40c8602d` | 3 | 2 | 1 | 6,489 |
| Total | 6 | 4 | 2 | 12,724 |

The first batch's logging setting did not take effect until a service restart.
Only the second batch has matched native logs. In each batch the first
vulnerable-side sample was empty, the second requested a tool, and the fixed-side
control requested a tool. These are transport observations, not final verdicts
or an estimate of general reliability. No prompts were rewritten to evade the
filter, no automatic retries or fallback were added, and no further model calls
were made after the native blocking reason was identified.

## Delivered changes and verification

- `scripts/probe_langchain_transport.py` and its fixed JSON configuration preserve
  exact-input samples, request limits, received responses, errors and usage.
- `scripts/audit_langchain_transport.py` and its configuration correlate native
  logs with journaled response IDs. The report distinguishes `upstream_blocked`,
  unresolved empty responses and nonempty choices. Conflicting matching native
  evidence is rejected. Nonempty choices are not claimed to be final verdicts.
- The audit exports whitelisted diagnostic fields only. Authorization headers,
  OAuth material, private project identifiers and raw message bodies stay out of
  exported reports. The native logs remain outside the repository in the local
  proxy's protected log directory.
- The overall usage audit now includes the new diagnostic family exactly once.
- Four regression tests cover confirmed blocking, valid controls, unmatched and
  unexplained empty responses, conflicting IDs, secret exclusion and accounting.
- Full offline suite after changes: **354 passed in 9.80s**. Each preceding live
  diagnostic batch passed its then-current full **350-test** gate.
- Proxy request logging restored to `false`; service restarted and active.

Offline reproduction (no credentials or API calls required):

```sh
uv run --no-sync pytest
uv run --no-sync python scripts/audit_langchain_transport.py
uv run --no-sync python scripts/summarize_live_usage.py
```

Audit artifact: `artifacts/langchain_transport_diagnosis_2026-09-19.json`.
Reproducing the native correlation requires the retained local proxy logs.
The audit is an offline diagnostic, not a runtime proxy patch: future empty
responses without native feedback remain unresolved.

## Remaining limitation

The full pair still lacks a completed vulnerable-side Agent verdict. The earlier
fixed-side `SAFE / REFUTED` remains limited to the two traversal hypotheses.
The six concrete reproduction probes already demonstrate the local pair's
behavior, but do not substitute for a live Agent evaluation or automatic
vulnerability discovery. Provider-side filter review is the appropriate next
step for the confirmed block; repeated sampling until a pass would not establish
a repair. No provider report was sent and no complete-pair success is claimed.
