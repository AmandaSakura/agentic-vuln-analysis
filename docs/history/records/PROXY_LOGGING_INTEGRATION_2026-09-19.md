# Automatic local proxy diagnostics

The shared `OpenAICompatibleChatModel` now reads local CLIProxyAPI native-response
evidence when `proxy_log_dir` is configured. Both existing Gemini benchmark model
configurations enable it, including the LangChain pair runner.

Each outgoing request gets a random `X-Cv-Agent-Request-Id` header. The runtime
waits up to two seconds for the proxy's local log and requires both that header
and the native response ID to match the current request/response. File timestamps
only reduce the search set; they do not establish attribution. Partial, missing,
unreadable or conflicting logs cannot establish an upstream block.

The experiment journal receives a `model_proxy_diagnostic` event with:

- `diagnosis`: `upstream_response`, `upstream_blocked`,
  `native_evidence_unavailable`, or `native_evidence_conflict`;
- request and response IDs, a normalized block-reason enum, candidate count,
  reported native token totals and upstream output-budget field when present.

An established block causes the ordinary failed-trial path to report
`upstream_blocked: OTHER` (or the observed enum). It never produces a safety
verdict. Received usage is recorded before parsing and counted once; native
usage is corroborating evidence, not an additional request charge. A missing log
does not invalidate an otherwise valid reply or invent a cause for an empty one.
HTTP/connection errors retain the existing transport errors; native correlation
currently requires a decoded response with an ID. No retries or fallback were added.

Only whitelisted diagnostics are exported from proxy logs. Authorization headers,
OAuth tokens, raw native message text and project identifiers are not copied into
experiment diagnostics. The standalone historical audit uses the same parser.

## Local service setup

`~/.config/cliproxyapi/config.yaml` now retains `request-log: true`.
`~/.config/cliproxyapi/auths/logs` is mode `0700`. The systemd user-service drop-in
`~/.config/systemd/user/cliproxyapi.service.d/private-logs.conf` sets `UMask=0077`,
so new raw log files are private. The service was reloaded, restarted and verified
active. Raw logs remain local and outside the repository; they contain sensitive
request/response material and are not intended as shareable artifacts.

## Verification

Nine new tests cover bound blocking, absence/mismatch/partial writes, a valid
reply without logs, delayed log completion, conflicting evidence, timestamp
rounding, secret exclusion and non-duplicated accounting.

Full suite: **363 passed in 9.32s**. The full gate caught the initial timestamp
rounding defect and blocked live transport before the fix.

One benign live verification requested `Reply with OK.` through the normal gate.
It returned successfully and automatically recorded `upstream_response` with
matching IDs: **1 request, 92 provider-reported tokens**.

Artifact: `artifacts/transport_raw_diagnostic/721590c1000d4509a7c922bd31efb55c/`.
The earlier attempt `944c0ec139c643f59b0cd29eeb941e81` stopped at the pytest gate
and made zero model requests. No blocked vulnerability prompt was resubmitted.

To repeat this single benign verification:

```sh
source ~/.config/cliproxyapi/client.env
export ANTIGRAVITY_API_KEY="$OPENAI_API_KEY"
uv run --no-sync python scripts/verify_proxy_logging.py
```

This implements failure visibility; it does not change Google's filtering or
complete the previously incomplete LangChain paired evaluation.
