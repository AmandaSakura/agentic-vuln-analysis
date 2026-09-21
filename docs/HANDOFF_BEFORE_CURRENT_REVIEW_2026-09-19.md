# Handoff 2026-09-19 — Test Contract and Evidence Repair

Project: `/home/joker/AAA_NUS_SEM2/cv_agent`.

Read `AGENTS.md`, `docs/TEST_CONTRACT.md`, and `docs/TEST_REPAIR_RESULT_2026-09-19.md` before continuing. The user requires a complete pytest pass before every changed version can enter real API experiments. The live runtime enforces that requirement; do not bypass it with raw HTTP, environment flags or old pass logs.

## What changed

- Review findings and counterexamples: `docs/PROJECT_REVIEW_2026-09-19.md`.
- Executed repair plan: `docs/superpowers/plans/2026-09-19-test-contract-and-repair.md`.
- The full pytest gate runs once per process/source snapshot before model transport; changes or a failed test run block subsequent calls. Its logs live under `artifacts/pytest_gate/`. A failed gate does not consume a model request.
- Static taint reports `MAY_REACH/NOT_ESTABLISHED` and retains `UNRESOLVED` validation. Guard-name patterns and source differences are hypotheses, not exploit confirmations. The concrete Python probe retains supported positive witnesses.
- Candidate confirmations carry a typed repository/candidate/entry/source-digest identity. Request probes/dataflow must begin at the candidate; registered fixtures must have a matching subject. Final evidence validation rejects another subject's result.
- Python qualified imports no longer produce bare-name shortcuts into unrelated files. Probe resolution preserves aliases and rejects module rebinding/shadowing.
- API usage is saved before response parsing, including malformed messages and tool arguments, and counted once. Raw response diagnostics now use the shared runtime and journal.
- LangChain detector IDs are neutral; checkout locators are runner-private. Differential reproduction requires the exact benign output and intended invalid-variable rejection, bounded child execution, pinned revisions and clean checkouts.

The worktree retains earlier uncommitted changes. This repair did not create a commit or PR and did not make any real model API requests. Historical experiment artifacts have not been rewritten to the new validator semantics.

## Verified evidence and its limits

The local LangChain vulnerable/fixed pair still has a reproducible difference for the synthetic attribute and dunder probes; benign formatting is a separate required control. This does not prove the Agent can discover or validate this vulnerability.

The 66-case context audit previously retained direct targets in 0/66 original text, 66/66 graph and 66/66 metadata-BM25 cases. Future retrieval comparisons must include the stronger text baseline. The 8-case live comparison is exploratory prediction evidence, not a general accuracy or exploit-confirmation result.

The usage audit now includes the formerly omitted raw proxy diagnostic: 362 recorded requests and 1,371,526 reported tokens, with one older request missing usage. This is the subtotal for supported recorded families, not a claim to recover every historical service bill.

## Transport diagnosis: observations, not an established safety cause

Pinned CLIProxyAPI source deletes non-Claude `maxOutputTokens` and translates candidate arrays into choices. Some saved compatible responses contain empty choices and reasoning usage. The saved `transport_raw_diagnostic` response is a successful compatible-proxy response, not a failed native Google response.

The assertion that vulnerability-related reasoning triggered Google safety moderation was not established by those artifacts. Do not preserve that assertion as a confirmed root cause or automatically classify all empty choices as safety blocks. No automatic retry or fallback was added. A future retry policy needs evidence, explicit request accounting and bounded tests.

Do not print proxy credentials or restart/modify the shared proxy.

## Remaining work

1. LangChain E1 runner is now implemented in `scripts/run_langchain_pair_eval.py`, with neutral inputs and subject-bound current-run pair evidence. See `docs/LANGCHAIN_AGENT_RESULT_2026-09-19.md`.
2. Full pytest (350 passed) and mandatory real-pair preflight passed. Live attempt recorded both cases as failed before transport because `ANTIGRAVITY_API_KEY` is absent; zero requests. Configure the variable in the execution environment, then rerun the runner. Keep prediction labels, typed validation, failures and costs separate.
3. Scanner rules still do not discover template-formatting sinks. Oracle-seeded pair analysis is not end-to-end scanner recall.
4. The full 330-trial OWASP matrix is incomplete. The held-out input preparation has 20 repositories / 158 source checkouts and no evaluated held-out results. Do not expand to full evaluation before small-batch correctness is demonstrated.
5. LangChain is now development-inspected. If it informs tuning, produce a new held-out manifest excluding related repository/advisory data and retain the old manifest for audit.

## Offline commands

```sh
uv run --no-sync pytest
uv run --no-sync cv-agent harness-check
uv run --no-sync python -m cv_agent.live_gate
uv run --no-sync python scripts/summarize_live_usage.py
```

The standalone gate command tests admission without sending any API request. Admission is not transferable to another process; a real run independently verifies its current snapshot.
