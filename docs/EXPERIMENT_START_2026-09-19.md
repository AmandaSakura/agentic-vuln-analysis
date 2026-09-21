# Development experiment launch — 2026-09-19

The user requested starting experiments after the bug repairs. The frozen
66-case OWASP E1–E5 development matrix is now running. This is development
evaluation, not independent held-out validation.

## Updated-code pair acceptance

Run: `artifacts/langchain_agent_eval/615ca84226fd4c08b701575dc54dcb6e/`.
The mandatory gate passed all 377 tests. Both E1 cases completed: vulnerable
VULNERABLE, fixed SAFE within the two declared traversal hypotheses. Six model
requests returned usable responses; reported total usage was 15,698 tokens.
This run includes the explicit analysis scope and generator-probe repair.

## Full development matrix

Run: `artifacts/development_benchmark/87818baabbba4552b31c02af055ac938/`.
Command: `uv run --no-sync python scripts/run_development_benchmark.py`.
Execution session: 18828; Python PID at launch: 383745.

- 66 frozen cases, 11 categories, E1–E5: 330 scheduled trials.
- Existing limits: 6,600 model requests, 86,400-second admission window.
- Existing model configuration: `configs/micro_benchmark.json`; unchanged.
- Source snapshots, frozen manifest and dataset identity: `metadata.json` and `source/`.
- Durable request/tool evidence: `events.jsonl`.
- After each trial: `results.json`, `summary.json`, `report.md`.
- No automatic retry or provider fallback. Failed, abstained and unrun cells
  remain in denominators. Token usage is reported; monetary cost is unknown.

The earlier pilot expansion hold was reviewed against the later completed
bounded E3–E5 checks and the new pair acceptance; this launch follows the user's
request to proceed. Intermittent provider blocking remains measurable failure,
and the proxy still strips the output-token cap. The request limit is not a
guaranteed token or currency ceiling.

A first shell-detached launch (PID 383581) did not survive its shell and made no
recorded model requests. The actual run above uses the persistent execution
session. No completed run was overwritten or restarted.

## User-requested stop

Stopped with SIGINT after approximately 19.7 minutes; both runner processes
exited and the final summary was flushed. No restart was made.
44 E1 trials abstained, one trial was interrupted, 285 trials were not run.
331 requests were recorded, with 330 responses, zero invalid responses and
619,489 reported tokens. One interrupted request has unknown reported usage;
remote computation may continue after the local client disconnects.

The sampled E1 rationales consistently cite candidate-local `doGet` delegating
to `doPost` outside admitted context. More requests or concurrency alone will
not correct this evidence limitation. Review candidate/context protocol before
another full run; any protocol change must create a separately identified run.
