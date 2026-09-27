# Jev routing implementation plan

**Goal:** Replace generative planning with one typed Jev request when a bounded three-expert plan is sufficient; retain LLM deep planning for uncertainty.

**Architecture:** Add the native TypeSafe protocol to the existing gated `OpenAICompatibleChatModel`. A router reads candidate source through the scoped tool registry, chooses a validator for each expert, and validates the assembled plan using existing policy. Routing is recorded separately from expert evidence and never contributes a vote.

**Tech stack:** Python, Pydantic, urllib, LangGraph, pytest; no new dependency.

The repository's documentation layout requires plans under the existing reference/history directories. Implementation proceeds inline under the user's authorization.

- [x] Add `runtime/jev.py` and offline transport tests: POST `/v1/systemone`, strict choice validation, usage preservation on malformed responses, test-gate enforcement, no retry.
- [x] Add `agents/routing.py`, a routing result contract, and optional workflow routing: scoped source read, validator selection, confidence threshold, existing plan-policy checks, explicit LLM escalation, unchanged expert quorum.
- [x] Extend evaluation execution with an explicit routing configuration. Add a separate, bounded development runner/config and a no-argument launcher that loads `JEV_API_KEY` from `.env.experiments`.
- [x] Cover routing success, uncertainty, invalid choices, source truncation, evidence invariants and usage accounting with offline tests. Run `uv run --no-sync pytest` before any live request.
- [x] Document the environment variable, command, output directory and limits. No live Jev experiment can run until the user supplies its key.

Validation: full offline suite passed, **1219 tests**. Native Jev HTTP and the mixed Jev/chat evaluation were verified with mocked responses; no real provider request was made. Historical `AgenticVerdict` schema and scripted E1–E5 output remain unchanged; only `RoutedAgenticVerdict` carries routing records.

## V2: bounded decisions inspired by mu

Reference commit: `AmandaSakura/mu@8252cc6ed561e45ff658c9c89f134b9e90499bc8`, particularly `policy.ts`, `decision.ts`, `decisions/swarm-routing.ts` and the Jev retrospective.

- [x] Replace the global plan question with independent `validator.scan`, `validator.taint`, `validator.authz` choices. Keep probability thresholds at 0.85; record model confidence separately.
- [x] Preserve accepted validator tasks. Experts whose choice is uncertain retain their existing unassigned ReAct execution; required permission/command/fixture plan policy remains authoritative. Escalate the whole plan only if no choices are usable or policy rejects the composition.
- [x] Add explicit off/shadow/active modes, proposed vs applied decisions, specification version, state digest and latency. Shadow leaves baseline planning budgets intact. API/ledger errors remain failures under this repository's contract.
- [x] Add a V2 configuration and retain the original V1 config and all run artifacts. Cover partial adoption, probability/confidence differences, shadow/off, policy rejection and request/usage accounting offline.
- [x] Run the complete offline suite. Record a local replay of the two historical responses without treating it as a V2 live result; do not infer quality or savings from replay.

V2 validation: **1230 tests passed**. The partial-plan fixture and command checks still escalate when required dependencies or mandatory taint checks would be missing. Shadow-mode tests compare the exact planner and expert requests against the original E4 execution. Historical response-policy replay is documented in [Jev routing](JEV_ROUTING.md); no V2 live request was made.
