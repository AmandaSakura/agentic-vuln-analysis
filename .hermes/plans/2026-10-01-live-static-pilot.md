# Bounded Live Static Evidence Pilot

User instruction: start the proposed small real-model trial. This is a new research diagnostic, not R17 product enablement, a K5–K8 restart, target execution, or a held-out claim.

- Model: configured deepseek-flash, thinking disabled, max output 1024, timeout 180s.
- Inputs: the current owned application directory's three candidates plus two anonymous generated literal-mode controls. References and canonical finding states remain outside model messages.
- Calls: five single-shot requests at most; 30000 reported tokens. Reserve serialized request bytes plus 1024 output tokens and 256 framing allowance before each call; this is conservative admission bookkeeping, not a provider-token measurement.
- Transport: only OpenAICompatibleChatModel. Run its original full pytest gate in the actual experiment process before reading credentials. Subsequent complete() retains its gate and same-source checks. No saved stamp, raw HTTP, retry or alternate model.
- Produce static bundles before model calls, verify each complete package, and supply only source slices, declared contract and original registered observations. Model tools are empty. No source module import/execution.
- Output: append/fsync actual request and raw response/usage events, proposed JSON and acceptance decisions. Malformed JSON, missing/contradictory usage, returned model mismatch, budget boundary, transport error or unsupported strong assertion stops the run and retains artifacts.
- Credentials: use only DEEPSEEK_API_KEY from the existing .env.experiments, after the gate. Never print or snapshot credentials.
- Score: per-candidate source/observation grounding, proposed-state consistency, invalid responses, request usage, latency and complete failures. A model state never overrides canonical static evidence.
- Missing external validity: these development controls and this self-owned repository cannot establish held-out detection quality, human benefit or general project safety.

Implementation is isolated in audit/live_static_pilot_20261001/{protocol.json,run.py}. Execute once with the project uv environment; preserve all historical artifact directories. No production source/test changes are required.

## Actual outcome

Executed once. The in-process gate passed 2941 tests in 427.49s before credential loading. Two actual provider requests returned deepseek-flash, 3759 reported tokens with no missing/conflicting usage. First UNKNOWN was accepted; second UNKNOWN matched the canonical static state but referenced a tool-internal source/fact ID rather than the permitted observation reference namespace. The original run stopped with no retry; three planned candidates remain unrun. Read-only reconciliation is in `audit/live_static_pilot_20261001/result.json`. Do not treat this as completion of all five candidates or independent project quality evidence.
