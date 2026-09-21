# DeepSeek output correction repair, 2026-09-21

Source run: artifacts/python_heldout_pair_gate_v2/3d7c8ffe622e48018e20c953bcf70e2c.

The hp001_b/E5 scan expert repeatedly cited an exact-scope REFUTED observation in supporting_observation_ids while evidence_ids contained only a retrieved source reference. The existing evidence contract also requires a validator reference in evidence_ids, but the generic error did not identify this omission. Other failed loops ended with rationale strings exceeding 360 characters despite a generic schema correction message.

Changes in src/cv_agent/react_engine.py:

- Explicitly document the dual citation requirement in the expert prompt.
- When a matching, untruncated, exact-subject supporting validator is missing from evidence_ids, report its citation ID and the field to correct. Do not recommend unrelated or mismatched validator evidence.
- State the 360-character rationale limit in plain language, with a shorter one-sentence target.
- On rationale length errors, report the actual character count and ask for one sentence under 180 characters while preserving the substantive judgment and citations.

No output is truncated or auto-reclassified; schema limits, evidence rules, and step budgets remain unchanged. Existing subject, conflict, unsupported-evidence, and malformed-output checks remain active.

Two new offline regressions failed before the implementation and passed afterward. They exercise complete correction conversations and check that corrected VULNERABLE/CONFIRMED outputs remain accepted, without converting them to abstentions. Relevant tests: 53 passed. Full suite: 633 passed in 25.14s. git diff --check passed.

No new live API calls were made during this repair. The earlier gate still failed. These changes repair actionable feedback, not proof of live model compliance or recovery of the separate ABSTAIN result; a new bounded run is needed to measure those outcomes.
