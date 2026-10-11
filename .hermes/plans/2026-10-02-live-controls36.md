# 36 development controls live evidence review

Goal: execute the user-approved, single-shot, tools-disabled review of the existing 36 owned synthetic permission controls.

Architecture: copy source into neutral temporary directories, build and verify product-v2 static bundles, freeze prompts, run the complete in-process pytest admission gate, then use OpenAICompatibleChatModel. Reference labels are loaded only by the subsequent scorer.

Files: audit/live_controls36_20261002/protocol.json, run.py, analyze.py, result.json; docs/CURRENT_STATUS.md.

- [x] Freeze sorted source-only manifest, exact source hashes, one AST-selected chmod operation per case, and producer-observation-only-v1 prompts.
- [x] Run `uv run --no-sync python audit/live_controls36_20261002/run.py`; original full pytest gate passed 2948/433.63s before credentials. Actual 36 requests / 42267 reported tokens; no retries or fallback, no stop condition triggered.
- [x] Score immutable replies against canonical observations (36/36) and, separately, frozen development reference labels (22/36). All historical failures preserved; no unrun cases in this batch.
- [x] Publish counts, confusion tables, scope limits and raw ledger references in result.json, verification.md and CURRENT_STATUS. R17, G-A and claim eligibility unchanged.
