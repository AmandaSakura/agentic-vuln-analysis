# LangChain Agent Integration Implementation Plan

**Goal:** Complete the oracle-seeded development evaluation with candidate-bound executable evidence and bounded live calls.

**Architecture:** Reuse the existing six-process pair reproduction as mandatory offline preflight. Register its evidence through `run_fixture_test`, checking checkout identity and source contents again on use. Keep private labels and physical paths outside detector inputs. Use the existing E1 Agent pipeline and recorded runtime, with no provider retries.

**Tech Stack:** Python, pytest, existing AgenticPipeline and local LangChain environments.

- [x] Add failing tests for neutral inputs, wrong subjects, modified sources, and concrete pair evidence.
- [x] Implement `scripts/run_langchain_pair_eval.py`; expose only the registered scenario ID and sanitized observed behavior. A fixed case refutes only these two traversal hypotheses.
- [x] Extend recorded tool injection without changing existing default behavior.
- [x] Run targeted tests, then `uv run --no-sync pytest` and mandatory real pair integration.
- [ ] Run the configured two-case E1 evaluation with at most 20 requests and 300 seconds; preserve failures and usage.
- [x] Document actual outcomes and limitations. Preserve dirty work; no aggregate commit.

Live evaluation was attempted but remains incomplete: missing `ANTIGRAVITY_API_KEY`, zero requests. Both failed trials and passing real-pair preflight are preserved in the result report.

Execution is inline under the user's continue instruction; the executing-plans subskill is unavailable.
