# Semantic Repairs Implementation Plan

> Execute inline in this task; the user has authorized implementation.

**Goal:** Repair the nine reproduced failures without promoting incomplete static evidence to safety or exploit proof.

**Architecture:** Permission collection must report incomplete traversal distinctly from real termination. Command-flow analysis must retain interpreter taint and recognize local fixed argv only when its structure cannot be changed or escape the bounded analysis.

**Tech Stack:** Python AST, existing tool registry, offline pytest through uv.

- [x] In `src/cv_agent/tools/validation/permissions.py`, mark unvisited statements following a nonconstant branch as incomplete; remove unsupported Try from the bounded issue allowlist. Preserve straight-line and dead-code controls.
- [x] In `tests/test_semantic_diagnostics.py`, add argv reassignment, mutation, alias escape, keyword args, explicit executable, and absolute shell path controls. Run `uv run --no-sync pytest -q tests/test_semantic_diagnostics.py --tb=short` before implementation.
- [x] In `src/cv_agent/tools/analysis/python_flow.py`, retain taint for interpreters and executable overrides; recognize single-assignment argv literals whose references are exclusively supported subprocess argument uses. Do not infer safety for escaped or mutated containers.
- [x] Run `uv run --no-sync pytest -q tests/test_semantic_diagnostics.py tests/test_taint_regressions.py tests/test_review_semantics.py tests/test_validation_tools.py`.
- [x] Run `uv run --no-sync pytest -o addopts='' -q` and `git diff --check`; update `docs/CURRENT_STATUS.md` and append actual repair results to the diagnostic record. No live model calls.
