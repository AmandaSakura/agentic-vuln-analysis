# Remove Legacy Facades Implementation Plan

> Execute locally in tested batches. The user authorized removing obsolete Python import paths without further consultation. Preserve public CLI/shell behavior, detector semantics, dirty work and historical artifacts; do not run paid models.

**Goal:** Leave only `__init__.py` and `cli.py` at the package root and remove all 71 obsolete forwarding modules.

**Architecture:** Implementation and tests import each symbol from its owning package. Small launch scripts remain commands, not general-purpose re-export modules. Dataset/result schemas, analysis logic and frozen output fixtures remain unchanged.

**Tech Stack:** Python, AST-aware import migration, pytest, uv wheel build.

## 1. Migrate remaining consumers

- [x] Back up current source/tests/scripts/config/docs outside the checkout and run the complete baseline suite.
- [x] Add an AST regression that rejects legacy imports in implementation and ordinary behavior tests, including `from cv_agent import old_module`.
- [x] Rewrite symbol imports using the existing forwarding definitions. Replace dynamic schema lookup with explicit canonical class mappings; keep all schema and behavior assertions.
- [x] Run focused tests and the full offline suite before deleting any module.

Example canonical imports:

```python
from cv_agent.domain.chat import ModelReply, ModelToolCall
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.tools.registry import ToolRegistry
```

## 2. Retire the old Python paths

- [x] Add failing tests for the two-file root and the absence of forwarding modules.
- [x] Replace old/new identity checks with canonical ownership and public-API checks. Keep parser goldens, evidence assertions and offline quorum behavior checks.
- [x] Delete only the 71 identified forwarding source files. Remove their now-unused package directories without touching historical outputs.
- [x] Update current docs to canonical `python -m cv_agent.runtime.admission` and `python -m cv_agent.evaluation.quorum_probe` commands. Historical dated records remain historical.
- [x] Run the complete suite; record why compatibility-specific assertions changed rather than hiding the test-count difference.

## 3. Finish navigation and command boundaries

- [x] Reduce script entry points to imports needed by their existing main guards; preserve both standalone worker probes and all guard arguments.
- [x] Keep useful top-level public object exports but remove the claim that the root contains compatibility modules.
- [x] Verify shell/CLI routes, offline commands, wheel imports, frozen configs and historical artifact identity; update the cleanup record.

Completion requires a passing full suite and no active source/test/launcher reference to removed module paths. No deletion of historical data or analyzer behavior change is part of this plan.
