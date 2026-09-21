# Configuration Layout Implementation Plan

**Goal:** Make config ownership visible and remove duplicated active advisory definitions without changing experiment semantics.

**Architecture:** Models, datasets, profiles, experiments, preparation, diagnostics and historical paired protocols have explicit directories. Existing JSON files move with only declared config path substitutions. Current gate/matrix compose their existing validated dataset/profile contracts; no fallback or discovery loader.

**Tech Stack:** Python, Pydantic, JSON, offline pytest.

## Batch 1 — classify and relocate

- [x] Freeze every original config byte hash and old/new mapping in tests/fixtures/config_relocation.json.
- [x] Add tests/test_config_layout.py: no root JSON, reverse declared path substitutions and verify original hashes, resolve every config dependency.
- [x] Run new tests and observe missing layout failures.
- [x] Move 33 root configs into explicit categories. Update executable source and test fixture paths, including split Path expressions and dynamic filenames; retain artifact paths and historical documents.
- [x] Preserve old operational-entrypoint golden guards: normalize only declared config paths in their AST comparison.
- [x] Run the complete offline suite before batch 2.

## Batch 2 — current advisory entrypoints

- [x] Add tests that runner load_config equals the archived v4 contract, uses dataset/profile files, and preserves 10/30 cell order, MLflow scope, import roots, budgets, expected abstentions, and model config contents.
- [x] In evaluation/datasets/composition.py add explicit file loading using AdvisoryDataset, AdvisoryRunProfile and compose_advisory_config.
- [x] Switch gate/matrix and v4 audit to the same loader. Adapt synthetic fixtures to write separate contracts; test missing and invalid files fail rather than using history.
- [x] Write configs README and update current documentation to identify current paths, historical status and dedicated experiments still in use.
- [x] Run complete offline pytest, wheel/CLI checks and historical artifact preservation checks.

No real model calls, credential access, downloads, commits or historical artifact rewrites. Work inline under existing user authorization.


## Verification results

- Batch 1: new layout tests failed before migration. After relocating config dependencies
  and synthetic fixture paths, the complete offline suite passed: 739 tests.
- Batch 2: new current-runner tests failed when only split declarations existed.
  After switching to composition, the complete suite passed: 741 tests in 27.09 seconds.
- Tests verify exact resolved contracts, 10/30 cell order, scenario/import-root invariants,
  profile and dataset changes reaching the runner, and rejection of missing/invalid
  current profiles even when historical copies exist.
- All 36 original JSON payloads match original byte hashes after reversing only the
  declared path substitutions. No config removed; root contains README and seven directories.
- Offline wheel imports: 165 modules; offline CLI checks: four. Historical artifacts:
  all 15,492 original file sizes and modification timestamps preserved.
- No credentials read, model requests sent, benchmark downloads or commits performed.
- Existing historical preparation commands retain their previous regeneration behavior;
  history is organizational, not a new immutable storage mechanism.
