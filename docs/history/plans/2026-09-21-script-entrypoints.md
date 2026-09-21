# Direct operational entry points

The user requested continuing the cleanup of `scripts/`. This plan preserves
operational behavior and removes obsolete Python launcher paths. No model calls,
dataset downloads, credential reads or historical artifact edits are needed.

## Batch 1: remove Python forwarding commands

- Freeze all 47 launcher main guards before changes.
- Add failing tests that scripts has no forwarding Python files, package module
  guards retain all original arguments, and both heldout shell commands invoke
  `uv run --no-sync python -m cv_agent.evaluation.runners.run_python_heldout_pair_*`.
- Test the shell commands with copied launchers, a temporary fake environment file
  and a fake uv executable, never the real `.env.experiments`.
- Delete only the 47 wrappers and update the two shell command lines.
- Micro provenance records the actual implementation files recursively, with no
  dependency on a deleted launcher; retain byte/hash assertions in regression tests.
- Run targeted tests and full offline pytest before the next batch.

## Batch 2: standalone workers and navigation

- Move the two unchanged workers to `scripts/probes/`, update reproduction runner
  paths, and test direct isolated interpreter execution with `--help`.
- Keep the workers independent of cv_agent; verify their original bytes and include
  nested scripts in the no-ungated-HTTP scan and existing admission fingerprint.
- Leave four shell commands plus a scripts README at the root. Keep DeepSeek CLI
  argument behavior and benchmark-fetch behavior unchanged.
- Describe direct package commands for other runners/preparation/diagnostics.
- Preserve archived documents and frozen configs; descriptions of old script paths
  in those historical inputs are not live command routing.
- Finish with complete pytest, offline wheel import/CLI checks, original guard
  comparisons, and artifact preservation checks.

## Completed verification

- Batch 1: all 47 original main-guard source fragments are compared as ASTs
  using the test interpreter; this avoids Python-version differences in AST dump
  formatting. Mocked shell tests verify argv, working directory and exported
  environment. Complete offline suite: 734 passed.
- Batch 2: path and isolation tests failed before moving workers, then passed
  after relocation. Original worker SHA-256 values are unchanged. Complete
  offline suite: 737 passed (26.24 seconds).
- Offline wheel: 165 modules imported without checkout scripts on sys.path;
  four offline CLI checks passed. Shell syntax and git diff whitespace checks passed.
- All 15,492 pre-existing artifact file sizes and modification timestamps match
  the pre-refactor manifest. Original config hashes match. DeepSeek and benchmark
  download shell files remain byte-identical.
- No real model calls, credential reads or benchmark downloads were performed.
- Compatibility change is explicit: the 47 old Python script paths are removed;
  equivalent module main guards retain their original arguments and behavior.
