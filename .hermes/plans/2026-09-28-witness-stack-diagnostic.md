# Witness Stack Diagnostic Implementation Plan

> **For agentic workers:** Execute these bounded tasks with the available collaboration tools. The user authorizes one paired target run and dataset v5 with the conditions below.

**Goal:** Save a timeout stack without syscall tracing, then run the two pinned snapshots once each using v5 and the existing heavy profile.

**Architecture:** Keep the command audit hook, seccomp and Landlock. Pass a separate inherited pipe for native faulthandler output, retain that FD through isolation, and drain it with the JSON result pipe. The diagnostic CLI explicitly disables strace; grants are forwarded regardless of tracing. Dataset v5 differs in one JSON value, with a sidecar version note so the JSON remains a one-key change.

**Tech Stack:** Existing UV environments, Python faulthandler/os/select, existing source-bound witness.

---

## Task 1: v5 with preserved v4 defaults

- [x] Create `configs/datasets/advisory_pairs_v5.json` by copying v4 and changing only `pairs[2].entry_value_assumptions["self._nworkers"]` from null to 1.
- [x] Write `configs/datasets/advisory_pairs_v5.md`: bound source says `workers or 1`, default workers is 1; old six-cell runs stay v4; existing experiments keep v4; v5 keeps `claim_eligible=false`.
- [x] Add a failing exact recursive diff/loader regression before implementation. Add an explicit optional dataset selector to the loader and diagnostic preparer, both retaining v4 defaults.

## Task 2: separate diagnostic stack pipe

**Modify:** `src/cv_agent/evaluation/diagnostics/bounded_execution_witness.py`, `run_bounded_witness_diagnostic.py`.
**Test:** `tests/test_bounded_witness_stacks.py`.

```python
run_witness(manifest, diagnostic_only=True,
    diagnostic_read_grants=existing_four_leaf_grants,
    diagnostic_trace_path=None, diagnostic_stack_capture=True)
```

- [x] Add real synthetic timeout/thread, fast-Popen, grant-without-trace, diagnostic-only and output-bound controls.
- [x] Pass a dedicated stack write FD and parent deadline in the SHA-bound worker envelope. Preserve it using existing `retained_fds`.
- [x] After isolation, arm `faulthandler.dump_traceback_later(max(.01, deadline-time.monotonic()-3), repeat=False, file=stack_fd, exit=False)`.
- [x] Drain stack bytes separately while processing JSON and while finishing the worker. Keep at most 64,000 bytes, continue draining overflow and mark truncation. Do not mix stack bytes into the result protocol or add filesystem write grants.
- [x] Add CLI `--no-strace --dump-stacks`; record tracing disabled, stack bytes and source/argv/proof facts. Default proof behavior and fixture resource limits remain unchanged.

## Task 3: one paired diagnostic and stop

- [x] Prepare both manifests from explicit v5, the same neutral template, pinned checkouts/interpreters, and unchanged heavy profile (15/20s CPU, 2GiB AS,64FD,30s wall).
- [x] Preserve the same nonce, model/control paths and four leaf grants; no extra proc/sys reads or target-internal stubs.
- [x] Run full `uv run --no-sync pytest` and harness. Run the two targets once each with `--no-strace --dump-stacks`.
- [x] Report candidate frame/source SHA/line, argv and local Bash replay if captured; otherwise report stacks/last stage. Do not invent strong candidate status from unverified assumptions or a single literal observation.
- [x] Commit durable results and stop. No model calls, dependency/tool installation, further target reruns or automatic sandbox extensions.
