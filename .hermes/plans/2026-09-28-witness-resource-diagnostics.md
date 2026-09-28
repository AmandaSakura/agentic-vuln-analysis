# Witness Resource Diagnostics Implementation Plan

> **For agentic workers:** Execute the bounded tasks below with the available collaboration tools. Keep the two-round stop and the user's approval requirements for dataset changes or dependency installation.

**Goal:** Identify the target's CPU-limit signal, measure import resources without tracing, and expose a named measurement-based heavy target configuration while preserving existing fixture defaults.

**Architecture:** Resource profiles live in `runtime/witness_resources.py`; process observation lives in `evaluation/diagnostics/process_resource_accounting.py`. The witness records actual target limits and self usage, while its parent samples target/tracer independently. Baseline imports use existing Python 3.12 venvs and GNU time in a network namespace, with no Landlock, fixture limits, strace or dependency installation.

**Tech Stack:** Existing UV environments, GNU time, Linux procfs, Python resource/signal/waitid, existing audit/Landlock/seccomp witness.

---

## Boundaries and stop

- Do not edit `fixtures.py` default `(5,5)` CPU / 1,500,000,000-byte AS / 64-FD limits.
- Do not admit the remaining six procfs/sysfs reads, change `_nworkers`, install isolation tools, or call models.
- Round 1: two outside-sandbox import baselines, then a paired `cpu_diagnostic` run with CPU soft 5 / hard 10 seconds. A kernel-origin target SIGXCPU supports `cpu_limit_exceeded`; aggregate tracer+target CPU does not.
- Round 2: one paired `heavy_target` diagnostic after explicit measured values are selected and recorded. Stop after this pair; if the designated serve entry is still not reached, recommend a mature isolation tool without installing it.
- Any package/tool installation requires a separate user confirmation. Dataset v4 remains unchanged.

## Task 1: import baselines

- [ ] Use `/usr/bin/unshare --user --map-current-user --net` to prevent networking while preserving the target UID.
- [ ] Launch `/usr/bin/time -v -o <new-time-log> <existing-py312-python> -X importtime -c 'import mlflow.pyfunc.backend'` with the corresponding checkout as PYTHONPATH and bytecode writes disabled.
- [ ] Sample the Python child externally every 10 ms: CPU ticks, VmPeak/VmHWM, and `/proc/<pid>/fd` count. FD peak is an observed lower bound; maxRSS alone cannot size RLIMIT_AS.
- [ ] Save exact argv, interpreter/checkout binding, time/import logs and hashes, sampled metrics, deadline and return status. Preserve historical outputs.

## Task 2: explicit resource profiles

**Create:** `src/cv_agent/runtime/witness_resources.py`, `tests/test_witness_resource_profiles.py`.

```python
WitnessResourceProfile.fixture_default()
# name='fixture_default', cpu_soft_seconds=5, cpu_hard_seconds=5,
# address_space_bytes=1_500_000_000, file_size_bytes=1_000_000,
# open_files=64, wall_seconds=12.0
WitnessResourceProfile(name='cpu_diagnostic', cpu_soft_seconds=5,
    cpu_hard_seconds=10, address_space_bytes=1_500_000_000,
    file_size_bytes=1_000_000, open_files=64, wall_seconds=20.0)
```

- [ ] Add failing tests for fixed legacy defaults and child-applied limits, invalid/unbounded profiles, and mocked nondefault apply/readback.
- [ ] Implement the immutable profile with finite positive fields; require soft<hard for nondefault names. Fixed default cannot be silently mutated. Heavy values must appear explicitly in serialized manifest data.
- [ ] Add `WitnessManifest.resource_profile` with default factory. Nondefault profiles are diagnostic-only. Bash replay retains fixture defaults.

## Task 3: attribution and separate accounting

**Create:** `src/cv_agent/evaluation/diagnostics/process_resource_accounting.py`, `tests/test_process_resource_accounting.py`.
**Modify:** `bounded_execution_witness.py`, `run_bounded_witness_diagnostic.py`.

```python
snapshot = self_usage()  # RUSAGE_SELF: target threads only
observer = ProcessResourceSampler(pid)
observer.sample()
# After waitid(P_PID, pid, WEXITED | WNOWAIT), before Popen.wait:
final_own_cpu = observer.finish_unreaped()
```

- [ ] Test synthetic CPU/FD workloads, absent/reused PID, ambiguous SIGKILL and parent timeout. Never relabel aggregate usage as target/tracer own CPU.
- [ ] For nondefault profiles, block SIGXCPU in the worker and use sigwaitinfo in a trusted monitor thread. Record si_code/si_pid/si_uid, self CPU, actual getrlimit values and phase; exit the whole worker after reporting. Kernel SI_KERNEL yields `cpu_limit_exceeded`; target-sent SIGXCPU has a separate gap.
- [ ] Emit worker PID/resources before limits/import and keep all failure paths' last progress. Record parent's kill reason separately.
- [ ] Sample the tracer independently; obtain its final own CPU while unreaped with waitid WNOWAIT. Lost target final measurement stays explicitly incomplete.

## Task 4: measure, select values and stop

- [ ] Derive explicit heavy CPU, AS, FD and wall limits from the larger of the two baselines plus bootstrap/tracing margin; include calculations and record actual installed limits.
- [ ] Keep the same nonce, concrete model/control paths, neutral call template and four-file read policy for paired CPU and heavy diagnostics.
- [ ] Run targeted controls, full `uv run --no-sync pytest`, and `uv run --no-sync cv-agent harness-check`. Commit code and durable summaries.
- [ ] Report CPU attribution, import measurements, chosen profile, last phase/first command, unresolved obligations, two-round stop and next required user decisions.
