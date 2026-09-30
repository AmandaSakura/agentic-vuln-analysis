"""Separate process accounting without admitting procfs to the target."""

from __future__ import annotations

import os
import errno
from pathlib import Path
import resource
import subprocess
import sys
import textwrap
import time

import pytest

from cv_agent.runtime.witness import accounting


def _fake_process(root: Path, *, pid: int = 123, start: int = 42,
                  user: int = 20, system: int = 10, state: str = "S") -> Path:
    directory = root / str(pid)
    directory.mkdir(exist_ok=True)
    fields = ["0"] * 32
    fields[0] = state
    fields[11] = str(user)
    fields[12] = str(system)
    fields[19] = str(start)
    (directory / "stat").write_text(f"{pid} (a name with ) and () parens) " + " ".join(fields))
    (directory / "status").write_text("Name:\ttest\nVmPeak:\t4096 kB\nVmHWM:\t2048 kB\n")
    descriptor_directory = directory / "fd"
    descriptor_directory.mkdir(exist_ok=True)
    for index in range(3):
        (descriptor_directory / str(index)).touch()
    return directory


def test_self_usage_does_not_charge_reaped_child_cpu() -> None:
    before = accounting.self_usage()
    child_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    subprocess.run([
        sys.executable, "-c",
        "import time\nend=time.process_time()+0.2\nwhile time.process_time()<end: pass",
    ], check=True, timeout=4)
    after = accounting.self_usage()
    child_after = resource.getrusage(resource.RUSAGE_CHILDREN)

    assert after["pid"] == os.getpid()
    assert after["max_rss_kib"] > 0
    assert child_after.ru_utime + child_after.ru_stime - (
        child_before.ru_utime + child_before.ru_stime
    ) >= 0.15
    assert after["user_cpu_seconds"] + after["system_cpu_seconds"] - (
        before["user_cpu_seconds"] + before["system_cpu_seconds"]
    ) < 0.15


def test_external_sample_observes_cpu_and_open_fds_without_reaping() -> None:
    source = textwrap.dedent("""
        import os, sys, time
        descriptors = [os.open('/dev/null', os.O_RDONLY) for _ in range(20)]
        end = time.process_time() + 0.2
        while time.process_time() < end:
            pass
        print('ready', flush=True)
        sys.stdin.readline()
    """)
    process = subprocess.Popen([sys.executable, "-c", source], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert process.stdout is not None and process.stdout.readline() == "ready\n"
        sampler = accounting.ProcessResourceSampler(process.pid)
        sampler.sample()
        result = sampler.summary()
        assert result["pid_starttime_ticks"] > 0
        assert result["total_cpu_seconds"] >= 0.15
        assert result["open_fd_count"] >= 23
        assert result["fd_observed_peak"] >= 23
        assert result["fd_peak_is_lower_bound"] is True
        assert result["max_rss_kib"] > 0
        assert result["max_virtual_memory_kib"] >= result["max_rss_kib"]
        assert result["accounting_complete"] is False
        process.communicate("done\n", timeout=3)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def test_fast_exit_can_be_accounted_as_zombie_before_first_sample() -> None:
    process = subprocess.Popen([sys.executable, "-c", "sum(range(200000))"])
    sampler = accounting.ProcessResourceSampler(process.pid)
    try:
        deadline = time.monotonic() + 4
        while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            assert time.monotonic() < deadline
            time.sleep(0.005)
        result = sampler.finish_unreaped()
        assert result["cpu_accounting_complete"] is True
        assert result["accounting_complete"] is True
        # Fast exits can consume less than procfs's one-clock-tick resolution.
        assert result["total_cpu_seconds"] >= 0
        assert result["cpu_resolution_seconds"] == 1 / os.sysconf("SC_CLK_TCK")
        assert result["pid_starttime_ticks"] > 0
        assert result["fd_peak_is_lower_bound"] is True
        assert process.wait(timeout=2) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def test_sample_handles_parentheses_and_requires_exited_state_for_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(accounting, "_PROC_ROOT", tmp_path)
    directory = _fake_process(tmp_path)
    sampler = accounting.ProcessResourceSampler(123)
    sampler.sample()
    time.sleep(0.002)
    sampler.sample()
    alive = sampler.finish_unreaped()
    assert alive["cpu_accounting_complete"] is False
    assert alive["pid_starttime_ticks"] == 42
    assert alive["fd_observed_peak"] == 3
    assert alive["max_rss_kib"] == 2048
    assert alive["sample_interval_seconds"] > 0
    assert alive["total_cpu_seconds"] == 30 / os.sysconf("SC_CLK_TCK")

    _fake_process(tmp_path, state="Z", user=40, system=20)
    exited = sampler.finish_unreaped()
    assert exited["cpu_accounting_complete"] is True
    assert exited["total_cpu_seconds"] == 60 / os.sysconf("SC_CLK_TCK")
    assert directory.exists()


def test_reused_pid_cannot_replace_first_process_measurements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(accounting, "_PROC_ROOT", tmp_path)
    _fake_process(tmp_path)
    sampler = accounting.ProcessResourceSampler(123)
    sampler.sample()
    original = sampler.summary()
    _fake_process(tmp_path, start=99, user=900, system=900, state="Z")
    sampler.sample()
    result = sampler.finish_unreaped()

    assert result["pid_identity_mismatch"] is True
    assert result["pid_starttime_ticks"] == original["pid_starttime_ticks"]
    assert result["total_cpu_seconds"] == original["total_cpu_seconds"]
    assert result["cpu_accounting_complete"] is False


@pytest.mark.parametrize("stat_content", [None, "123 (missing closing parenthesis", "123 (x) S"])
def test_absent_or_malformed_proc_never_invents_measurements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stat_content: str | None,
) -> None:
    monkeypatch.setattr(accounting, "_PROC_ROOT", tmp_path)
    if stat_content is not None:
        directory = tmp_path / "123"
        directory.mkdir()
        (directory / "stat").write_text(stat_content)
    sampler = accounting.ProcessResourceSampler(123)
    sampler.sample()
    result = sampler.finish_unreaped()

    assert result["sample_count"] == 0
    assert result["user_cpu_seconds"] is None
    assert result["system_cpu_seconds"] is None
    assert result["max_rss_kib"] is None
    assert result["fd_observed_peak"] is None
    assert result["cpu_accounting_complete"] is False


def test_disappearance_retains_only_last_observed_lower_bounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(accounting, "_PROC_ROOT", tmp_path)
    directory = _fake_process(tmp_path)
    sampler = accounting.ProcessResourceSampler(123)
    sampler.sample()
    before = sampler.summary()
    (directory / "stat").unlink()
    result = sampler.finish_unreaped()

    assert result["total_cpu_seconds"] == before["total_cpu_seconds"]
    assert result["fd_observed_peak"] == before["fd_observed_peak"]
    assert result["cpu_accounting_complete"] is False


def test_partial_status_does_not_invent_memory_or_fd_measurements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(accounting, "_PROC_ROOT", tmp_path)
    directory = _fake_process(tmp_path)
    (directory / "status").write_text("VmPeak:\tnonsense\nVmHWM:\t-1 kB\n")
    for entry in (directory / "fd").iterdir():
        entry.unlink()
    (directory / "fd").rmdir()
    sampler = accounting.ProcessResourceSampler(123)
    sampler.sample()
    result = sampler.summary()

    assert result["total_cpu_seconds"] is not None
    assert result["max_rss_kib"] is None
    assert result["max_virtual_memory_kib"] is None
    assert result["open_fd_count"] is None
    assert result["fd_observed_peak"] is None


def test_fd_permission_error_preserves_cpu_memory_and_records_individual_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(accounting, "_PROC_ROOT", tmp_path)
    _fake_process(tmp_path)
    original_iterdir = Path.iterdir

    def denied_fds(path: Path):
        if path == tmp_path / "123" / "fd":
            raise PermissionError(errno.EACCES, "denied fd observation", str(path))
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", denied_fds)
    sampler = accounting.ProcessResourceSampler(123)
    sampler.sample()
    result = sampler.summary()

    assert result["total_cpu_seconds"] == 30 / os.sysconf("SC_CLK_TCK")
    assert result["max_rss_kib"] == 2048
    assert result["max_virtual_memory_kib"] == 4096
    assert result["open_fd_count"] is None
    assert result["measurement_gaps"] == [{
        "field": "open_fd_count", "path": str(tmp_path / "123" / "fd"),
        "error": "PermissionError", "errno": errno.EACCES,
    }]
