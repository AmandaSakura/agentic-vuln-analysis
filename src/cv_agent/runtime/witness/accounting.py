"""Own-process CPU and external procfs samples for diagnostic accounting.

These host reads do not grant the restricted target access to procfs. Final CPU
ticks can be read from an unreaped zombie; descriptor peaks are only observed
lower bounds because descriptors may open and close between samples.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import resource
import time
from typing import Any


_PROC_ROOT = Path("/proc")
_MEMORY_FIELD = re.compile(r"^(VmPeak|VmSize|VmHWM|VmRSS):\s+(\d+)\s+kB\s*$")


def self_usage() -> dict[str, int | float]:
    """Return this process's lifetime CPU/RSS, excluding waited-for children."""
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "pid": os.getpid(),
        "user_cpu_seconds": usage.ru_utime,
        "system_cpu_seconds": usage.ru_stime,
        "max_rss_kib": usage.ru_maxrss,
    }


def _stat(path: Path, pid: int) -> tuple[str, int, int, int] | None:
    try:
        text = path.read_text()
        opening = text.find(" (")
        closing = text.rfind(") ")
        if opening < 0 or closing <= opening or int(text[:opening]) != pid:
            return None
        fields = text[closing + 2:].split()
        state = fields[0]
        user, system, start = (int(fields[index]) for index in (11, 12, 19))
        if len(state) != 1 or min(user, system, start) < 0:
            return None
        return state, user, system, start
    except (OSError, ValueError, IndexError):
        return None


def _memory(path: Path) -> dict[str, int]:
    try:
        text = path.read_text()
    except OSError:
        return {}
    fields: dict[str, int] = {}
    for line in text.splitlines():
        match = _MEMORY_FIELD.fullmatch(line)
        if match is not None:
            fields[match[1]] = int(match[2])
    return fields


def _fd_count(path: Path) -> int:
    return sum(1 for entry in path.iterdir() if entry.name.isdecimal())


class ProcessResourceSampler:
    """Sample one PID, rejecting later observations with a different starttime.

    ``finish_unreaped`` must be called after the parent observes exit without
    reaping. A live process or an absent stat file cannot supply final CPU.
    """

    def __init__(self, pid: int) -> None:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("resource accounting requires a positive PID")
        self.pid = pid
        self._clock_ticks = int(os.sysconf("SC_CLK_TCK"))
        self._starttime: int | None = None
        self._user_ticks: int | None = None
        self._system_ticks: int | None = None
        self._max_rss: int | None = None
        self._max_virtual_memory: int | None = None
        self._rss: int | None = None
        self._virtual_memory: int | None = None
        self._open_fds: int | None = None
        self._fd_peak: int | None = None
        self._samples = 0
        self._first_sample: float | None = None
        self._last_sample: float | None = None
        self._sample_interval: float | None = None
        self._max_sample_interval: float | None = None
        self._identity_mismatch = False
        self._cpu_complete = False
        self._measurement_gaps: list[dict[str, Any]] = []

    def _observe(self, *, final: bool) -> None:
        if self._identity_mismatch or self._cpu_complete:
            return
        directory = _PROC_ROOT / str(self.pid)
        stat = _stat(directory / "stat", self.pid)
        if stat is None:
            return
        state, user, system, start = stat
        if self._starttime is not None and start != self._starttime:
            self._identity_mismatch = True
            return
        memory = _memory(directory / "status")
        descriptor_gap: dict[str, Any] | None = None
        try:
            descriptors = _fd_count(directory / "fd")
        except OSError as error:
            descriptors = None
            descriptor_gap = {
                "field": "open_fd_count", "path": str(directory / "fd"),
                "error": type(error).__name__, "errno": error.errno,
            }
        # A PID can disappear/reappear while status or the FD directory is read.
        checked = _stat(directory / "stat", self.pid)
        if checked is None:
            return
        if checked[3] != start:
            self._identity_mismatch = True
            return
        state, user, system, start = checked
        now = time.monotonic()
        self._starttime = start
        self._user_ticks, self._system_ticks = user, system
        if descriptor_gap is not None and descriptor_gap not in self._measurement_gaps:
            self._measurement_gaps.append(descriptor_gap)
        self._samples += 1
        if self._last_sample is not None:
            self._sample_interval = now - self._last_sample
            self._max_sample_interval = max(self._max_sample_interval or 0,
                                            self._sample_interval)
        if self._first_sample is None:
            self._first_sample = now
        self._last_sample = now
        if "VmHWM" in memory:
            self._max_rss = max(self._max_rss or 0, memory["VmHWM"])
        if "VmPeak" in memory:
            self._max_virtual_memory = max(self._max_virtual_memory or 0, memory["VmPeak"])
        if "VmRSS" in memory:
            self._rss = memory["VmRSS"]
        if "VmSize" in memory:
            self._virtual_memory = memory["VmSize"]
        if descriptors is not None:
            self._open_fds = descriptors
            self._fd_peak = max(self._fd_peak or 0, descriptors)
        self._cpu_complete = final and state in {"Z", "X", "x"}

    def sample(self) -> None:
        """Observe available own-process counters; missing data stays missing."""
        self._observe(final=False)

    def finish_unreaped(self) -> dict[str, Any]:
        """Collect final CPU ticks while the exited process still has procfs data."""
        self._observe(final=True)
        return self.summary()

    def summary(self) -> dict[str, Any]:
        """Return observed measurements and their explicit completeness limits."""
        return {
            "pid": self.pid,
            "pid_starttime_ticks": self._starttime,
            "pid_identity_mismatch": self._identity_mismatch,
            "measurement_gaps": [dict(gap) for gap in self._measurement_gaps],
            "user_cpu_seconds": (self._user_ticks / self._clock_ticks
                                 if self._user_ticks is not None else None),
            "system_cpu_seconds": (self._system_ticks / self._clock_ticks
                                   if self._system_ticks is not None else None),
            "total_cpu_seconds": ((self._user_ticks + self._system_ticks) / self._clock_ticks
                                  if self._user_ticks is not None and
                                  self._system_ticks is not None else None),
            "cpu_resolution_seconds": 1 / self._clock_ticks,
            "cpu_accounting_complete": self._cpu_complete,
            "accounting_complete": self._cpu_complete,
            "accounting_scope": "own_process_cpu_only",
            "max_rss_kib": self._max_rss,
            "max_virtual_memory_kib": self._max_virtual_memory,
            "last_rss_kib": self._rss,
            "last_virtual_memory_kib": self._virtual_memory,
            "memory_peaks_observed_only": True,
            "open_fd_count": self._open_fds,
            "fd_observed_peak": self._fd_peak,
            "fd_peak_is_lower_bound": True,
            "sample_count": self._samples,
            "sample_interval_seconds": self._sample_interval,
            "maximum_sample_interval_seconds": self._max_sample_interval,
            "sampling_elapsed_seconds": (self._last_sample - self._first_sample
                                         if self._last_sample is not None and
                                         self._first_sample is not None else None),
        }
