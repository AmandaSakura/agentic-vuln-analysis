"""Measure the real preexec callable in a child inheriting worker isolation.

This module does not provide isolation: the caller has already installed seccomp
and Landlock. The outer command hook must yield during this tagged measurement.
Native calls through ctypes remain outside Python audit/profile coverage; missing
normal-return delivery always fails verification.
"""

from __future__ import annotations

import json
import math
import os
import select
import signal
import sys
import time
import types
from typing import Any, Callable


_PROCESS_EVENTS = frozenset({
    'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn', 'os.spawn',
    'os.fork', 'os.forkpty', 'pty.spawn', 'os.posix_spawnp',
    '_thread.start_new_thread', '_thread.start_joinable_thread',
})
_MAX_BYTES = 48_000
_MAX_EVENTS = 256
_EXIT = os._exit
_SYS_EXIT = sys.exit


class _ForbiddenProcessAction(BaseException):
    pass


def _argument(value: Any) -> Any:
    if type(value) in (str, int, bool, float, type(None)):
        if type(value) is float and not math.isfinite(value):
            return {'type': 'nonfinite_float'}
        return value[:400] if type(value) is str else value
    if type(value) is bytes:
        return value[:200].decode('utf-8', errors='replace')
    return {'type': type(value).__name__}


def verify_preexec(fn: Callable[[], Any] | None, *, timeout_seconds: float = 2.0,
                   verify_sources: Callable[[], list[str]] | None = None) -> dict[str, Any]:
    if fn is None:
        return {'ok': True, 'kind': 'none', 'normal_return': True,
                'trusted_verifier_fork': False, 'events': [], 'forbidden_events': []}
    if not callable(fn):
        return {'ok': False, 'gap': 'preexec_not_callable', 'events': [],
                'forbidden_events': [], 'normal_return': False,
                'trusted_verifier_fork': False}
    if not 0 < timeout_seconds <= 5:
        raise ValueError('preexec timeout must be in (0, 5] seconds')
    read_fd, write_fd = os.pipe()
    started = time.monotonic()
    try:
        pid = os.fork()
    except OSError as error:
        os.close(read_fd)
        os.close(write_fd)
        return {'ok': False, 'gap': 'preexec_fork_failed', 'errno': error.errno,
                'events': [], 'forbidden_events': [], 'normal_return': False,
                'trusted_verifier_fork': False}
    if pid == 0:
        os.close(read_fd)
        running = False
        count = 0
        forbidden: list[str] = []
        hook_selftest = False
        profile_selftest = False
        checking_profile = False

        def send(payload: dict[str, Any]) -> None:
            data = json.dumps(payload, separators=(',', ':'), allow_nan=False).encode() + b'\n'
            view = memoryview(data)
            while view:
                view = view[os.write(write_fd, view):]

        def event(name: str, args: tuple[Any, ...] = (), *, denied: bool = False) -> None:
            nonlocal count
            count += 1
            if denied:
                forbidden.append(name)
            if count <= _MAX_EVENTS:
                send({'kind': 'event', 'event': name,
                      'arguments': [_argument(arg) for arg in args[:4]], 'forbidden': denied})
            if count > _MAX_EVENTS:
                raise _ForbiddenProcessAction('preexec_event_limit')
            if denied:
                raise _ForbiddenProcessAction(name)

        def audit(name: str, args: tuple[Any, ...]) -> None:
            nonlocal hook_selftest
            if not running:
                return
            if name == 'cv_agent.preexec.hook_selftest':
                hook_selftest = True
            event(name, args, denied=name in _PROCESS_EVENTS or name in {
                'sys.setprofile', 'sys.settrace', 'sys._getframe', 'sys._current_frames',
            } or (name == 'object.__getattr__' and len(args) > 1
                  and type(args[1]) is str and args[1] in {'tb_frame', 'gi_frame', 'cr_frame', 'ag_frame'}))

        def profile(frame: Any, name: str, arg: Any) -> None:
            nonlocal profile_selftest
            if running and name == 'c_call':
                if checking_profile and arg is id:
                    profile_selftest = True
                wrapped = (arg.__self__ if type(arg) is types.MethodWrapperType
                           and arg.__name__ == '__call__' else None)
                if arg is _EXIT or wrapped is _EXIT:
                    event('os._exit', denied=True)
                elif arg is _SYS_EXIT or wrapped is _SYS_EXIT:
                    event('sys.exit', denied=True)

        def trace(frame: Any, name: str, arg: Any) -> Any:
            # C dispatch helpers (e.g. functools.partial/map) need not generate
            # a c_call for the wrapped sys.exit. Its SystemExit still crosses
            # a traced Python frame even if target code catches it afterward.
            if running and name == 'exception' and issubclass(arg[0], SystemExit):
                event('sys.exit', denied=True)
            return trace

        normal_return = False
        error = None
        try:
            sys.addaudithook(audit)
            # Register before calling target code; no target callable is replaced.
            sys.setprofile(profile)
            sys.settrace(trace)
            running = True
            sys.audit('cv_agent.preexec.hook_selftest')
            checking_profile = True
            id(None)
            checking_profile = False
            if not hook_selftest or not profile_selftest:
                raise RuntimeError('preexec observer selftest failed')
            fn()
            normal_return = True
        except BaseException as exc:
            error = type(exc).__name__
        finally:
            running = False
            sys.setprofile(None)
            sys.settrace(None)
        source_gaps: list[str] = []
        source_check_performed = False
        if verify_sources is not None:
            try:
                source_gaps = verify_sources()
                source_check_performed = True
            except BaseException as exc:
                source_gaps = ['preexec_source_check_error:' + type(exc).__name__]
        try:
            send({'kind': 'complete', 'normal_return': normal_return, 'exception': error,
                  'forbidden_events': forbidden[:_MAX_EVENTS], 'event_count': count,
                  'hook_selftest': hook_selftest, 'profile_selftest': profile_selftest,
                  'source_check_performed': source_check_performed, 'source_gaps': source_gaps,
                  'events_truncated': count > _MAX_EVENTS})
        finally:
            _EXIT(0)
    os.close(write_fd)
    os.set_blocking(read_fd, False)
    data = bytearray()
    status: int | None = None
    gap: str | None = None
    eof = False
    try:
        deadline = started + timeout_seconds
        while status is None or not eof:
            if time.monotonic() >= deadline:
                gap = 'preexec_timeout'
                break
            if not eof:
                ready, _, _ = select.select([read_fd], [], [], min(.01, deadline - time.monotonic()))
                if ready:
                    chunk = os.read(read_fd, 16_384)
                    if not chunk:
                        eof = True
                    else:
                        data.extend(chunk)
                        if len(data) > _MAX_BYTES:
                            gap = 'preexec_result_too_large'
                            break
            else:
                time.sleep(.001)
            if status is None:
                waited, raw_status = os.waitpid(pid, os.WNOHANG)
                if waited:
                    status = raw_status
    finally:
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, status = os.waitpid(pid, 0)
        os.close(read_fd)
    records: list[dict[str, Any]] = []
    try:
        records = [json.loads(line) for line in bytes(data).splitlines()]
        if any(type(record) is not dict for record in records):
            raise ValueError('non-object message')
    except (ValueError, UnicodeDecodeError):
        gap = gap or 'preexec_invalid_result'
        records = []
    events = [record for record in records if record.get('kind') == 'event']
    forbidden_events = [record['event'] for record in events if record.get('forbidden')]
    completions = [record for record in records if record.get('kind') == 'complete']
    complete = completions[0] if len(completions) == 1 and records and records[-1] is completions[0] else {}
    exit_code = os.waitstatus_to_exitcode(status)
    if not gap:
        if exit_code != 0:
            gap = 'preexec_nonzero_exit'
        elif not complete:
            gap = 'preexec_missing_normal_return'
        elif not complete.get('hook_selftest') or not complete.get('profile_selftest'):
            gap = 'preexec_selftest_failed'
        elif forbidden_events or complete.get('forbidden_events'):
            gap = 'preexec_process_action_attempted'
        elif complete.get('events_truncated'):
            gap = 'preexec_event_limit'
        elif complete.get('event_count') != len(events):
            gap = 'preexec_incomplete_event_delivery'
        elif verify_sources is not None and (
                complete.get('source_check_performed') is not True or complete.get('source_gaps')):
            gap = 'preexec_source_unbound'
        elif complete.get('normal_return') is not True or complete.get('exception') is not None:
            gap = 'preexec_exception'
    return {'ok': gap is None, 'kind': 'executed_child', 'gap': gap,
            'child_pid': pid, 'parent_pid': os.getpid(), 'exit_code': exit_code,
            'normal_return': complete.get('normal_return') is True,
            'exception': complete.get('exception'), 'events': events,
            'hook_selftest': complete.get('hook_selftest'),
            'profile_selftest': complete.get('profile_selftest'),
            'source_check_performed': complete.get('source_check_performed'),
            'source_gaps': complete.get('source_gaps', []),
            'event_count': complete.get('event_count'), 'forbidden_events': forbidden_events,
            'trusted_verifier_fork': True, 'timeout_seconds': timeout_seconds,
            'elapsed_seconds': time.monotonic() - started,
            'native_call_coverage': 'Python audit/profile; raw native process calls are not observed'}
