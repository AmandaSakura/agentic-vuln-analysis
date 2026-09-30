"""Real seccomp child execution must distinguish return from exit/exec attempts."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from cv_agent.domain.evidence import ValidationStatus
from cv_agent.runtime.witness.obligations.preexec import verify_preexec
from cv_agent.tools.validation.fixtures import _run_fixture_case
from cv_agent.tools.validation.models import FixtureCase, FixtureOutcome


def _run(fn, *, timeout=1.0):
    def runner():
        result = verify_preexec(fn, timeout_seconds=timeout)
        if result.get('child_pid'):
            try:
                os.waitpid(result['child_pid'], os.WNOHANG)
            except ChildProcessError:
                result['reaped_check'] = True
            else:
                result['reaped_check'] = False
        return FixtureOutcome(status=ValidationStatus.UNRESOLVED,
                              summary="preexec measurement", details=result)
    case = FixtureCase(case_id="synthetic-preexec", runner=runner,
                       read_roots=(Path('/usr/lib'), Path('/lib'), Path('/lib64')),
                       isolated=True)
    outcome = _run_fixture_case(case, 4.0)
    assert outcome.summary == "preexec measurement", outcome.model_dump()
    return outcome.details


def _normal():
    return None


def _caught_ordinary():
    try:
        raise OSError("ordinary target failure")
    except OSError:
        return None


def _raises():
    raise ValueError("target preexec failed")


def _exit():
    os._exit(0)


def _sys_exit():
    try:
        sys.exit(0)
    except BaseException:
        pass


def _exec():
    try:
        os.execv('/bin/true', ['/bin/true'])
    except BaseException:
        pass


def _subprocess():
    try:
        subprocess.run(['/bin/true'])
    except BaseException:
        pass


def _fork():
    try:
        os.fork()
    except BaseException:
        pass


def _disable_profile():
    try:
        sys.setprofile(None)
    except BaseException:
        pass


def _timeout():
    time.sleep(10)


def _ctypes_load():
    ctypes.CDLL('libc.so.6')


@pytest.mark.parametrize('fn', [_normal, _caught_ordinary])
def test_actual_normal_return_is_verified(fn):
    result = _run(fn)
    assert result['ok'] is True, result
    assert result['normal_return'] is True
    assert result['exit_code'] == 0
    assert result['trusted_verifier_fork'] is True
    assert result['forbidden_events'] == []
    assert result['hook_selftest'] and result['profile_selftest']
    assert result['reaped_check'] is True


def test_none_requires_no_child():
    result = verify_preexec(None)
    assert result['ok'] is True
    assert result['kind'] == 'none'
    assert result['trusted_verifier_fork'] is False


@pytest.mark.parametrize('fn', [_raises, _exit, _sys_exit, _exec, _subprocess, _fork, _disable_profile])
def test_process_actions_or_exceptions_cannot_verify_even_if_caught(fn):
    result = _run(fn)
    assert result['ok'] is False, result
    assert result['gap'].startswith('preexec_'), result
    if fn is not _raises:
        assert result['forbidden_events'], result


def test_timeout_is_bounded_and_child_reaped():
    result = _run(_timeout, timeout=.15)
    assert result['ok'] is False
    assert result['gap'] == 'preexec_timeout'
    assert result['reaped_check'] is True


def test_ctypes_loading_is_allowed_and_recorded():
    result = _run(_ctypes_load)
    assert result['ok'] is True, result
    assert any(event['event'] == 'ctypes.dlopen' for event in result['events'])
