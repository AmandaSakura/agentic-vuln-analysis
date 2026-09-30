"""Behavioral controls found by independent preexec verifier review."""

from __future__ import annotations

import functools
import os
import sys
import threading

import pytest

from test_witness_preexec import _run


def _wrapped_exit():
    try:
        sys.exit.__call__(0)
    except BaseException:
        pass


def _partial_exit():
    try:
        functools.partial(sys.exit, 0)()
    except BaseException:
        pass


def _mapped_exit():
    try:
        list(map(sys.exit, [0]))
    except BaseException:
        pass


def _wrapped_os_exit():
    os._exit.__call__(0)


@pytest.mark.parametrize("fn", [_wrapped_exit, _partial_exit, _mapped_exit])
def test_wrapped_sys_exit_attempt_is_not_verified_if_exception_is_caught(fn):
    result = _run(fn)
    assert result["ok"] is False, result
    assert result["gap"] == "preexec_process_action_attempted", result
    assert "sys.exit" in result["forbidden_events"], result


def test_builtin_os_exit_wrapper_cannot_fake_normal_return():
    result = _run(_wrapped_os_exit)
    assert result["ok"] is False, result
    # CPython may omit this C dispatch from profile events. Actual exit(0)
    # still cannot deliver the verifier's required normal-return completion.
    assert result["gap"] == "preexec_missing_normal_return", result
    assert result["normal_return"] is False, result


def _exit_in_new_thread():
    def action():
        try:
            sys.exit(0)
        except BaseException:
            pass

    thread = threading.Thread(target=action)
    thread.start()
    thread.join()


def test_new_thread_cannot_hide_a_caught_exit_attempt():
    result = _run(_exit_in_new_thread)
    assert result["ok"] is False, result
    assert any(name in result["forbidden_events"] for name in (
        "sys.exit", "_thread.start_new_thread", "_thread.start_joinable_thread",
    )), result


def _disable_current_frame_then_exit():
    frame = sys._getframe()
    frame.f_trace = None
    try:
        functools.partial(sys.exit, 0)()
    except BaseException:
        pass


def _disable_trace_through_exception_then_exit():
    try:
        raise ValueError("obtain own traceback frame")
    except ValueError as error:
        frame = error.__traceback__.tb_frame
    frame.f_trace = None
    try:
        functools.partial(sys.exit, 0)()
    except BaseException:
        pass


@pytest.mark.parametrize("fn", [_disable_current_frame_then_exit, _disable_trace_through_exception_then_exit])
def test_frame_trace_disabling_cannot_hide_a_caught_exit_attempt(fn):
    result = _run(fn)
    assert result["ok"] is False, result
    assert result["forbidden_events"], result


def _exit_only_without_an_active_exception():
    if sys.exception() is None:
        os._exit(0)


def _exit_only_with_an_active_exception():
    if sys.exception() is not None:
        os._exit(0)


@pytest.mark.parametrize("fn, expected_ok", [
    (_exit_only_without_an_active_exception, False),
    (_exit_only_with_an_active_exception, True),
])
def test_direct_preexec_measurement_has_no_observer_exception(fn, expected_ok):
    result = _run(fn)
    assert result["ok"] is expected_ok, result
    if not expected_ok:
        assert "os._exit" in result["forbidden_events"], result


@pytest.mark.parametrize("condition, should_confirm", [("is None", False), ("is not None", True)])
def test_bounded_preexec_measurement_does_not_inherit_capture_exception(tmp_path, condition, should_confirm):
    from cv_agent.domain.evidence import ValidationStatus
    from cv_agent.runtime.witness.kernel import run_witness
    from test_bounded_execution_witness import NONCE, _manifest

    manifest = _manifest(tmp_path, f'''
        import os
        import sys
        import subprocess
        def preexec():
            if sys.exception() {condition}:
                os._exit(0)
        class Service:
            def serve(self, model_uri):
                subprocess.Popen(["bash", "-c", f"record {{model_uri}}"], preexec_fn=preexec)
    ''')
    result = run_witness(manifest, nonce=NONCE, verify_obligations=True)
    expected = ValidationStatus.CONFIRMED if should_confirm else ValidationStatus.UNRESOLVED
    assert result.status == expected, result.model_dump()
    for name in ("probe_event", "control_event"):
        assert result.details[name]["preexec_verification"]["ok"] is should_confirm, result.model_dump()
        if not should_confirm:
            assert "os._exit" in result.details[name]["preexec_verification"]["forbidden_events"]
