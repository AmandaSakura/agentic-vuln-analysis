"""Isolated fixture execution, loopback transport and subject-bound tool adapters."""

from __future__ import annotations

import ctypes
import errno
import json
import multiprocessing
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, cast

from ..agent_tools import ToolExecutionScope
from ..agent_types import ToolObservation, ValidationStatus
from ..fixture_isolation import restrict_fixture_filesystem
from ..harness import FULL_SYSTEM_HARNESS
from ..types import FrozenModel
from .models import CaseInput, FixtureCase, FixtureOutcome, LoopbackCase, LoopbackRequest, LoopbackResponse
from .scope import _json_content


_FIXTURE_RESULT_MAX_BYTES = 2_000_000


_FIXTURE_CLEANUP_SECONDS = 2.0


def _apply_fixture_limits() -> None:
    try:
        import resource
    except ImportError as error:
        raise RuntimeError("fixture resource limits are unavailable") from error

    limits = (
        ("cpu", resource.RLIMIT_CPU, (5, 5)),
        ("address_space", resource.RLIMIT_AS, (1_500_000_000, 1_500_000_000)),
        ("file_size", resource.RLIMIT_FSIZE, (1_000_000, 1_000_000)),
        ("open_files", resource.RLIMIT_NOFILE, (64, 64)),
    )
    failures: list[str] = []
    for name, limit, values in limits:
        try:
            resource.setrlimit(limit, values)
        except (OSError, ValueError) as error:
            failures.append(f"{name}: {type(error).__name__}: {error}")
    if failures:
        raise RuntimeError(
            "could not apply fixture resource limits: " + "; ".join(failures)
        )


def _write_fixture_message(result_fd: int, message: Mapping[str, Any]) -> None:
    encoded = json.dumps(
        message,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    view = memoryview(encoded)
    while view:
        written = os.write(result_fd, view[:65_536])
        view = view[written:]


def _fixture_worker(
    runner: Callable[[], FixtureOutcome],
    result_fd: int,
    read_roots: tuple[Path, ...],
    retained_fds: tuple[int, ...],
    accept_only: bool,
    isolated: bool,
    resource_limited: bool,
) -> None:
    try:
        if resource_limited:
            _apply_fixture_limits()
        if isolated:
            _install_fixture_isolation(result_fd, retained_fds=retained_fds, accept_only=accept_only)
            restrict_fixture_filesystem(read_roots)
        outcome = runner()
        _write_fixture_message(
            result_fd,
            {"kind": "ok", "payload": outcome.model_dump(mode="json")},
        )
    except BaseException as error:
        try:
            _write_fixture_message(
                result_fd,
                {"kind": "error", "payload": f"{type(error).__name__}: {error}"},
            )
        except OSError:
            pass
    finally:
        try:
            os.close(result_fd)
        except OSError:
            pass


def _install_fixture_isolation(
    result_fd: int, *, retained_fds: tuple[int, ...] = (), accept_only: bool = False,
) -> None:
    """Close inherited descriptors and deny socket syscalls before fixture code runs."""

    devnull_fd = os.open(os.devnull, os.O_RDWR)
    try:
        for fd in (0, 1, 2):
            if fd != result_fd:
                os.dup2(devnull_fd, fd)
    finally:
        if devnull_fd > 2 and devnull_fd != result_fd:
            os.close(devnull_fd)

    for raw_fd in os.listdir("/proc/self/fd"):
        fd = int(raw_fd)
        if fd > 2 and fd != result_fd and fd not in retained_fds:
            try:
                os.close(fd)
            except OSError:
                pass

    seccomp = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    seccomp.seccomp_rule_add.restype = ctypes.c_int
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_load.restype = ctypes.c_int
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.restype = None

    allow = 0x7FFF0000
    deny = 0x00050000 | errno.EPERM
    context = seccomp.seccomp_init(allow)
    if not context:
        raise RuntimeError("could not initialize fixture seccomp isolation")
    try:
        for name in (
            b"socket",
            b"socketpair",
            b"connect",
            b"bind",
            b"listen",
            b"accept",
            b"accept4",
            b"sendto",
            b"sendmsg",
            b"recvfrom",
            b"recvmsg",
        ):
            if accept_only and name in {
                b"accept", b"accept4", b"sendto", b"sendmsg", b"recvfrom", b"recvmsg",
            }:
                # Only the pre-bound loopback listener and result pipe survive.
                # New sockets and outgoing connections are still denied.
                continue
            syscall = seccomp.seccomp_syscall_resolve_name(name)
            if syscall < 0:
                continue
            result = seccomp.seccomp_rule_add(context, deny, syscall, 0)
            if result != 0:
                raise RuntimeError(
                    f"could not add fixture seccomp rule for {name.decode()}"
                )
        if seccomp.seccomp_load(context) != 0:
            raise RuntimeError("could not load fixture seccomp isolation")
    finally:
        seccomp.seccomp_release(context)


def _wait_for_fixture_exit(
    process: multiprocessing.Process,
    timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while process.is_alive():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.02, remaining))
    process.join(0)
    return True


def _terminate_fixture_process(process: multiprocessing.Process) -> None:
    if not process.is_alive():
        process.join(0)
        return
    process.terminate()
    if _wait_for_fixture_exit(process, _FIXTURE_CLEANUP_SECONDS):
        return
    process.kill()
    _wait_for_fixture_exit(process, _FIXTURE_CLEANUP_SECONDS)


def _run_fixture_case(
    case: FixtureCase, timeout_seconds: float, *,
    retained_fds: tuple[int, ...] = (), accept_only: bool = False,
    parent_action: Callable[[], None] | None = None,
) -> FixtureOutcome:
    deadline = time.monotonic() + timeout_seconds
    context = multiprocessing.get_context("fork")
    read_fd, write_fd = os.pipe()
    process = context.Process(
        target=_fixture_worker,
        args=(
            case.runner,
            write_fd,
            case.read_roots,
            retained_fds,
            accept_only,
            case.isolated,
            case.resource_limited,
        ),
    )
    process.start()
    os.close(write_fd)
    os.set_blocking(read_fd, False)

    chunks: list[bytes] = []
    total = 0
    read_error: str | None = None
    saw_eof = False

    def drain_result() -> None:
        nonlocal read_error, saw_eof, total
        while True:
            try:
                chunk = os.read(read_fd, 65_536)
            except BlockingIOError:
                break
            except OSError as error:
                read_error = f"{type(error).__name__}: {error}"
                break
            if not chunk:
                saw_eof = True
                break
            total += len(chunk)
            if total <= _FIXTURE_RESULT_MAX_BYTES:
                chunks.append(chunk)
            elif read_error is None:
                read_error = "fixture result exceeded its Harness byte limit"

    timed_out = False
    try:
        if parent_action is not None:
            try:
                parent_action()
            except Exception as error:
                _terminate_fixture_process(process)
                return FixtureOutcome(
                    status=ValidationStatus.UNRESOLVED,
                    summary="loopback request driver failed",
                    details={"error": f"{type(error).__name__}: {error}"},
                )
        while process.is_alive():
            drain_result()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            time.sleep(min(0.02, remaining))
        drain_result()
    finally:
        try:
            os.close(read_fd)
        except OSError:
            pass

    if timed_out:
        _terminate_fixture_process(process)
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="fixture exceeded its Harness timeout",
        )
    process.join(0)
    if read_error is not None:
        _terminate_fixture_process(process)
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="fixture result channel failed",
            details={"error": read_error},
        )
    raw_message = b"".join(chunks)
    if not raw_message or not saw_eof:
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary=f"fixture exited without a result (exit={process.exitcode})",
        )
    try:
        message = json.loads(raw_message.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="fixture returned an invalid result envelope",
            details={"error": f"{type(error).__name__}: {error}"},
        )
    kind = message.get("kind")
    payload = message.get("payload")
    if kind == "error":
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="fixture raised an exception",
            details={"error": payload},
        )
    if kind != "ok":
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="fixture returned an unknown result envelope",
            details={"kind": kind},
        )
    return FixtureOutcome.model_validate(payload)


def _loopback_status(
    base_url: str,
    case: LoopbackCase,
    headers: tuple[tuple[str, str], ...],
    timeout_seconds: int,
) -> int:
    request = urllib.request.Request(
        f"{base_url}{case.path}",
        data=case.body if case.body else None,
        headers=dict(headers),
        method=case.method,
    )
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            response.read(4_096)
            return response.status
    except urllib.error.HTTPError as error:
        error.read(4_096)
        return error.code


def _run_loopback_case(case: LoopbackCase, timeout_seconds: int) -> FixtureOutcome:
    application = case.application

    class Handler(BaseHTTPRequestHandler):
        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            request = LoopbackRequest(
                method=self.command,
                path=self.path,
                headers=dict(self.headers.items()),
                body=self.rfile.read(length) if length else b"",
            )
            try:
                response = application(request)
            except Exception:
                response = LoopbackResponse(status=500, body=b"application error")
            self.send_response(response.status)
            for name, value in response.headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(response.body)

        do_GET = _dispatch
        do_POST = _dispatch
        do_PUT = _dispatch
        do_PATCH = _dispatch
        do_DELETE = _dispatch

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    # Bind in trusted code before restricting the child. The child can accept
    # these local requests but cannot create sockets or connect elsewhere.
    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = timeout_seconds
    base_url = f"http://127.0.0.1:{server.server_port}"
    statuses: list[int] = []
    deadline = time.monotonic() + timeout_seconds

    def serve() -> FixtureOutcome:
        for _ in range(2):
            server.handle_request()
        return FixtureOutcome(status=ValidationStatus.UNRESOLVED, summary="loopback requests served")

    def drive() -> None:
        for headers in (case.unauthorized_headers, case.authorized_headers):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("loopback case exceeded its deadline")
            statuses.append(_loopback_status(base_url, case, headers, remaining))

    try:
        outcome = _run_fixture_case(
            FixtureCase(case.case_id, serve, read_roots=case.read_roots),
            timeout_seconds, retained_fds=(server.fileno(),),
            accept_only=True, parent_action=drive,
        )
    finally:
        server.server_close()
    if len(statuses) != 2 or outcome.summary != "loopback requests served":
        return outcome
    unauthorized, authorized = statuses

    details = {
        "authorized_status": authorized,
        "bind_host": "127.0.0.1",
        "unauthorized_status": unauthorized,
    }
    if 200 <= unauthorized < 300 and 200 <= authorized < 300:
        return FixtureOutcome(
            status=ValidationStatus.CONFIRMED,
            summary="unauthorized and authorized requests both reached the protected action",
            details=details,
        )
    if unauthorized in {401, 403} and 200 <= authorized < 300:
        return FixtureOutcome(
            status=ValidationStatus.REFUTED,
            summary="the loopback case denied the unauthorized request",
            details=details,
        )
    return FixtureOutcome(
        status=ValidationStatus.UNRESOLVED,
        summary="loopback statuses did not establish or refute authorization",
        details=details,
    )


def fixture(
    fixtures: Mapping[str, FixtureCase],
    arguments: FrozenModel,
    scope: ToolExecutionScope,
) -> ToolObservation:
    value = cast(CaseInput, arguments)
    case = fixtures.get(value.case_id)
    if case is None:
        return ToolObservation(
            tool="run_fixture_test",
            status="error",
            content=f"fixture case is not registered: {value.case_id}",
        )
    if scope.candidate_path is not None and (scope.subject is None or case.subject != scope.subject):
        return ToolObservation(tool="run_fixture_test", status="blocked",
                               content="fixture subject does not match this candidate/source")
    outcome = _run_fixture_case(
        case,
        min(
            FULL_SYSTEM_HARNESS.validation.timeout_seconds,
            case.timeout_seconds
            if case.timeout_seconds is not None
            else FULL_SYSTEM_HARNESS.validation.timeout_seconds,
        ),
    )
    return ToolObservation(
        tool="run_fixture_test",
        status="ok",
        validation_status=outcome.status,
        content=_json_content(outcome.model_dump(mode="json")),
        evidence_ids=(f"fixture:{value.case_id}",),
        subject=case.subject,
    )


def loopback(
    loopbacks: Mapping[str, LoopbackCase],
    arguments: FrozenModel,
    scope: ToolExecutionScope,
) -> ToolObservation:
    value = cast(CaseInput, arguments)
    case = loopbacks.get(value.case_id)
    if case is None:
        return ToolObservation(
            tool="run_loopback_http_case",
            status="error",
            content=f"loopback case is not registered: {value.case_id}",
        )
    if scope.candidate_path is not None and (scope.subject is None or case.subject != scope.subject):
        return ToolObservation(tool="run_loopback_http_case", status="blocked",
                               content="loopback subject does not match this candidate/source")
    outcome = _run_loopback_case(
        case,
        FULL_SYSTEM_HARNESS.validation.timeout_seconds,
    )
    return ToolObservation(
        tool="run_loopback_http_case",
        status="ok",
        validation_status=outcome.status,
        content=_json_content(outcome.model_dump(mode="json")),
        evidence_ids=(f"loopback:{value.case_id}",),
        subject=case.subject,
    )
