from __future__ import annotations

import ctypes
import ast
import errno
import json
import multiprocessing
import os
import re
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, cast

from pydantic import Field

from .agent_tools import (
    AgentTool,
    ToolExecutionScope,
    repository_tools,
)
from .agent_types import ToolObservation, ValidationStatus
from .harness import FULL_SYSTEM_HARNESS
from .fixture_isolation import restrict_fixture_filesystem
from .function_parameters import ast_parameters
from .python_flow import CallBinding, function_node, parameter_names, python_document_flow
from .python_probe import probe_python_eval
from .retrieval import RepositoryIndex
from .types import CodeDocument, FrozenModel


@dataclass(frozen=True)
class PatternRule:
    category: str
    pattern: re.Pattern[str]


SOURCE_RULES = (
    PatternRule(
        "http-input",
        re.compile(
            r"\b(?:request|req)\.(?:args|query|body|params|headers|cookies)\b|"
            r"\brequest\.get(?:Header|Headers|Parameter|ParameterMap|ParameterValues|"
            r"Cookies?|QueryString)\s*\(|"
            r"\.getTheParameter\s*\(|"
            r"\br\.URL\.Query\s*\(|\bmux\.Vars\s*\(|\bctx\.Param\s*\(",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "process-input",
        re.compile(r"\b(?:input\s*\(|sys\.argv\b|os\.environ\b|process\.env\b)"),
    ),
)

SINK_RULES = (
    PatternRule("code-execution", re.compile(r"(?<![\w.])(?:eval|exec)\s*\(")),
    PatternRule(
        "command-execution",
        re.compile(
            r"\b(?:os\.system|subprocess\.(?:run|call|Popen)|"
            r"child_process\.(?:exec|execSync|spawn)|exec\.Command|"
            r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\("
        ),
    ),
    PatternRule(
        "sql",
        re.compile(
            r"\.(?:execute|executeQuery|executeUpdate|executemany|"
            r"prepareStatement|prepareCall|query|raw)\s*\(",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "ldap",
        re.compile(r"\.search\s*\(", re.IGNORECASE),
    ),
    PatternRule(
        "path-access",
        re.compile(r"\b(?:open|readFile|writeFile|os\.Open|os\.ReadFile)\s*\("),
    ),
    PatternRule(
        "outbound-request",
        re.compile(r"\b(?:requests\.(?:get|post)|fetch|http\.Get)\s*\("),
    ),
)

SANITIZER_RULES = (
    PatternRule(
        "shell-escaping",
        re.compile(r"\b(?:shlex\.quote|shellescape|escapeShellArg)\s*\("),
    ),
    PatternRule(
        "numeric-validation",
        re.compile(r"\b(?:int|parseInt|strconv\.(?:Atoi|ParseInt))\s*\("),
    ),
    PatternRule(
        "path-normalization",
        re.compile(r"\b(?:Path\.resolve|os\.path\.realpath|filepath\.Clean)\s*\("),
    ),
    PatternRule(
        "schema-validation",
        re.compile(r"\b(?:validate|parse_obj|model_validate|safeParse)\s*\("),
    ),
)

GUARD_PATTERN = re.compile(
    r"\b(?:authorize|authorization|authenticate|require_?permission|"
    r"check_?permission|has_?permission|require_?role|is_?admin|"
    r"UseGuards|enforce_policy|check_?tenant|assert_?owner)\b",
    re.IGNORECASE,
)
PRINCIPAL_PATTERN = re.compile(
    r"\b(?:request|req)\.user\b|\b(?:actor|principal|current_user|session_user|identity)\b",
    re.IGNORECASE,
)
RESOURCE_PATTERN = re.compile(
    r"\b(?:tenant|organization|project|account|user|resource|document)_id\b|"
    r"\b(?:req|request)\.params(?:\.[A-Za-z_]\w*|\[['\"][^'\"]+['\"]\])",
    re.IGNORECASE,
)
SENSITIVE_ACTION_PATTERN = re.compile(
    r"\b(?:delete|remove|update|write|admin|execute|run_command|transfer|invite|"
    r"set_role|change_role|read_secret)\b",
    re.IGNORECASE,
)
ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:final\s+)?(?:[\w.$<>\[\],?]+\s+)+)?"
    r"(?P<name>[A-Za-z_$][\w$]*)"
    r"(?:\s*:[^=]+)?\s*(?P<operator>:=|=(?!=))\s*"
    r"(?P<value>.+?)\s*;?\s*(?://.*)?$"
)
COLLECTION_PUT_RE = re.compile(
    r"\b(?P<name>[A-Za-z_$][\w$]*)\.put\s*\((?P<arguments>[^;]*)\)"
)
CALL_RE = re.compile(
    r"(?P<name>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*"
    r"\((?P<arguments>[^()]*)\)"
)
_FIXTURE_RESULT_MAX_BYTES = 2_000_000
_FIXTURE_CLEANUP_SECONDS = 2.0


class PathInput(FrozenModel):
    path: str


class FindReferencesInput(FrozenModel):
    symbol: str


class TraceDataflowInput(FrozenModel):
    source_path: str
    sink_path: str | None = None
    max_hops: int = Field(default=4, ge=0, le=8)


class CaseInput(FrozenModel):
    case_id: str


class CompareGuardInput(FrozenModel):
    route_path: str
    max_hops: int = Field(default=4, ge=0, le=8)


class FixtureOutcome(FrozenModel):
    status: ValidationStatus
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class FixtureCase:
    case_id: str
    runner: Callable[[], FixtureOutcome]
    timeout_seconds: float | None = None
    read_roots: tuple[Path, ...] = ()

    def __post_init__(self) -> None:
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("fixture timeout must be positive")


@dataclass(frozen=True)
class LoopbackRequest:
    method: str
    path: str
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class LoopbackResponse:
    status: int
    body: bytes = b""
    headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class LoopbackCase:
    case_id: str
    application: Callable[[LoopbackRequest], LoopbackResponse]
    path: str = "/"
    method: str = "GET"
    unauthorized_headers: tuple[tuple[str, str], ...] = ()
    authorized_headers: tuple[tuple[str, str], ...] = (
        ("Authorization", "Bearer project-owned-test-principal"),
    )
    body: bytes = b""
    read_roots: tuple[Path, ...] = ()


@dataclass(frozen=True)
class _DocumentFlow:
    path: str
    sources: tuple[dict[str, Any], ...]
    sinks: tuple[dict[str, Any], ...]
    sanitizers: tuple[dict[str, Any], ...]
    tainted_variables: tuple[str, ...]
    tainted_calls: tuple[str, ...]
    call_bindings: tuple[CallBinding, ...] = ()


def _json_content(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _matching_lines(
    document: CodeDocument,
    rules: Iterable[PatternRule],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(document.text.splitlines(), start=1):
        for rule in rules:
            for match in rule.pattern.finditer(line):
                findings.append(
                    {
                        "category": rule.category,
                        "line": line_number,
                        "match": match.group(0),
                        "text": line.strip(),
                    }
                )
    return findings


def _parameters(document: CodeDocument) -> tuple[str, ...]:
    node = function_node(document)
    if node is not None:
        return parameter_names(node)
    parsed_parameters = ast_parameters(document)
    if parsed_parameters is not None:
        return parsed_parameters
    header = document.text.split("{", 1)[0]
    match = re.search(r"\((?P<parameters>[^)]*)\)", header)
    if not match:
        return ()
    parameters: list[str] = []
    for raw in match.group("parameters").split(","):
        raw = raw.strip()
        if not raw:
            continue
        name_match = re.search(
            r"([A-Za-z_$][\w$]*)\s*$",
            raw.split("=", maxsplit=1)[0].split(":", maxsplit=1)[0].strip(),
        )
        if name_match and name_match.group(1) not in {"self", "cls"}:
            parameters.append(name_match.group(1))
    return tuple(parameters)


def _contains_identifier(text: str, names: Iterable[str]) -> bool:
    return any(re.search(rf"\b{re.escape(name)}\b", text) for name in names)


def _value_is_tainted(
    value: str,
    *,
    tainted: set[str],
    tainted_containers: set[str],
    source_hits: Iterable[str] = (),
) -> bool:
    return (
        bool(tuple(source_hits))
        or _contains_identifier(value, tainted)
        or _contains_identifier(value, tainted_containers)
    )


def _document_flow(
    document: CodeDocument,
    *,
    initial_tainted: Iterable[str] = (),
    sink_category: str = "command-execution",
) -> _DocumentFlow:
    parsed = python_document_flow(
        document, initial_tainted=initial_tainted, sink_category=sink_category,
        source_rules=SOURCE_RULES, sink_rules=SINK_RULES, sanitizer_rules=SANITIZER_RULES,
    )
    if parsed is not None:
        return _DocumentFlow(**parsed)
    tainted = set(initial_tainted)
    tainted_containers: set[str] = set()
    sources: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    sanitizers: list[dict[str, Any]] = []
    tainted_calls: set[str] = set()
    call_bindings: list[CallBinding] = []

    for line_number, line in enumerate(document.text.splitlines(), start=1):
        code_line = line.split("//", maxsplit=1)[0]
        source_hits = [
            rule.category for rule in SOURCE_RULES if rule.pattern.search(code_line)
        ]
        sanitizer_hits = [
            rule.category for rule in SANITIZER_RULES if rule.pattern.search(code_line)
            and (
                (rule.category == "shell-escaping" and sink_category == "command-execution")
                or (rule.category == "numeric-validation" and sink_category in {"command-execution", "code-execution", "sql"})
            )
        ]
        assignment = ASSIGNMENT_RE.match(code_line)
        if source_hits:
            sources.append(
                {
                    "line": line_number,
                    "categories": source_hits,
                    "text": line.strip(),
                }
            )
        if sanitizer_hits:
            sanitizers.append(
                {
                    "line": line_number,
                    "categories": sanitizer_hits,
                    "text": line.strip(),
                }
            )
        if assignment:
            name = assignment.group("name")
            value = assignment.group("value")
            for put in COLLECTION_PUT_RE.finditer(code_line):
                if _value_is_tainted(
                    put.group("arguments"),
                    tainted=tainted,
                    tainted_containers=tainted_containers,
                    source_hits=source_hits,
                ):
                    tainted_containers.add(put.group("name"))
            if sanitizer_hits:
                tainted.discard(name)
            elif _value_is_tainted(
                value,
                tainted=tainted,
                tainted_containers=tainted_containers,
                source_hits=source_hits,
            ):
                tainted.add(name)
            else:
                tainted.discard(name)
        else:
            for put in COLLECTION_PUT_RE.finditer(code_line):
                if _value_is_tainted(
                    put.group("arguments"),
                    tainted=tainted,
                    tainted_containers=tainted_containers,
                    source_hits=source_hits,
                ):
                    tainted_containers.add(put.group("name"))

        line_is_tainted = (
            bool(source_hits)
            or _contains_identifier(code_line, tainted)
            or _contains_identifier(code_line, tainted_containers)
        )
        for rule in SINK_RULES:
            if rule.category != sink_category:
                continue
            match = rule.pattern.search(code_line)
            if match:
                sinks.append(
                    {
                        "category": rule.category,
                        "line": line_number,
                        "match": match.group(0),
                        "tainted": line_is_tainted and not sanitizer_hits,
                        "text": line.strip(),
                    }
                )
        if not re.match(r"^\s*(?:def|func|function)\b", code_line):
            for call in CALL_RE.finditer(code_line):
                try:
                    expression = ast.parse("f(" + call.group("arguments") + ")", mode="eval").body
                    arguments = tuple(
                        any(isinstance(node, ast.Name) and node.id in tainted for node in ast.walk(arg))
                        or any(rule.pattern.search(ast.unparse(arg)) for rule in SOURCE_RULES)
                        for arg in expression.args
                    )
                except SyntaxError:
                    # Unsupported argument syntax does not justify tainting every parameter.
                    continue
                if not any(arguments):
                    continue
                tainted_calls.add(call.group("name"))
                call_bindings.append(CallBinding(call.group("name"), arguments))

    return _DocumentFlow(
        path=document.path,
        sources=tuple(sources),
        sinks=tuple(sinks),
        sanitizers=tuple(sanitizers),
        tainted_variables=tuple(sorted(tainted)),
        tainted_calls=tuple(sorted(tainted_calls)),
        call_bindings=tuple(call_bindings),
    )


def _symbol_matches_target(symbol: str, target: CodeDocument) -> bool:
    final = symbol.rsplit(".", 1)[-1]
    return any(
        definition == symbol or definition.rsplit(".", 1)[-1] == final
        for definition in target.defines
    )


def _admitted_document(
    index: RepositoryIndex,
    path: str,
    scope: ToolExecutionScope,
    tool: str,
) -> tuple[CodeDocument | None, ToolObservation | None]:
    if path not in scope.admitted_paths:
        return None, ToolObservation(
            tool=tool,
            status="blocked",
            content=f"path is outside the retrieved execution scope: {path}",
        )
    document = index.document(path)
    if document is None:
        return None, ToolObservation(
            tool=tool,
            status="error",
            content=f"indexed document not found: {path}",
        )
    return document, None


def _scope_documents(
    index: RepositoryIndex,
    scope: ToolExecutionScope,
) -> list[CodeDocument]:
    return [
        document
        for path in sorted(scope.admitted_paths)
        if (document := index.document(path)) is not None
    ]


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
) -> None:
    try:
        _apply_fixture_limits()
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
        args=(case.runner, write_fd, case.read_roots, retained_fds, accept_only),
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


def validation_tools(
    index: RepositoryIndex,
    *,
    fixed_index: RepositoryIndex | None = None,
    paired_paths: Mapping[str, str] | None = None,
    fixture_cases: Iterable[FixtureCase] = (),
    loopback_cases: Iterable[LoopbackCase] = (),
) -> tuple[AgentTool, ...]:
    paired = dict(paired_paths or {})
    fixture_list = tuple(fixture_cases)
    loopback_list = tuple(loopback_cases)
    fixtures = {case.case_id: case for case in fixture_list}
    loopbacks = {case.case_id: case for case in loopback_list}
    if len(fixtures) != len(fixture_list):
        raise ValueError("fixture cases must have unique ids")
    if len(loopbacks) != len(loopback_list):
        raise ValueError("loopback cases must have unique ids")

    def references(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        value = cast(FindReferencesInput, arguments)
        matches = [
            {
                "calls": [call for call in document.calls if value.symbol in call],
                "defines": [
                    definition
                    for definition in document.defines
                    if value.symbol in definition
                ],
                "path": document.path,
            }
            for document in _scope_documents(index, scope)
            if any(value.symbol in symbol for symbol in (*document.calls, *document.defines))
        ]
        return ToolObservation(
            tool="find_references",
            status="ok",
            content=_json_content({"references": matches, "symbol": value.symbol}),
            evidence_ids=tuple(f"reference:{item['path']}" for item in matches),
        )

    def static_check(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        value = cast(PathInput, arguments)
        document, error = _admitted_document(index, value.path, scope, "run_static_check")
        if error is not None:
            return error
        findings = _matching_lines(cast(CodeDocument, document), SINK_RULES)
        return ToolObservation(
            tool="run_static_check",
            status="ok",
            content=_json_content(
                {
                    "finding_count": len(findings),
                    "findings": findings,
                    "path": value.path,
                }
            ),
            evidence_ids=(f"static:{value.path}",),
        )

    def pattern_tool(
        tool_name: str,
        rules: Iterable[PatternRule],
    ) -> Callable[[FrozenModel, ToolExecutionScope], ToolObservation]:
        def handle(
            arguments: FrozenModel,
            scope: ToolExecutionScope,
        ) -> ToolObservation:
            value = cast(PathInput, arguments)
            document, error = _admitted_document(index, value.path, scope, tool_name)
            if error is not None:
                return error
            findings = _matching_lines(cast(CodeDocument, document), rules)
            return ToolObservation(
                tool=tool_name,
                status="ok",
                content=_json_content(
                    {
                        "finding_count": len(findings),
                        "findings": findings,
                        "path": value.path,
                    }
                ),
                evidence_ids=(f"{tool_name}:{value.path}",),
            )

        return handle

    def trace_dataflow(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        value = cast(TraceDataflowInput, arguments)
        source, error = _admitted_document(
            index,
            value.source_path,
            scope,
            "trace_dataflow",
        )
        if error is not None:
            return error
        if value.sink_path is not None and value.sink_path not in scope.admitted_paths:
            return ToolObservation(
                tool="trace_dataflow",
                status="blocked",
                content="sink path is outside the retrieved execution scope",
            )

        queue: deque[tuple[str, tuple[str, ...], tuple[dict[str, Any], ...], str]] = deque(
            (cast(CodeDocument, source).path, (), (), category)
            for category in dict.fromkeys(rule.category for rule in SINK_RULES)
        )
        visited: set[tuple[str, tuple[str, ...], str]] = set()
        unresolved_edges: list[dict[str, str]] = []
        confirmed_trace: tuple[dict[str, Any], ...] | None = None
        while queue:
            path, initial_tainted, trace, category = queue.popleft()
            state_key = (path, initial_tainted, category)
            if state_key in visited:
                continue
            visited.add(state_key)
            document = index.document(path)
            if document is None:
                continue
            flow = _document_flow(
                document, initial_tainted=initial_tainted, sink_category=category
            )
            step = {
                "path": path,
                "sanitizers": list(flow.sanitizers),
                "sinks": list(flow.sinks),
                "sources": list(flow.sources),
                "tainted_calls": list(flow.tainted_calls),
                "tainted_variables": list(flow.tainted_variables),
            }
            next_trace = (*trace, step)
            if any(sink["tainted"] for sink in flow.sinks) and (
                value.sink_path is None or path == value.sink_path
            ):
                confirmed_trace = next_trace
                break
            if len(next_trace) > value.max_hops:
                continue
            for neighbor in index.graph_neighbors(path, direction="forward"):
                if neighbor not in scope.admitted_paths:
                    continue
                target = index.document(neighbor)
                if target is None:
                    continue
                matching_calls = [
                    call
                    for call in flow.call_bindings
                    if _symbol_matches_target(call.name, target)
                ]
                if not matching_calls:
                    unresolved_edges.append({"from": path, "to": neighbor})
                    continue
                parameters = _parameters(target)
                for call in matching_calls:
                    tainted_parameters = {
                        name for name, is_tainted in zip(parameters, call.positional)
                        if is_tainted and name
                    }
                    tainted_parameters.update(
                        name for name, is_tainted in call.keywords
                        if is_tainted and name in parameters
                    )
                    if tainted_parameters:
                        queue.append((
                            neighbor, tuple(sorted(tainted_parameters)), next_trace, category
                        ))

        status = (
            ValidationStatus.CONFIRMED
            if confirmed_trace is not None
            else ValidationStatus.UNRESOLVED
        )
        return ToolObservation(
            tool="trace_dataflow",
            status="ok",
            validation_status=status,
            content=_json_content(
                {
                    "status": status,
                    "trace": list(confirmed_trace or ()),
                    "unresolved_edges": unresolved_edges,
                }
            ),
            evidence_ids=tuple(
                f"taint:{step['path']}" for step in (confirmed_trace or ())
            ),
        )

    def concrete_eval_probe(arguments: FrozenModel, scope: ToolExecutionScope) -> ToolObservation:
        value = cast(TraceDataflowInput, arguments)
        _, error = _admitted_document(index, value.source_path, scope, "probe_python_eval")
        if error is not None:
            return error
        if value.sink_path is not None and value.sink_path not in scope.admitted_paths:
            return ToolObservation(tool="probe_python_eval", status="blocked",
                                   content="sink path is outside the retrieved execution scope")
        result = probe_python_eval(index, scope.admitted_paths, value.source_path,
                                   value.sink_path, value.max_hops)
        return ToolObservation(
            tool="probe_python_eval", status="ok",
            validation_status=ValidationStatus(result["status"]), content=_json_content(result),
            evidence_ids=(f"probe:{value.source_path}",),
        )

    def routes(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        value = cast(PathInput, arguments)
        document, error = _admitted_document(index, value.path, scope, "get_routes")
        if error is not None:
            return error
        item = cast(CodeDocument, document)
        inferred = sorted(
            {
                *item.routes,
                *(
                    f"{match.group(1).upper()}:{match.group(2)}"
                    for match in re.finditer(
                        r"\.(get|post|put|patch|delete)\(\s*['\"]([^'\"]*)['\"]",
                        item.text,
                        flags=re.IGNORECASE,
                    )
                ),
            }
        )
        return ToolObservation(
            tool="get_routes",
            status="ok",
            content=_json_content({"path": value.path, "routes": inferred}),
            evidence_ids=(f"routes:{value.path}",),
        )

    def guards(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        value = cast(PathInput, arguments)
        document, error = _admitted_document(index, value.path, scope, "get_guards")
        if error is not None:
            return error
        item = cast(CodeDocument, document)
        inferred = sorted(
            {
                *item.guards,
                *(match.group(0) for match in GUARD_PATTERN.finditer(item.text)),
            }
        )
        return ToolObservation(
            tool="get_guards",
            status="ok",
            content=_json_content({"guards": inferred, "path": value.path}),
            evidence_ids=(f"guards:{value.path}",),
        )

    def semantic_matches(
        tool_name: str,
        pattern: re.Pattern[str],
        key: str,
    ) -> Callable[[FrozenModel, ToolExecutionScope], ToolObservation]:
        def handle(
            arguments: FrozenModel,
            scope: ToolExecutionScope,
        ) -> ToolObservation:
            value = cast(PathInput, arguments)
            document, error = _admitted_document(index, value.path, scope, tool_name)
            if error is not None:
                return error
            item = cast(CodeDocument, document)
            matches = sorted({match.group(0) for match in pattern.finditer(item.text)})
            return ToolObservation(
                tool=tool_name,
                status="ok",
                content=_json_content({key: matches, "path": value.path}),
                evidence_ids=(f"{tool_name}:{value.path}",),
            )

        return handle

    def compare_guard(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        value = cast(CompareGuardInput, arguments)
        route, error = _admitted_document(
            index,
            value.route_path,
            scope,
            "compare_route_and_service_guard",
        )
        if error is not None:
            return error
        route_path = cast(CodeDocument, route).path
        queue: deque[tuple[str, tuple[str, ...]]] = deque(
            [(route_path, (route_path,))]
        )
        records_by_path: dict[str, dict[str, Any]] = {}
        sensitive_occurrences: list[tuple[tuple[str, ...], str, int]] = []
        while queue:
            path, graph_path = queue.popleft()
            distance = len(graph_path) - 1
            if distance > value.max_hops:
                continue
            document = index.document(path)
            if document is None:
                continue
            guard_lines = [
                line_number
                for line_number, line in enumerate(document.text.splitlines(), start=1)
                if GUARD_PATTERN.search(line)
            ]
            sensitive_lines = [
                line_number
                for line_number, line in enumerate(document.text.splitlines(), start=1)
                if not re.match(
                    r"^\s*(?:(?:async\s+)?def|function|func)\b",
                    line,
                )
                and SENSITIVE_ACTION_PATTERN.search(line)
            ]
            records_by_path.setdefault(
                path,
                {
                    "distance": distance,
                    "guards": sorted(
                        {
                            *document.guards,
                            *(
                                match.group(0)
                                for match in GUARD_PATTERN.finditer(document.text)
                            ),
                        }
                    ),
                    "guard_lines": guard_lines,
                    "path": path,
                    "principals": sorted(
                        {
                            match.group(0)
                            for match in PRINCIPAL_PATTERN.finditer(document.text)
                        }
                    ),
                    "resources": sorted(
                        {
                            match.group(0)
                            for match in RESOURCE_PATTERN.finditer(document.text)
                        }
                    ),
                    "sensitive": bool(sensitive_lines),
                    "sensitive_lines": sensitive_lines,
                },
            )
            sensitive_occurrences.extend(
                (graph_path, path, line) for line in sensitive_lines
            )
            for neighbor in index.graph_neighbors(path, direction="forward"):
                if neighbor in scope.admitted_paths and neighbor not in graph_path:
                    queue.append((neighbor, (*graph_path, neighbor)))
        records = sorted(
            records_by_path.values(),
            key=lambda record: (record["distance"], record["path"]),
        )
        has_sensitive = any(record["sensitive"] for record in records)

        def edge_call_lines(caller_path: str, target_path: str) -> list[int]:
            caller = index.document(caller_path)
            target = index.document(target_path)
            if caller is None or target is None:
                return []
            final_names = {
                call.rsplit(".", 1)[-1]
                for call in caller.calls
                if _symbol_matches_target(call, target)
            }
            return [
                line_number
                for line_number, line in enumerate(caller.text.splitlines(), start=1)
                if any(
                    re.search(rf"\b{re.escape(name)}\s*\(", line)
                    for name in final_names
                )
            ]

        def occurrence_is_guarded(
            graph_path: tuple[str, ...],
            sensitive_path: str,
            sensitive_line: int,
        ) -> bool:
            for position, guard_path in enumerate(graph_path):
                record = records_by_path[guard_path]
                if guard_path == sensitive_path:
                    if any(line < sensitive_line for line in record["guard_lines"]):
                        return True
                    continue
                next_path = graph_path[position + 1]
                boundary = min(
                    edge_call_lines(guard_path, next_path),
                    default=None,
                )
                if boundary is not None and any(
                    line < boundary for line in record["guard_lines"]
                ):
                    return True
            return False

        guard_dominates = bool(
            sensitive_occurrences
            and all(
                occurrence_is_guarded(
                    graph_path,
                    sensitive_path,
                    sensitive_line,
                )
                for graph_path, sensitive_path, sensitive_line in sensitive_occurrences
            )
        )
        if has_sensitive and not guard_dominates:
            status = ValidationStatus.CONFIRMED
            interpretation = (
                "sensitive downstream action has no preceding authorization guard"
            )
        elif has_sensitive and guard_dominates:
            status = ValidationStatus.UNRESOLVED
            interpretation = (
                "a guard precedes the sensitive action, but static presence alone does not "
                "prove principal and resource enforcement"
            )
        else:
            status = ValidationStatus.UNRESOLVED
            interpretation = "no sensitive authorization-relevant action was established"
        return ToolObservation(
            tool="compare_route_and_service_guard",
            status="ok",
            validation_status=status,
            content=_json_content(
                {
                    "interpretation": interpretation,
                    "records": records,
                    "status": status,
                }
            ),
            evidence_ids=tuple(f"authz:{record['path']}" for record in records),
        )

    def compare_versions(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        value = cast(PathInput, arguments)
        vulnerable, error = _admitted_document(
            index,
            value.path,
            scope,
            "compare_vulnerable_and_fixed",
        )
        if error is not None:
            return error
        fixed_path = paired.get(value.path)
        fixed = fixed_index.document(fixed_path) if fixed_index and fixed_path else None
        if fixed is None:
            return ToolObservation(
                tool="compare_vulnerable_and_fixed",
                status="ok",
                content=_json_content(
                    {
                        "status": ValidationStatus.UNRESOLVED,
                        "summary": "no verified paired fixed document is registered",
                    }
                ),
            )
        vulnerable_item = cast(CodeDocument, vulnerable)
        vulnerable_sinks = _matching_lines(vulnerable_item, SINK_RULES)
        fixed_sinks = _matching_lines(fixed, SINK_RULES)
        vulnerable_guards = sorted(
            {match.group(0) for match in GUARD_PATTERN.finditer(vulnerable_item.text)}
        )
        fixed_guards = sorted(
            {match.group(0) for match in GUARD_PATTERN.finditer(fixed.text)}
        )
        fixed_guard_lines = [
            line_number
            for line_number, line in enumerate(fixed.text.splitlines(), start=1)
            if GUARD_PATTERN.search(line)
        ]
        guard_precedes_fixed_sinks = bool(
            fixed_sinks
            and all(
                any(guard_line < sink["line"] for guard_line in fixed_guard_lines)
                for sink in fixed_sinks
            )
        )
        sink_removed = len(fixed_sinks) < len(vulnerable_sinks)
        governing_guard_added = (
            len(fixed_guards) > len(vulnerable_guards)
            and guard_precedes_fixed_sinks
        )
        supports_fix = sink_removed or governing_guard_added
        status = (
            ValidationStatus.CONFIRMED
            if supports_fix
            else ValidationStatus.UNRESOLVED
        )
        return ToolObservation(
            tool="compare_vulnerable_and_fixed",
            status="ok",
            validation_status=status,
            content=_json_content(
                {
                    "fixed_guard_count": len(fixed_guards),
                    "fixed_guard_precedes_sinks": guard_precedes_fixed_sinks,
                    "fixed_path": fixed_path,
                    "fixed_sink_count": len(fixed_sinks),
                    "status": status,
                    "vulnerable_guard_count": len(vulnerable_guards),
                    "vulnerable_path": value.path,
                    "vulnerable_sink_count": len(vulnerable_sinks),
                }
            ),
            evidence_ids=(f"vulnerable:{value.path}", f"fixed:{fixed_path}"),
        )

    def fixture(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        del scope
        value = cast(CaseInput, arguments)
        case = fixtures.get(value.case_id)
        if case is None:
            return ToolObservation(
                tool="run_fixture_test",
                status="error",
                content=f"fixture case is not registered: {value.case_id}",
            )
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
        )

    def loopback(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        del scope
        value = cast(CaseInput, arguments)
        case = loopbacks.get(value.case_id)
        if case is None:
            return ToolObservation(
                tool="run_loopback_http_case",
                status="error",
                content=f"loopback case is not registered: {value.case_id}",
            )
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
        )

    def json_tool(
        name: str,
        description: str,
        input_model: type[FrozenModel],
        handler: Callable[[FrozenModel, ToolExecutionScope], ToolObservation],
        *, available: bool = True,
    ) -> AgentTool:
        return AgentTool(
            name=name,
            description=description,
            input_model=input_model,
            handler=handler,
            content_type="json",
            available=available,
        )

    return (
        json_tool("find_references", "Find admitted definitions and call references for one symbol.", FindReferencesInput, references),
        json_tool("run_static_check", "Run deterministic sink rules on one admitted code span.", PathInput, static_check),
        json_tool("run_fixture_test", f"Run one project-registered bounded fixture by id. Registered case IDs: {json.dumps(sorted(fixtures))}", CaseInput, fixture, available=bool(fixtures)),
        json_tool("find_sources", "Find untrusted-input sources in one admitted code span.", PathInput, pattern_tool("find_sources", SOURCE_RULES)),
        json_tool("find_sinks", "Find security-sensitive sinks in one admitted code span.", PathInput, pattern_tool("find_sinks", SINK_RULES)),
        json_tool("trace_dataflow", "Trace tainted values through admitted call-graph paths.", TraceDataflowInput, trace_dataflow),
        json_tool("probe_python_eval", "Independently probe request input reaching eval using two concrete inputs in a bounded Python function-slice interpreter. Use the candidate entry as source_path. Does not execute repository code or prove application exploitability. Unsupported syntax and no witness mean UNRESOLVED, not SAFE.", TraceDataflowInput, concrete_eval_probe,
                  available=any(doc.language == "python" and doc.adapter_tier == "ast" for doc in index.documents.values())),
        json_tool("find_sanitizers", "Find sanitizer or validation operations in one admitted span.", PathInput, pattern_tool("find_sanitizers", SANITIZER_RULES)),
        json_tool("compare_vulnerable_and_fixed", "Compare one admitted vulnerable span with its registered verified fixed pair.", PathInput, compare_versions, available=bool(fixed_index and paired)),
        json_tool("get_routes", "Read structured and inferred route declarations for one admitted span.", PathInput, routes),
        json_tool("get_guards", "Read structured and inferred authorization guards for one admitted span.", PathInput, guards),
        json_tool("inspect_principal", "Inspect principal identity evidence in one admitted span.", PathInput, semantic_matches("inspect_principal", PRINCIPAL_PATTERN, "principals")),
        json_tool("inspect_resource_scope", "Inspect resource and tenant scope evidence in one admitted span.", PathInput, semantic_matches("inspect_resource_scope", RESOURCE_PATTERN, "resources")),
        json_tool("compare_route_and_service_guard", "Compare reachable route and service authorization enforcement.", CompareGuardInput, compare_guard),
        json_tool("run_loopback_http_case", f"Run one project-registered HTTP case on an ephemeral loopback server. Registered case IDs: {json.dumps(sorted(loopbacks))}", CaseInput, loopback, available=bool(loopbacks)),
    )


def full_agent_tools(
    index: RepositoryIndex,
    *,
    fixed_index: RepositoryIndex | None = None,
    paired_paths: Mapping[str, str] | None = None,
    fixture_cases: Iterable[FixtureCase] = (),
    loopback_cases: Iterable[LoopbackCase] = (),
) -> tuple[AgentTool, ...]:
    return (
        *repository_tools(index),
        *validation_tools(
            index,
            fixed_index=fixed_index,
            paired_paths=paired_paths,
            fixture_cases=fixture_cases,
            loopback_cases=loopback_cases,
        ),
    )
