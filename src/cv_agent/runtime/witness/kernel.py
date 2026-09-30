"""Source-bound, positive-only command witness for one concrete input.

The target runs in a fresh, restricted Python process. An audit hook records the
first command event and terminates that process. A separate restricted process
replays only a verified Bash ``-c`` command with a local argument recorder.
This is a bounded observation, not a general Python sandbox or a SAFE proof.
"""

from __future__ import annotations

import hashlib
import faulthandler
import json
import os
import platform
import re
import select
import signal
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import nullcontext
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from uuid import uuid4

from pydantic import Field, model_validator

from cv_agent.domain.evidence import ValidationStatus, ValidationSubject
from cv_agent.domain.types import FrozenModel
from cv_agent.runtime.fixture_isolation import restrict_fixture_filesystem
from cv_agent.runtime.witness_resources import WitnessResourceProfile
from cv_agent.runtime.witness_entry import (
    EntryInvocation, bound_instance_method, class_dictionary, click_callback,
    module_dictionary, qualified_function, source_entry_code,
)
from cv_agent.runtime.witness.isolation_policy import IsolationReadGrant
from cv_agent.runtime.witness.accounting import (
    ProcessResourceSampler,
    self_usage,
)
from cv_agent.tools.validation.fixtures import (
    _apply_fixture_limits,
    _install_fixture_isolation,
)
from cv_agent.tools.validation.witness_scenario import WitnessScenarioHypothesis, subject_has_scenario


_COMMAND_EVENTS = frozenset({
    "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn",
    "os.fork", "os.forkpty", "pty.spawn",
})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DOTTED_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*\Z")
_COMMAND_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9-]*\Z")
_NONCE = re.compile(r"[A-Za-z0-9]{12,64}\Z")
_RESULT_LIMIT = 64_000
_REPLAY_TIMEOUT = 5.0
_TRACE_LIMIT = 16_000_000
_STACK_LIMIT = 64_000
_STACK_TIMEOUT_MARGIN = 3.0


class _CapturedCommand(BaseException):
    """Abort Popen and leave the audit callback before running its verifier."""


def _worker_path(python_executable: Path | None = None) -> str:
    return f"{(python_executable or Path(sys.executable)).parent}:/bin:/usr/bin"


def _interpreter_identity(expected: Path | None) -> dict[str, Any]:
    """Check the running Python's invoked path and venv prefix, without imports."""
    executable = Path(sys.executable).absolute()
    prefix = Path(sys.prefix).resolve()
    expected_path = expected.absolute() if expected is not None else None
    expected_prefix = expected_path.parent.parent.resolve() if expected_path else None
    return {
        "executable": str(executable),
        "prefix": str(prefix),
        "base_prefix": str(Path(sys.base_prefix).resolve()),
        "version": platform.python_version(),
        "expected_executable": str(expected_path) if expected_path else None,
        "expected_prefix": str(expected_prefix) if expected_prefix else None,
        "matches_manifest": (expected_path is None or
                             (executable == expected_path and prefix == expected_prefix)),
    }


class SourceFileBinding(FrozenModel):
    module_name: str
    relative_path: str
    sha256: str

    @model_validator(mode="after")
    def check_identity(self) -> SourceFileBinding:
        if not _DOTTED_NAME.fullmatch(self.module_name):
            raise ValueError("module_name must be a dotted Python name")
        if not _safe_relative_path(self.relative_path):
            raise ValueError("source relative_path must remain inside checkout")
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError("source sha256 must be a lowercase full-file SHA256")
        return self


class WitnessManifest(FrozenModel):
    """Data-only call and source identity; no target-internal stubs are allowed."""

    subject: ValidationSubject
    checkout_root: Path
    import_root: str = '.'
    module_name: str
    class_name: str | None = None
    method_name: str
    entry_invocation: EntryInvocation = "instance_method"
    entry_relative_path: str
    entry_file_sha256: str
    entry_first_line: int = Field(ge=1)
    source_modules: tuple[SourceFileBinding, ...]
    probe_argument: str
    recorder_command: str
    recorder_arguments: tuple[str, ...] = ()
    bash_path: Path = Path("/bin/bash")
    python_executable: Path | None = None
    resource_profile: WitnessResourceProfile = Field(default_factory=WitnessResourceProfile.fixture_default)
    constructor_args: tuple[Any, ...] = ()
    constructor_kwargs: dict[str, Any] = Field(default_factory=dict)
    call_args: tuple[Any, ...] = ()
    call_kwargs: dict[str, Any] = Field(default_factory=dict)
    precondition_files: dict[str, str] = Field(default_factory=dict)
    probe_directory_prefix: str = "model"
    original_subject: ValidationSubject | None = None
    scenario_hypothesis: WitnessScenarioHypothesis | None = None
    scenario_origin: Literal["dataset_provided", "model_proposed"] | None = None

    @model_validator(mode="after")
    def check_manifest(self) -> WitnessManifest:
        if self.scenario_hypothesis is not None:
            if self.original_subject is None or self.scenario_origin is None:
                raise ValueError("classified witness scenario requires original subject and provenance")
            if self.scenario_hypothesis.execution_subject(self.original_subject) != self.subject:
                raise ValueError("execution subject differs from the classified scenario")
            if self.scenario_origin == "model_proposed" and subject_has_scenario(self.original_subject):
                raise ValueError("model scenario cannot replace dataset premises")
            if self.scenario_origin == "dataset_provided" and self.original_subject != self.subject:
                raise ValueError("dataset classification must match the original subject")
        elif self.original_subject is not None or self.scenario_origin is not None:
            raise ValueError("scenario provenance requires a classified scenario")
        if self.import_root != '.' and not _safe_relative_path(self.import_root):
            raise ValueError('source import root must remain relative to checkout')
        if not _DOTTED_NAME.fullmatch(self.module_name):
            raise ValueError("module_name must be a dotted Python name")
        if not all(_DOTTED_NAME.fullmatch(x) and "." not in x for x in (
            self.method_name, self.probe_argument,
        )):
            raise ValueError("class, method, and probe argument must be simple Python names")
        if self.entry_invocation == "instance_method":
            if self.class_name is None or not _DOTTED_NAME.fullmatch(self.class_name) or "." in self.class_name:
                raise ValueError("instance method requires a simple class name")
        elif self.class_name is not None or self.constructor_args or self.constructor_kwargs:
            raise ValueError("function entries cannot carry class or constructor inputs")
        if not _safe_relative_path(self.entry_relative_path):
            raise ValueError("entry_relative_path must remain inside checkout")
        if not _SHA256.fullmatch(self.entry_file_sha256):
            raise ValueError("entry_file_sha256 must be a lowercase full-file SHA256")
        if not _COMMAND_NAME.fullmatch(self.recorder_command):
            raise ValueError("recorder_command must be one simple executable name")
        if self.python_executable is not None and not self.python_executable.is_absolute():
            raise ValueError("python_executable must be an absolute path")
        if any(not re.fullmatch(r"[A-Za-z0-9._-]+", part)
               for part in self.recorder_arguments):
            raise ValueError("recorder arguments must be simple literal words")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", self.probe_directory_prefix):
            raise ValueError("probe_directory_prefix must contain no shell syntax")
        if self.probe_argument in self.call_kwargs:
            raise ValueError("probe argument must be supplied only by the witness")
        if self.subject.property_id != "command-execution":
            raise ValueError("witness requires the command-execution candidate property")
        if self.probe_argument not in self.subject.input_parameters:
            raise ValueError("probe argument must be declared as candidate input")
        if self.subject.entry_path.split("::", 1)[0] != self.entry_relative_path:
            raise ValueError("subject and entry file differ")
        bindings = {item.module_name: item for item in self.source_modules}
        if len(bindings) != len(self.source_modules):
            raise ValueError("source module names must be unique")
        entry = bindings.get(self.module_name)
        if entry is None or (entry.relative_path, entry.sha256) != (
            self.entry_relative_path, self.entry_file_sha256,
        ):
            raise ValueError("entry module needs an identical source binding")
        root_module = self.module_name.split(".", 1)[0]
        if "." in self.module_name and root_module not in bindings:
            raise ValueError("top-level package needs an explicit source binding")
        for name in self.precondition_files:
            if not _safe_relative_path(name):
                raise ValueError("precondition file must be beneath the probe directory")
        try:
            json.dumps((self.constructor_args, self.constructor_kwargs,
                        self.call_args, self.call_kwargs, self.precondition_files), allow_nan=False)
        except (TypeError, ValueError) as error:
            raise ValueError("call manifest values must be JSON data") from error
        return self

    @property
    def entry_qualified_name(self) -> str:
        return (f"{self.class_name}.{self.method_name}"
                if self.class_name is not None else self.method_name)


class WitnessResult(FrozenModel):
    status: Literal[ValidationStatus.CONFIRMED, ValidationStatus.UNRESOLVED]
    raw_status: Literal["EXPANDED_OBSERVED", "LITERAL_OBSERVED", "UNRESOLVED"]
    gaps: tuple[str, ...] = ()
    details: dict[str, Any] = Field(default_factory=dict)


def _safe_relative_path(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value and not path.is_absolute() and value == str(path)
                and all(part not in {".", ".."} for part in path.parts))


def _safe_runtime_path(path: Path) -> bool:
    return (
        path.is_absolute()
        and ".." not in path.parts
        and re.fullmatch(r"/[A-Za-z0-9_./-]+", str(path)) is not None
        and path.resolve(strict=True) == path
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        return False
    return True


def _unresolved(*gaps: str, details: dict[str, Any] | None = None) -> WitnessResult:
    return WitnessResult(status=ValidationStatus.UNRESOLVED, raw_status="UNRESOLVED",
                         gaps=tuple(gaps), details=details or {})


def _assumption_gaps(manifest: WitnessManifest) -> tuple[str, ...]:
    """Only call kwargs are directly established at this data-only boundary."""
    gaps: list[str] = []
    for name, expected in manifest.subject.entry_boolean_arguments.items():
        actual = manifest.call_kwargs.get(name)
        if not isinstance(actual, bool) or actual is not expected:
            gaps.append(f"entry_boolean_argument_unverified:{name}")
    for name, expected in manifest.subject.entry_value_assumptions.items():
        if name not in manifest.call_kwargs or manifest.call_kwargs[name] != expected:
            gaps.append(f"entry_value_assumption_unverified:{name}")
    for name in manifest.subject.entry_condition_assumptions:
        gaps.append(f"entry_condition_assumption_unverified:{name}")
    return tuple(gaps)


def _read_roots(checkout: Path, runtime: Path) -> tuple[Path, ...]:
    roots = [checkout, runtime, Path(__file__).resolve().parents[3], Path(sys.prefix),
             Path(sys.base_prefix)]
    roots.extend(Path(name) for name in ("/lib", "/lib64", "/usr/lib", "/etc/ld.so.cache")
                 if Path(name).exists())
    return tuple(dict.fromkeys(path.resolve() for path in roots if path.exists()))


def _write_result(fd: int, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         default=str).encode("utf-8")
    if len(encoded) > _RESULT_LIMIT:
        encoded = b'{"kind":"error","gap":"witness_result_too_large"}'
    view = memoryview(encoded + b"\n")
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _frame_data(frame: Any, checkout: Path) -> dict[str, Any]:
    path = Path(frame.f_code.co_filename)
    source_path = str(path.resolve()) if path.exists() else str(path)
    record: dict[str, Any] = {
        "file": source_path,
        "line": frame.f_lineno,
        "qualname": frame.f_code.co_qualname,
        "first_line": frame.f_code.co_firstlineno,
        "module_name": frame.f_globals.get("__name__"),
    }
    if path.is_file():
        try:
            record["sha256"] = _sha256(path)
        except OSError:
            pass
    record["in_checkout"] = _inside(path, checkout)
    return record


def _capture_event(event: str, args: tuple[Any, ...], checkout: Path,
                   manifest: WitnessManifest, expected_code: Any,
                   trusted_popen_codes: tuple[Any, Any],
                   preexec_capture: list[Any] | None = None, *,
                   expected_globals: dict[str, Any] | None = None) -> dict[str, Any]:
    frames: list[dict[str, Any]] = []
    code_objects: list[Any] = []
    preexec_values: list[Any] = []
    frame = sys._getframe(2)
    candidate_bindings: list[bool] = []
    while frame is not None and len(frames) < 24:
        frames.append(_frame_data(frame, checkout))
        code_objects.append(frame.f_code)
        if any(frame.f_code is trusted for trusted in trusted_popen_codes):
            preexec_values.append(frame.f_locals.get("preexec_fn", object()))
        candidate_bindings.append(expected_code is not None and frame.f_code is expected_code
                                  and expected_globals is not None and frame.f_globals is expected_globals)
        frame = frame.f_back
    entry_file = str((checkout / manifest.entry_relative_path).resolve())
    candidate = next((item for item, bound in zip(frames, candidate_bindings) if bound and
                      item["file"] == entry_file
                      and item["qualname"] == manifest.entry_qualified_name
                      and item["first_line"] == manifest.entry_first_line
                      and item.get("sha256") == manifest.entry_file_sha256), None)
    emit_index = 0
    if event == "subprocess.Popen":
        while (emit_index < len(frames)
               and Path(frames[emit_index]["file"]).name == "subprocess.py"
               and frames[emit_index]["qualname"].startswith("Popen.")):
            emit_index += 1
    emitter = frames[emit_index] if emit_index < len(frames) else None
    authentic_popen = (event == "subprocess.Popen" and len(code_objects) >= 2
                      and code_objects[0] is trusted_popen_codes[0]
                      and code_objects[1] is trusted_popen_codes[1])
    preexec_verified_none = (authentic_popen and len(preexec_values) == 2
                             and all(value is None for value in preexec_values))
    if preexec_capture is not None:
        preexec_capture.extend(preexec_values)
    argv: list[str] | None = None
    env_has_probe = False
    env_keys: list[str] = []
    actual_executable_is_bash = False
    captured_cwd: str | None = None
    if event == "subprocess.Popen" and len(args) == 4:
        raw_argv = args[1]
        if isinstance(raw_argv, (list, tuple)) and all(isinstance(x, str) for x in raw_argv):
            argv = list(raw_argv)
        captured_cwd = args[2] if isinstance(args[2], str) else None
        env = args[3]
        env_path: str | None = _worker_path() if env is None else None
        if type(env) is dict:
            names = [key.decode("ascii", errors="replace") if isinstance(key, bytes) else str(key)
                     for key in env]
            env_keys = [name for name in names if name in {"BASH_ENV", "ENV", "SHELLOPTS"}
                        or name.startswith("BASH_FUNC_")]
            env_has_probe = any(isinstance(value, str) and "$(printf " in value
                                for value in env.values())
            raw_path = env.get("PATH", os.defpath)
            if isinstance(raw_path, str):
                env_path = raw_path
        executable = args[0]
        if isinstance(executable, str) and env_path is not None:
            resolved = (executable if Path(executable).is_absolute()
                        else shutil.which(executable, path=env_path))
            if resolved is not None:
                try:
                    actual_executable_is_bash = (
                        Path(resolved).resolve(strict=True)
                        == manifest.bash_path.resolve(strict=True)
                    )
                except OSError:
                    pass
    elif event == "os.system" and args and isinstance(args[0], str):
        argv = ["/bin/sh", "-c", args[0]]
    elif event in {"os.exec", "os.posix_spawn", "os.spawn", "pty.spawn"}:
        raw_argv = args[1] if event != "os.spawn" and len(args) > 1 else (
            args[2] if len(args) > 2 else None)
        if isinstance(raw_argv, (list, tuple)) and all(isinstance(x, str) for x in raw_argv):
            argv = list(raw_argv)
    return {"kind": "command_event", "event": event, "argv": argv,
            "authentic_subprocess_popen": authentic_popen,
            "preexec_verified_none": preexec_verified_none,
            "actual_executable_is_bash": actual_executable_is_bash,
            "captured_cwd": captured_cwd,
            "env_has_probe": env_has_probe, "shell_env_keys": sorted(env_keys),
            "frames": frames, "candidate_frame": candidate, "emitter_frame": emitter}


def _verify_module_sources(manifest: WitnessManifest, checkout: Path) -> list[str]:
    gaps: list[str] = []
    bindings = {item.module_name: item for item in manifest.source_modules}
    root_name = manifest.module_name.split(".", 1)[0]
    for binding in manifest.source_modules:
        module = sys.modules.get(binding.module_name)
        if module is None and binding.module_name not in {
            manifest.module_name, root_name,
        }:
            # A helper may be imported by the candidate only during invocation.
            # Its checkout source and digest are verified at the command event.
            continue
        source = getattr(module, "__file__", None)
        expected = checkout / binding.relative_path
        if not source or not _inside(Path(source), checkout):
            gaps.append(f"module_outside_checkout:{binding.module_name}")
        elif Path(source).resolve() != expected.resolve() or _sha256(Path(source)) != binding.sha256:
            gaps.append(f"module_source_mismatch:{binding.module_name}")
    for name, module in tuple(sys.modules.items()):
        source = getattr(module, "__file__", None)
        if not source:
            continue
        path = Path(source)
        if name == root_name or name.startswith(root_name + "."):
            if not _inside(path, checkout):
                gaps.append(f"target_package_outside_checkout:{name}")
        if not _inside(path, checkout):
            continue
        binding = bindings.get(name)
        if binding is None:
            gaps.append(f"undeclared_imported_source:{name}")
        elif path.resolve() != (checkout / binding.relative_path).resolve():
            gaps.append(f"module_source_mismatch:{name}")
        elif _sha256(path) != binding.sha256:
            gaps.append(f"module_source_mismatch:{name}")
    return gaps


def _worker(manifest: WitnessManifest, result_fd: int, runtime: Path,
            probe_path: Path, read_grants: tuple[IsolationReadGrant, ...] = (),
            record_open_attempts: bool = False, stack_result_fd: int | None = None,
            worker_deadline: float | None = None, verify_obligations: bool = False) -> None:
    interpreter = _interpreter_identity(manifest.python_executable)
    phase = "preflight"
    open_attempts: list[dict[str, Any]] = []
    open_attempt_count = 0
    read_roots: tuple[Path, ...] = ()
    applied_limits: dict[str, tuple[int, int]] | None = None
    values = branches = scenario_data = None
    pending_command: dict[str, Any] | None = None
    pending_preexec: list[Any] = []
    verifier_active = False
    captured_command_unwound = False
    concurrent_command_events: list[str] = []

    def resource_record() -> dict[str, Any]:
        return {"target_pid": os.getpid(), "target_self_usage": self_usage(),
                "resource_profile": manifest.resource_profile.model_dump(mode="json"),
                "applied_resource_limits": applied_limits,
                "current_resource_limits": manifest.resource_profile.actual_limits()}

    def emit(payload: dict[str, Any]) -> None:
        payload.update(resource_record())
        if record_open_attempts:
            payload.update(phase=phase, open_attempts=open_attempts,
                           open_attempt_count=open_attempt_count,
                           attempts_truncated=open_attempt_count > len(open_attempts),
                           isolation_read_roots=[str(path) for path in read_roots])
        _write_result(result_fd, payload)

    def progress() -> None:
        if (record_open_attempts or stack_result_fd is not None
                or manifest.resource_profile.name != "fixture_default"):
            _write_result(result_fd, {"kind": "progress", "phase": phase,
                                      "isolation_read_roots": [str(path) for path in read_roots],
                                      "interpreter": interpreter, **resource_record()})

    try:
        if not interpreter["matches_manifest"]:
            _write_result(result_fd, {"kind": "error", "gap": "worker_interpreter_mismatch",
                                      "interpreter": interpreter})
            return
        checkout = manifest.checkout_root.resolve(strict=True)
        if verify_obligations:
            from cv_agent.runtime.witness.obligations.values import ValueAssumptionObserver
            from cv_agent.runtime.witness.obligations.branches import BranchAssumptionObserver
            from cv_agent.runtime.witness.scenario_runtime import ScenarioDataObserver
            values = ValueAssumptionObserver(manifest)
            branches = BranchAssumptionObserver(manifest)
            scenario_data = ScenarioDataObserver(manifest, probe_path)
        progress()
        for binding in manifest.source_modules:
            source = checkout / binding.relative_path
            if not _inside(source, checkout) or _sha256(source) != binding.sha256:
                _write_result(result_fd, {"kind": "error", "gap": "source_mismatch",
                                          "module": binding.module_name,
                                          "interpreter": interpreter})
                return
        for grant in read_grants:
            if not grant.is_current():
                emit({"kind": "error", "gap": f"isolation_read_grant_stale:{grant.path}",
                      "interpreter": interpreter})
                return
        if manifest.resource_profile.name == "fixture_default":
            _apply_fixture_limits()
        else:
            # Keep SIGXCPU blocked in the target and all subsequently created
            # threads. The trusted waiter receives siginfo without depending on
            # a Python signal handler returning from a long C extension call.
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGXCPU})

            def watch_cpu_limit() -> None:
                info = signal.sigwaitinfo({signal.SIGXCPU})
                if info is None:
                    return
                # SI_KERNEL is 0x80 in Linux asm-generic/siginfo.h. User-sent
                # SIGXCPU must not be described as resource exhaustion.
                gap = ("cpu_limit_exceeded" if info.si_code == 0x80
                       else "target_signal:SIGXCPU")
                emit({"kind": "error", "gap": gap, "phase": phase,
                      "cpu_limit_signal": {"signal": "SIGXCPU", "si_code": info.si_code,
                                           "si_pid": info.si_pid, "si_uid": info.si_uid},
                      "interpreter": interpreter})
                os._exit(0)

            manifest.resource_profile.apply()
        applied_limits = manifest.resource_profile.actual_limits()
        _install_fixture_isolation(result_fd, deny_exec=True,
                                   retained_fds=(stack_result_fd,) if stack_result_fd is not None else ())
        # _install_fixture_isolation performs an actual execve/execveat EPERM
        # self-test before returning. The audit hook is installed afterward.
        read_roots = (*_read_roots(checkout, runtime), *(grant.path for grant in read_grants))
        restrict_fixture_filesystem(read_roots)
        if manifest.resource_profile.name != "fixture_default":
            # Created after both restrictions: the trusted monitor inherits
            # the same seccomp and Landlock policy as target-created threads.
            threading.Thread(target=watch_cpu_limit, name="witness-cpu-limit",
                             daemon=True).start()
        if stack_result_fd is not None:
            assert worker_deadline is not None
            faulthandler.dump_traceback_later(
                max(0.01, worker_deadline - time.monotonic() - _STACK_TIMEOUT_MARGIN),
                repeat=False, file=stack_result_fd, exit=False,
            )
        selftest_seen = False
        phase = "import"
        expected_code: Any = None
        expected_globals: dict[str, Any] | None = None
        trusted_popen_codes = (subprocess.Popen._execute_child.__code__,
                               subprocess.Popen.__init__.__code__)
        recording_command = False
        recording_thread: int | None = None
        worker_pid = os.getpid()

        def audit(event: str, args: tuple[Any, ...]) -> None:
            nonlocal selftest_seen, open_attempt_count, recording_command, recording_thread
            nonlocal pending_command, pending_preexec
            if branches is not None:
                branches.audit_event(event, args)
            if event == "cv_agent.witness.hook_selftest":
                selftest_seen = True
                return
            if event == "open" and record_open_attempts and not recording_command:
                # Audit events precede syscalls and do not establish denial. No
                # source hashing/path I/O here: that would recursively audit open.
                open_attempt_count += 1
                path = args[0] if args else None
                if isinstance(path, bytes):
                    path = os.fsdecode(path)
                if not isinstance(path, (str, int, type(None))):
                    path = "unsupported_path_object"
                frames = []
                frame = sys._getframe(1)
                for _ in range(4):
                    if frame is None:
                        break
                    frames.append({"file": frame.f_code.co_filename,
                                   "line": frame.f_lineno,
                                   "qualname": frame.f_code.co_qualname})
                    frame = frame.f_back
                open_attempts.append({"path": path, "phase": phase,
                                      "flags": args[2] if len(args) > 2 and
                                      isinstance(args[2], int) else None,
                                      "thread": __import__("_thread").get_ident(),
                                      "frames": frames})
                del open_attempts[:-32]
                return
            if event not in _COMMAND_EVENTS:
                return
            if recording_command:
                # The trusted verifier fork and its child have their own hook.
                # A target thread attempting a command concurrently cannot
                # silently borrow the completed candidate's first event.
                if os.getpid() == worker_pid and threading.get_ident() != recording_thread:
                    concurrent_command_events.append(event)
                    raise RuntimeError("concurrent target command during witness capture")
                if verifier_active and (os.getpid() != worker_pid or event == 'os.fork'):
                    return
                concurrent_command_events.append(event)
                raise _CapturedCommand()
            recording_command = True
            recording_thread = threading.get_ident()
            preexec_capture: list[Any] = []
            payload = _capture_event(event, args, checkout, manifest, expected_code,
                                     trusted_popen_codes, preexec_capture,
                                     expected_globals=expected_globals)
            payload["loaded_source_gaps"] = _verify_module_sources(manifest, checkout)
            payload["phase"] = phase
            payload["entry_adapter"] = {
                "invocation": manifest.entry_invocation,
                "public_parser_executed": False,
                "scope": ("direct_click_callback" if manifest.entry_invocation == "click_callback"
                          else "direct_source_entry"),
            }
            payload["seccomp_selftest"] = True
            payload["hook_selftest"] = selftest_seen
            payload["interpreter"] = interpreter
            if verify_obligations:
                assert values is not None and branches is not None
                values.verify_module_values()
                value_record = values.result()
                condition_record = branches.report()
                scenario_record = scenario_data.report()
                branches.close()
                boolean_gaps = [gap for gap in _assumption_gaps(manifest)
                                if gap.startswith("entry_boolean_argument_unverified:")]
                payload["assumption_verification"] = {
                    "enabled": True, "values": value_record, "conditions": condition_record,
                    "scenario_data": scenario_record,
                    "gaps": list(dict.fromkeys([*boolean_gaps, *value_record["gaps"],
                                                *condition_record["gaps"], *scenario_record["gaps"]])),
                    "environment": {"sys_platform": sys.platform, "os_name": os.name},
                }
                pending_command = payload
                pending_preexec = preexec_capture
                # Profile/trace callbacks are inhibited inside an audit hook.
                # A fork here would inherit that inhibition. Abort Popen and
                # unwind this callback before measuring the actual callable.
                raise _CapturedCommand()
            emit(payload)
            os._exit(0)

        sys.addaudithook(audit)
        sys.audit("cv_agent.witness.hook_selftest")
        if not selftest_seen:
            emit({"kind": "error", "gap": "hook_selftest_failed",
                                      "interpreter": interpreter})
            return
        # Capture the trusted framework type before target imports can shadow
        # its module or rebind its exported class. This import is worker-only.
        trusted_click_command = None
        if manifest.entry_invocation == "click_callback":
            import click.core
            trusted_click_command = click.core.Command
        entry_file = (checkout / manifest.entry_relative_path).resolve(strict=True)
        entry_template = None
        pending_template_error = None
        try:
            entry_template = source_entry_code(entry_file.read_bytes(), entry_file,
                                               manifest.entry_qualified_name,
                                               manifest.entry_first_line)
        except ValueError as error:
            if str(error) != "entry_source_code_nonunique":
                raise
            # The compiler removes definitions after an unconditional raise.
            # Preserve the genuine import error under isolation; a successful
            # import still cannot qualify or invoke a missing source template.
            pending_template_error = str(error)
        source_import_root = (checkout / manifest.import_root).resolve(strict=True)
        if not source_import_root.is_relative_to(checkout) or not source_import_root.is_dir():
            emit({'kind': 'error', 'gap': 'source_import_root_outside_checkout'})
            return
        sys.path.insert(0, str(source_import_root))
        import importlib
        progress()
        module = importlib.import_module(manifest.module_name)
        source_gaps = _verify_module_sources(manifest, checkout)
        if source_gaps:
            emit({"kind": "error", "gap": "source_mismatch",
                                      "source_gaps": source_gaps,
                                      "interpreter": interpreter})
            return
        if pending_template_error is not None:
            emit({"kind": "error", "gap": pending_template_error, "interpreter": interpreter})
            return
        assert entry_template is not None
        expected_globals = module_dictionary(module)
        try:
            if manifest.entry_invocation == "instance_method":
                target_class = expected_globals.get(manifest.class_name)
                function = qualified_function(class_dictionary(target_class).get(manifest.method_name),
                                              expected_globals, entry_template)
                phase = "construct"
                progress()
                if scenario_data is not None:
                    scenario_data.observe_constructor(manifest.constructor_args, manifest.constructor_kwargs)
                target = target_class(*manifest.constructor_args, **manifest.constructor_kwargs)
                entry_call = bound_instance_method(target, manifest.method_name, function)
            elif manifest.entry_invocation == "click_callback":
                function = click_callback(expected_globals.get(manifest.method_name),
                                          trusted_click_command, expected_globals, entry_template)
                entry_call = function
            else:
                function = qualified_function(expected_globals.get(manifest.method_name),
                                              expected_globals, entry_template)
                entry_call = function
            expected_code = function.__code__
        except ValueError as error:
            emit({"kind": "error", "gap": str(error), "interpreter": interpreter})
            return
        call_kwargs = dict(manifest.call_kwargs)
        call_kwargs[manifest.probe_argument] = str(probe_path)
        phase = "invoke"
        progress()
        if verify_obligations:
            assert values is not None and branches is not None
            def observe_entry(frame: Any) -> None:
                values.observe_entry(frame)
                values.verify_module_values()
                scenario_data.observe_entry(frame)
            branches.install(expected_code, on_entry=observe_entry)
        entry_call(*manifest.call_args, **call_kwargs)
        emit({"kind": "no_event", "seccomp_selftest": True,
                                  "hook_selftest": True, "source_verified": True,
                                  "interpreter": interpreter})
    except _CapturedCommand:
        captured_command_unwound = True
    except BaseException as error:
        emit({"kind": "error", "gap": "target_or_isolation_error",
                                  "error": f"{type(error).__name__}: {error}",
                                  "error_filename": error.filename if isinstance(error, OSError) else None,
                                  "error_errno": error.errno if isinstance(error, OSError) else None,
                                  "interpreter": interpreter})
    finally:
        if branches is not None:
            branches.close()
        if captured_command_unwound:
            # The handled capture exception has now left sys.exception().
            # Inheriting that synthetic exception would change the real
            # callable's behavior and can manufacture a false confirmation.
            if pending_command is None:
                emit({'kind': 'error', 'gap': 'command_capture_missing', 'phase': phase})
            else:
                from cv_agent.runtime.witness.obligations.preexec import verify_preexec
                verifier_active = True
                try:
                    if (pending_command['authentic_subprocess_popen'] and len(pending_preexec) == 2
                            and pending_preexec[0] is pending_preexec[1]):
                        pending_command['preexec_verification'] = verify_preexec(
                            pending_preexec[0], verify_sources=lambda: _verify_module_sources(manifest, checkout),
                        )
                    else:
                        pending_command['preexec_verification'] = {'ok': False, 'gap': 'preexec_capture_mismatch'}
                finally:
                    verifier_active = False
                pending_command['concurrent_command_events'] = list(concurrent_command_events)
                emit(pending_command)
        if stack_result_fd is not None:
            faulthandler.cancel_dump_traceback_later()
        os._exit(0)


def _run_worker(manifest: WitnessManifest, runtime: Path, probe_path: Path,
                read_grants: tuple[IsolationReadGrant, ...] = (),
                trace_path: Path | None = None, stack_capture: bool = False,
                verify_obligations: bool = False) -> dict[str, Any]:
    read_fd, write_fd = os.pipe()
    stack_read_fd, stack_write_fd = os.pipe() if stack_capture else (-1, -1)
    if stack_capture:
        os.set_blocking(stack_read_fd, False)
    stack_bytes = bytearray()
    stack_byte_count = 0
    stack_eof = False
    manifest_path: Path | None = None
    process: subprocess.Popen | None = None
    top_sampler: ProcessResourceSampler | None = None
    target_sampler: ProcessResourceSampler | None = None
    observed: dict[str, Any] = {}
    final: dict[str, Any] | None = None
    pending = b""
    parent_kill_reason: str | None = None
    deadline = time.monotonic() + manifest.resource_profile.wall_seconds

    def kill_group() -> None:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                # The group can vanish between an observation and cleanup.
                # This does not erase its last phase or the parent's reason.
                pass

    def sample() -> None:
        if top_sampler is not None:
            top_sampler.sample()
        if target_sampler is not None and target_sampler is not top_sampler:
            target_sampler.sample()

    def drain_stacks() -> None:
        nonlocal stack_byte_count, stack_eof
        if not stack_capture or stack_eof:
            return
        # Continue draining after the saved-byte limit so the native watchdog
        # cannot block on a full pipe. Bound each turn's work as well.
        for _ in range(32):
            try:
                chunk = os.read(stack_read_fd, 16_384)
            except BlockingIOError:
                break
            if not chunk:
                stack_eof = True
                break
            stack_byte_count += len(chunk)
            space = max(0, _STACK_LIMIT - len(stack_bytes))
            stack_bytes.extend(chunk[:space])

    def consume(chunk: bytes) -> None:
        nonlocal pending, observed, final, target_sampler
        pending += chunk
        while b"\n" in pending:
            line, pending = pending.split(b"\n", 1)
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError("worker message must be an object")
            if payload.get("kind") == "progress":
                observed = payload
            else:
                final = payload
            pid = payload.get("target_pid")
            if target_sampler is None and type(pid) is int and pid > 0:
                target_sampler = ProcessResourceSampler(pid)
            sample()

    def finish(outcome: dict[str, Any], kill_reason: str | None = None) -> dict[str, Any]:
        """Keep observations and read the launcher's own CPU before reaping."""
        nonlocal parent_kill_reason
        parent_kill_reason = kill_reason
        if process is not None:
            if kill_reason is not None:
                kill_group()
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                sample()
                drain_stacks()
                if time.monotonic() >= deadline and parent_kill_reason is None:
                    parent_kill_reason = "wall_timeout_after_result"
                    kill_group()
                time.sleep(0.01)
            if top_sampler is not None:
                top_sampler.finish_unreaped()
            process.wait()
        drain_stacks()
        result = {**observed, **outcome}
        if process is not None:
            result["returncode"] = process.returncode
            if result.get("gap") == "worker_missing_or_invalid_result" and process.returncode < 0:
                result["gap"] = f"worker_terminated:{signal.Signals(-process.returncode).name}"
            if process.returncode != 0 and final is not None and outcome.get("kind") != "error":
                # A delivered command record does not waive a failed worker.
                # Preserve it for diagnostics while restoring the proof gate.
                result["incomplete_result"] = outcome
                result["kind"] = "error"
                result["gap"] = (f"worker_terminated:{signal.Signals(-process.returncode).name}"
                                 if process.returncode < 0 else "worker_nonzero_exit")
        if parent_kill_reason is not None:
            result["parent_kill_reason"] = parent_kill_reason
        if target_sampler is not None:
            target = target_sampler.summary()
            target["self_reported_usage"] = result.get("target_self_usage")
            target["self_report_is_final"] = final is not None and outcome is final
        else:
            target = None
        result["resource_accounting"] = {
            "target": target,
            "tracer": top_sampler.summary() if trace_path is not None and top_sampler else None,
        }
        if stack_capture:
            result["stack_dump"] = {
                "enabled": True, "timeout_margin_seconds": _STACK_TIMEOUT_MARGIN,
                "text": stack_bytes.decode("utf-8", errors="replace"),
                "byte_count": stack_byte_count, "limit_bytes": _STACK_LIMIT,
                "truncated": stack_byte_count > _STACK_LIMIT,
            }
        return result

    try:
        manifest_bytes = json.dumps({
            "manifest": manifest.model_dump(mode="json"),
            "read_grants": [grant.model_dump(mode="json") for grant in read_grants],
            "record_open_attempts": trace_path is not None,
            "stack_result_fd": stack_write_fd if stack_capture else None,
            "worker_deadline": deadline if stack_capture else None,
            "verify_obligations": verify_obligations,
        }, sort_keys=True).encode("utf-8")
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        manifest_fd, raw_manifest_path = tempfile.mkstemp(
            prefix="witness-manifest-", suffix=".json", dir=runtime,
        )
        manifest_path = Path(raw_manifest_path)
        with os.fdopen(manifest_fd, "wb") as stream:
            stream.write(manifest_bytes)
        cache_prefix = Path(tempfile.mkdtemp(prefix="witness-pycache-", dir=runtime))
        python = manifest.python_executable or Path(sys.executable)
        command = [str(python), "-m", __name__, "--worker", str(write_fd),
                   str(runtime), str(probe_path), str(manifest_path), manifest_digest]
        if trace_path is not None:
            from cv_agent.runtime.witness.tracer import trace_command
            command = trace_command(command, trace_path)
        environment = {"PATH": _worker_path(manifest.python_executable),
                       "LC_ALL": "C", "LANG": "C",
                       "PYTHONDONTWRITEBYTECODE": "1",
                       "PYTHONPYCACHEPREFIX": str(cache_prefix),
                       "PYTHONPATH": str(Path(__file__).resolve().parents[3])}
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL,
                                   pass_fds=(write_fd, stack_write_fd) if stack_capture else (write_fd,),
                                   env=environment, cwd=runtime, start_new_session=True)
        top_sampler = ProcessResourceSampler(process.pid)
        if trace_path is None:
            target_sampler = top_sampler
        sample()
        os.close(write_fd)
        write_fd = -1
        if stack_capture:
            os.close(stack_write_fd)
            stack_write_fd = -1
        chunks: list[bytes] = []
        size = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return finish({"kind": "error", "gap": "worker_timeout"}, "wall_timeout")
            if trace_path is not None and trace_path.stat().st_size > _TRACE_LIMIT:
                return finish({"kind": "error", "gap": "read_trace_too_large"}, "trace_size_limit")
            sample()
            ready, _, _ = select.select([read_fd, stack_read_fd] if stack_capture and not stack_eof else [read_fd],
                                        [], [], min(remaining, 0.01))
            if not ready:
                continue
            drain_stacks()
            if read_fd not in ready:
                continue
            chunk = os.read(read_fd, 16_384)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _RESULT_LIMIT:
                return finish({"kind": "error", "gap": "worker_result_too_large"}, "result_size_limit")
            try:
                consume(chunk)
            except (ValueError, json.JSONDecodeError) as error:
                return finish({"kind": "error", "gap": "worker_invalid_json",
                               "error": str(error)}, "invalid_result")
        if pending:
            return finish({"kind": "error", "gap": "worker_invalid_json"})
        if final is None:
            return finish({"kind": "error", "gap": "worker_missing_or_invalid_result"})
        return finish(final)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return finish({"kind": "error", "gap": "worker_launch_error",
                       "error": f"{type(error).__name__}: {error}"},
                      "launcher_error" if process is not None else None)
    finally:
        if process is not None and process.poll() is None:
            kill_group()
            process.wait()
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
        if stack_read_fd >= 0:
            os.close(stack_read_fd)
        if stack_write_fd >= 0:
            os.close(stack_write_fd)
        if manifest_path is not None:
            manifest_path.unlink(missing_ok=True)


def _verified_bash_command(argv: Any, bash_path: Path,
                           python_executable: Path | None = None) -> str | None:
    if (not isinstance(argv, list) or len(argv) != 3
            or argv[1] != "-c" or not all(isinstance(x, str) for x in argv)):
        return None
    executable = argv[0]
    if executable not in {"bash", "sh"} and not Path(executable).is_absolute():
        return None
    resolved = (shutil.which(executable, path=_worker_path(python_executable))
                if not Path(executable).is_absolute() else executable)
    if resolved is None:
        return None
    try:
        if Path(resolved).resolve(strict=True) != bash_path.resolve(strict=True):
            return None
    except OSError:
        return None
    return argv[2]


def _simple_recorder_command(command: str, manifest: WitnessManifest,
                             probe_path: Path) -> bool:
    """Accept only a direct CLI call; shell control syntax outside the probe is U.

    Replay changes PATH to substitute the recorder, so any conditional or
    pipeline could behave differently from the captured worker environment.
    A narrow exact form avoids treating that different branch as a witness.
    """
    prefix = " ".join((manifest.recorder_command, *manifest.recorder_arguments))
    argument = str(probe_path)
    return command in {
        f"{prefix} {argument}",
        f"{prefix} {shlex.quote(argument)}",
        f"exec {prefix} {argument}",
        f"exec {prefix} {shlex.quote(argument)}",
    }


def _recorder_from_boundary(command: str, manifest: WitnessManifest,
                            probe_path: Path) -> WitnessManifest | None:
    """Select a recorder only from an exact direct command containing our path."""
    for argument in (str(probe_path), shlex.quote(str(probe_path))):
        suffix = ' ' + argument
        if not command.endswith(suffix):
            continue
        prefix = command[:-len(suffix)]
        if prefix.startswith('exec '):
            prefix = prefix[5:]
        words = prefix.split(' ')
        if (not words or not _COMMAND_NAME.fullmatch(words[0])
                or any(not re.fullmatch(r'[A-Za-z0-9._-]+', word) for word in words[1:])):
            continue
        selected = WitnessManifest.model_validate({
            **manifest.model_dump(mode='json'),
            'recorder_command': words[0], 'recorder_arguments': words[1:],
        })
        if _simple_recorder_command(command, selected, probe_path):
            return selected
    return None


def _bound_emitter(event: dict[str, Any], manifest: WitnessManifest,
                   checkout: Path) -> bool:
    emitter = event.get("emitter_frame")
    if not isinstance(emitter, dict) or not emitter.get("in_checkout") or not emitter.get("sha256"):
        return False
    return any(
        item.module_name == emitter.get("module_name")
        and str((checkout / item.relative_path).resolve()) == emitter.get("file")
        and item.sha256 == emitter.get("sha256")
        for item in manifest.source_modules
    )


def _replay(command: str, manifest: WitnessManifest, runtime: Path) -> dict[str, Any]:
    recorder_dir = runtime / "recorder_bin"
    if recorder_dir.is_symlink():
        return {"ok": False, "gap": "recorder_directory_is_symlink"}
    if not recorder_dir.exists():
        recorder_dir.mkdir()
    if not recorder_dir.is_dir():
        return {"ok": False, "gap": "recorder_directory_invalid"}
    recorder = recorder_dir / manifest.recorder_command
    if recorder.is_symlink():
        return {"ok": False, "gap": "recorder_is_symlink"}
    if recorder.exists() and not recorder.is_file():
        return {"ok": False, "gap": "recorder_path_invalid"}
    receipt = uuid4().hex
    recorder.write_text(
        "#!/bin/bash\n"
        f"printf '{receipt}\\0'\n"
        "printf '%s\\0' \"$@\"\n"
    )
    recorder.chmod(0o755)
    bash_path = manifest.bash_path.resolve(strict=True)
    if len(command.encode("utf-8")) > 2_048:
        return {"ok": False, "gap": "bash_command_too_large"}
    try:
        python = manifest.python_executable or Path(sys.executable)
        cache_prefix = Path(tempfile.mkdtemp(prefix="replay-pycache-", dir=runtime))
        process = subprocess.Popen(
            [str(python), "-m", __name__, "--replay-worker", str(runtime),
             str(manifest.checkout_root.resolve()), str(bash_path), str(recorder),
             str(manifest.python_executable) if manifest.python_executable else ""],
            cwd=runtime,
            env={"PATH": _worker_path(manifest.python_executable), "LC_ALL": "C",
                 "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1",
                 "PYTHONPYCACHEPREFIX": str(cache_prefix),
                 "PYTHONPATH": str(Path(__file__).resolve().parents[3])},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(command.encode("utf-8"))
        process.stdin.close()
        output_parts: list[bytes] = []
        output_size = 0
        deadline = time.monotonic() + _REPLAY_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                return {"ok": False, "gap": "bash_replay_timeout"}
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            if not ready:
                continue
            part = os.read(process.stdout.fileno(), 4096)
            if not part:
                break
            output_parts.append(part)
            output_size += len(part)
            if output_size > 16_384:
                process.kill()
                process.wait()
                return {"ok": False, "gap": "bash_replay_output_too_large"}
        try:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            return {"ok": False, "gap": "bash_replay_timeout_after_output"}
        output = b"".join(output_parts)
    except (OSError, ValueError, subprocess.TimeoutExpired, subprocess.SubprocessError) as error:
        return {"ok": False, "gap": "bash_replay_failed",
                "error": f"{type(error).__name__}: {error}"}
    prefix = receipt.encode() + b"\0"
    if output.startswith(b"replay_interpreter_mismatch"):
        return {"ok": False, "gap": "replay_interpreter_mismatch",
                "returncode": process.returncode}
    if process.returncode != 0 or not output.startswith(prefix):
        return {"ok": False, "gap": "bash_replay_failed",
                "returncode": process.returncode, "stdout_prefix": output[:100].decode(errors="replace")}
    parts = output[len(prefix):].split(b"\0")
    if parts[-1] != b"":
        return {"ok": False, "gap": "recorder_output_malformed"}
    try:
        arguments = [part.decode("utf-8") for part in parts[:-1]]
    except UnicodeDecodeError:
        return {"ok": False, "gap": "recorder_output_malformed"}
    return {"ok": True, "arguments": arguments, "returncode": process.returncode}


def _replay_worker(runtime: Path, checkout: Path, bash_path: Path, recorder: Path,
                   command: str, expected_python: Path | None) -> None:
    if not _interpreter_identity(expected_python)["matches_manifest"]:
        os.write(1, b"replay_interpreter_mismatch")
        os._exit(126)
    try:
        loader = {
            "x86_64": Path("/lib64/ld-linux-x86-64.so.2"),
            "aarch64": Path("/lib/ld-linux-aarch64.so.1"),
        }[platform.machine()]
        _apply_fixture_limits()
        _install_fixture_isolation(1, deny_exec=False)
        restrict_fixture_filesystem(
            _read_roots(checkout, runtime),
            executable_paths=(bash_path, loader, recorder),
        )
        os.execve(str(bash_path), [str(bash_path), "--noprofile", "--norc", "-c", command],
                  {"PATH": str(recorder.parent), "LC_ALL": "C", "LANG": "C"})
    except BaseException as error:
        os.write(1, f"replay_worker_error:{type(error).__name__}:{error}".encode()[:300])
        os._exit(125)


def _prepare_input(runtime: Path, manifest: WitnessManifest, nonce: str,
                   *, malicious: bool) -> tuple[Path, dict[str, str]]:
    suffix = f"$(printf {nonce})" if malicious else nonce
    path = runtime / f"{manifest.probe_directory_prefix}{suffix}"
    if path.is_symlink():
        raise ValueError("probe directory cannot be a symlink")
    path.mkdir(exist_ok=True)
    if not path.is_dir():
        raise ValueError("probe path is not a directory")
    hashes: dict[str, str] = {}
    for relative, content in manifest.precondition_files.items():
        target = path / relative
        parent_part = path
        for component in Path(relative).parts[:-1]:
            parent_part /= component
            if parent_part.is_symlink():
                raise ValueError("probe precondition parent cannot be a symlink")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            raise ValueError("probe precondition cannot be a symlink")
        if target.exists():
            if not target.is_file() or target.read_text() != content:
                raise ValueError("existing probe precondition differs from the manifest")
        else:
            target.write_text(content)
        hashes[relative] = _sha256(target)
    expected_directories = {Path(".")}
    for relative in manifest.precondition_files:
        parent = Path(relative).parent
        while parent != Path("."):
            expected_directories.add(parent)
            parent = parent.parent
    for item in path.rglob("*"):
        relative = item.relative_to(path)
        if item.is_symlink():
            raise ValueError("probe preconditions cannot contain symlinks")
        if item.is_dir() and relative not in expected_directories:
            raise ValueError("probe directory has undeclared content")
        if item.is_file() and relative.as_posix() not in manifest.precondition_files:
            raise ValueError("probe directory has undeclared content")
    return path, hashes


def _diagnostic_result(
    manifest: WitnessManifest,
    checkout: Path,
    runtime: Path,
    probe_path: Path,
    event: dict[str, Any],
    assumption_gaps: tuple[str, ...],
    details: dict[str, Any],
) -> WitnessResult:
    """Keep measuring after proof gaps while making candidate proof impossible."""
    gaps = list(assumption_gaps)
    gaps.extend(event.get("read_diagnostics", {}).get("gaps", []))
    gaps.extend(item["gap"] for item in
                event.get("read_diagnostics", {}).get("read_denials", []))
    details["diagnostic_only"] = True
    observed_popen_event = (
        event.get("kind") == "command_event"
        and event.get("event") == "subprocess.Popen"
        and event.get("authentic_subprocess_popen") is True
    )
    details["observed_popen_event"] = observed_popen_event
    details["reached_popen"] = (
        observed_popen_event
        and event.get("phase") == "invoke"
        and event.get("candidate_frame") is not None
        and _bound_emitter(event, manifest, checkout)
        and not event.get("loaded_source_gaps")
    )
    if event.get("kind") != "command_event":
        gaps.append(event.get("gap", "command_boundary_not_reached"))
    else:
        if event.get("phase") != "invoke":
            gaps.append("import_time_command_event" if event.get("phase") == "import"
                        else "event_outside_candidate_entry")
        if event.get("candidate_frame") is None:
            gaps.append("event_outside_candidate_frame")
        if not _bound_emitter(event, manifest, checkout):
            gaps.append("emitter_source_not_bound")
        if event.get("loaded_source_gaps"):
            gaps.extend(event["loaded_source_gaps"])
        if not event.get("seccomp_selftest") or not event.get("hook_selftest"):
            gaps.append("isolation_selftest_failed")
        if not event.get("authentic_subprocess_popen"):
            gaps.append("audit_event_not_authenticated")
        if not event.get("preexec_verified_none"):
            gaps.append("preexec_not_verified")
        if not event.get("actual_executable_is_bash"):
            gaps.append("actual_executable_not_verified_bash")
        if event.get("captured_cwd") is not None:
            gaps.append("captured_cwd_not_replayed")
        if event.get("shell_env_keys"):
            gaps.append("captured_shell_environment_not_replayed")
        argv = event.get("argv")
        marker = f"$(printf {details['probe_nonce']})"
        if not isinstance(argv, list) or not any(marker in part for part in argv):
            gaps.append("probe_not_in_argv" if event.get("env_has_probe")
                        else "preempted_by_unrelated_command_event")
        if (details["reached_popen"] and event.get("actual_executable_is_bash")
                and event.get("captured_cwd") is None and not event.get("shell_env_keys")):
            command = _verified_bash_command(
                argv, manifest.bash_path, manifest.python_executable,
            )
            if command is None:
                gaps.append("unsupported_shell_argv")
            elif not _simple_recorder_command(command, manifest, probe_path):
                gaps.append("unsupported_shell_command_shape")
            else:
                replay = _replay(command, manifest, runtime)
                details["probe_replay"] = replay
                if not replay.get("ok"):
                    gaps.append(replay.get("gap", "bash_replay_failed"))
    return WitnessResult(
        status=ValidationStatus.UNRESOLVED,
        raw_status="UNRESOLVED",
        gaps=tuple(dict.fromkeys(gaps)),
        details=details,
    )


def _verification_result(
    manifest: WitnessManifest, checkout: Path, runtime: Path, probe_path: Path,
    control_path: Path, event: dict[str, Any], assumption_gaps: tuple[str, ...],
    details: dict[str, Any], read_grants: tuple[IsolationReadGrant, ...],
    trace_path: Path | None, stack_capture: bool,
    derive_recorder: bool = False,
) -> WitnessResult:
    """Require complete runtime obligations on the probe and its benign control."""
    gaps: list[str] = []
    details['verification_mode'] = True
    details['diagnostic_only'] = False
    details['reached_popen'] = (
        event.get('kind') == 'command_event' and event.get('event') == 'subprocess.Popen'
        and event.get('phase') == 'invoke' and event.get('candidate_frame') is not None
        and event.get('authentic_subprocess_popen') is True
        and _bound_emitter(event, manifest, checkout) and not event.get('loaded_source_gaps')
    )
    if derive_recorder:
        details['recorder_derivation_enabled'] = True
        if not details['reached_popen']:
            return _unresolved(event.get('gap', 'recorder_boundary_not_qualified'), details=details)
        command = _verified_bash_command(event.get('argv'), manifest.bash_path, manifest.python_executable)
        selected = _recorder_from_boundary(command, manifest, probe_path) if command is not None else None
        if selected is None:
            return _unresolved('recorder_prefix_not_established', details=details)
        manifest = selected
        details['derived_recorder'] = {
            'command': manifest.recorder_command, 'arguments': list(manifest.recorder_arguments),
        }

    def measure(record: dict[str, Any], path: Path, *, control: bool) -> dict[str, Any] | None:
        event_gaps: list[str] = []
        boundary_gaps: list[str] = []
        if record.get('kind') != 'command_event':
            boundary_gaps.append(record.get('gap', 'command_boundary_not_reached'))
        if record.get('phase') != 'invoke' or record.get('candidate_frame') is None:
            boundary_gaps.append('event_outside_candidate_frame')
        if not _bound_emitter(record, manifest, checkout):
            boundary_gaps.append('emitter_source_not_bound')
        if not record.get('authentic_subprocess_popen'):
            boundary_gaps.append('audit_event_not_authenticated')
        if record.get('event') != 'subprocess.Popen':
            boundary_gaps.append('unsupported_command_event')
        if not record.get('seccomp_selftest') or not record.get('hook_selftest'):
            boundary_gaps.append('isolation_selftest_failed')
        boundary_gaps.extend(record.get('loaded_source_gaps', []))
        if not record.get('actual_executable_is_bash'):
            boundary_gaps.append('actual_executable_not_verified_bash')
        if record.get('captured_cwd') is not None:
            boundary_gaps.append('captured_cwd_not_replayed')
        if record.get('shell_env_keys'):
            boundary_gaps.append('captured_shell_environment_not_replayed')
        if record.get('concurrent_command_events'):
            boundary_gaps.append('concurrent_target_command_event')
        event_gaps.extend(boundary_gaps)
        assumptions = record.get('assumption_verification', {})
        if assumptions.get('enabled') is not True:
            event_gaps.extend(assumption_gaps)
            event_gaps.append('runtime_assumption_verification_missing')
        else:
            event_gaps.extend(assumptions.get('gaps', []))
        preexec = record.get('preexec_verification', {})
        if preexec.get('ok') is not True:
            event_gaps.append('preexec_not_verified')
            event_gaps.append(preexec.get('gap', 'preexec_verification_missing'))
            event_gaps.extend(preexec.get('source_gaps', []))
        argv = record.get('argv')
        if not control:
            marker = f"$(printf {details['probe_nonce']})"
            if not isinstance(argv, list) or not any(marker in part for part in argv):
                event_gaps.append('probe_not_in_argv' if record.get('env_has_probe')
                                  else 'preempted_by_unrelated_command_event')
        replay = None
        if not boundary_gaps:
            command = _verified_bash_command(argv, manifest.bash_path, manifest.python_executable)
            if command is None:
                event_gaps.append('unsupported_shell_argv')
            elif not _simple_recorder_command(command, manifest, path):
                event_gaps.append('unsupported_shell_command_shape')
            else:
                replay = _replay(command, manifest, runtime)
                details['control_replay' if control else 'probe_replay'] = replay
                if not replay.get('ok'):
                    event_gaps.append(replay.get('gap', 'bash_replay_failed'))
        if control:
            if record.get('event') != event.get('event') or (
                not isinstance(argv, list) or not isinstance(event.get('argv'), list)
                or argv[:2] != event['argv'][:2]
            ):
                event_gaps.append('benign_control_command_mismatch')
            if replay is None or not replay.get('ok'):
                event_gaps.append('benign_control_failed')
            elif replay.get('arguments') != [*manifest.recorder_arguments, str(path)]:
                event_gaps.append('benign_control_failed')
            if event_gaps:
                gaps.append('benign_control_failed')
                gaps.extend(f'benign_control:{gap}' for gap in event_gaps)
        else:
            gaps.extend(event_gaps)
        return replay

    probe_replay = measure(event, probe_path, control=False)
    control_trace = trace_path.with_name(trace_path.stem + '.control' + trace_path.suffix) if trace_path else None
    if control_trace is not None and control_trace.exists():
        return _unresolved(*gaps, 'benign_control_trace_exists', details=details)
    control_event = _run_worker(manifest, runtime, control_path, read_grants,
                                control_trace, stack_capture, True)
    details['control_event'] = control_event
    measure(control_event, control_path, control=True)
    if gaps:
        return _unresolved(*dict.fromkeys(gaps), details=details)
    assert probe_replay is not None
    marker = f"$(printf {details['probe_nonce']})"
    expanded = str(probe_path).replace(marker, details['probe_nonce'])
    arguments = probe_replay['arguments']
    if arguments == [*manifest.recorder_arguments, expanded]:
        return WitnessResult(status=ValidationStatus.CONFIRMED,
                             raw_status='EXPANDED_OBSERVED', details=details)
    if arguments == [*manifest.recorder_arguments, str(probe_path)]:
        return WitnessResult(status=ValidationStatus.UNRESOLVED,
                             raw_status='LITERAL_OBSERVED', details=details)
    return _unresolved('ambiguous_replay_observation', details=details)


def run_witness(
    manifest: WitnessManifest, *, nonce: str | None = None, diagnostic_only: bool = False,
    diagnostic_runtime_dir: Path | None = None,
    diagnostic_read_grants: tuple[IsolationReadGrant, ...] = (),
    diagnostic_trace_path: Path | None = None,
    diagnostic_stack_capture: bool = False,
    verify_obligations: bool = False,
    derive_recorder: bool = False,
) -> WitnessResult:
    """Observe one candidate-bound input and an independent benign control.

    ``CONFIRMED`` requires actual Bash expansion at the first source-bound
    command event. Every negative or incomplete observation remains unresolved.
    The caller must separately validate ``subject.source_digest`` against its
    trusted repository index before registering the result as candidate proof.
    """
    if nonce is None:
        nonce = uuid4().hex
    if verify_obligations and diagnostic_only:
        raise ValueError('verification and observation-only diagnostic modes are exclusive')
    if derive_recorder and not verify_obligations:
        raise ValueError('recorder derivation requires verification mode')
    if not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be 12-64 ASCII letters or digits")
    WitnessResourceProfile.model_validate(manifest.resource_profile.model_dump())
    extended_mode = diagnostic_only or verify_obligations
    if manifest.resource_profile.name != "fixture_default" and not extended_mode:
        raise ValueError("nondefault resource profiles are diagnostic-only")
    if diagnostic_runtime_dir is not None and not extended_mode:
        raise ValueError("a persistent probe directory is diagnostic-only")
    if (diagnostic_read_grants or diagnostic_trace_path is not None
            or diagnostic_stack_capture) and not extended_mode:
        raise ValueError("read grants, stacks and syscall tracing are diagnostic-only")
    if diagnostic_trace_path is not None:
        if not diagnostic_trace_path.is_absolute():
            raise ValueError("diagnostic trace path must be absolute")
        if diagnostic_trace_path.exists() or diagnostic_trace_path.is_symlink():
            raise FileExistsError(diagnostic_trace_path)
    for grant in diagnostic_read_grants:
        if not grant.is_current():
            return _unresolved(f"isolation_read_grant_stale:{grant.path}", details={
                "diagnostic_only": True, "claim_eligible": False,
                "isolation_read_grants": [item.model_dump(mode="json")
                                          for item in diagnostic_read_grants],
            })
    assumption_gaps = _assumption_gaps(manifest)
    if assumption_gaps and not extended_mode:
        return _unresolved(*assumption_gaps,
                           details={"subject": manifest.subject.model_dump(mode="json")})
    control_nonce = hashlib.sha256(f"control:{nonce}".encode()).hexdigest()[:24]
    checkout = manifest.checkout_root.resolve()
    if not checkout.is_dir():
        return _unresolved("checkout_missing")
    try:
        if not _inside(checkout / manifest.entry_relative_path, checkout):
            return _unresolved("source_outside_checkout")
        if _sha256(checkout / manifest.entry_relative_path) != manifest.entry_file_sha256:
            return _unresolved("source_mismatch")
        if manifest.bash_path.resolve(strict=True) != Path("/bin/bash").resolve(strict=True):
            return _unresolved("unsupported_bash_binary")
    except OSError as error:
        return _unresolved("source_or_bash_unavailable", details={"error": str(error)})
    if diagnostic_runtime_dir is None:
        runtime_context = tempfile.TemporaryDirectory(prefix="cv-agent-witness-")
    else:
        if (not diagnostic_runtime_dir.is_absolute() or ".." in diagnostic_runtime_dir.parts
                or re.fullmatch(r"/[A-Za-z0-9_./-]+", str(diagnostic_runtime_dir)) is None
                or diagnostic_runtime_dir.is_symlink()):
            raise ValueError("diagnostic runtime path contains unsupported syntax or symlinks")
        diagnostic_runtime_dir.mkdir(parents=True, exist_ok=True)
        if not _safe_runtime_path(diagnostic_runtime_dir):
            raise ValueError("diagnostic runtime path contains a symlinked parent")
        runtime_context = nullcontext(str(diagnostic_runtime_dir.resolve(strict=True)))
    with runtime_context as name:
        runtime = Path(name)
        if not _safe_runtime_path(runtime):
            return _unresolved("unsafe_probe_runtime_path")
        probe_path, probe_files = _prepare_input(runtime, manifest, nonce, malicious=True)
        control_path, control_files = _prepare_input(runtime, manifest, control_nonce,
                                                     malicious=False)
        details: dict[str, Any] = {
            "subject": manifest.subject.model_dump(mode="json"),
            "entry_file_sha256": manifest.entry_file_sha256,
            "probe_path": str(probe_path), "probe_nonce": nonce,
            "control_path": str(control_path), "control_nonce": control_nonce,
            "precondition_sha256": {"probe": probe_files, "control": control_files},
            "claim_eligible": False,
            "assumption_gaps": list(assumption_gaps),
            "resource_profile": manifest.resource_profile.model_dump(mode="json"),
            "isolation_read_grants": [grant.model_dump(mode="json")
                                      for grant in diagnostic_read_grants],
        }
        if (diagnostic_trace_path is None and not diagnostic_read_grants
                and not diagnostic_stack_capture and not verify_obligations):
            event = _run_worker(manifest, runtime, probe_path)
        else:
            event = _run_worker(manifest, runtime, probe_path,
                                diagnostic_read_grants, diagnostic_trace_path,
                                diagnostic_stack_capture, verify_obligations)
        if extended_mode:
            details["strace_enabled"] = diagnostic_trace_path is not None
            details["stack_capture_enabled"] = diagnostic_stack_capture
        if diagnostic_trace_path is not None:
            from cv_agent.runtime.witness.tracer import summarize_trace
            roots = tuple(Path(path) for path in event.get("isolation_read_roots", []))
            summary = (summarize_trace(diagnostic_trace_path, roots)
                       if event.get("gap") != "worker_launch_error" else {
                           "observed_only": True, "read_denials": [],
                           "gaps": ["isolation_trace_not_created_by_run"],
                           "trace_sha256": None, "trace_size": None,
                       })
            summary.update(open_attempts=event.get("open_attempts", []),
                           open_attempt_count=event.get("open_attempt_count", 0),
                           attempts_truncated=event.get("attempts_truncated", False))
            event["read_diagnostics"] = summary
            if event.get("gap") == "target_or_isolation_error" and summary["read_denials"]:
                # Preserve the exception text separately. Earlier caught denials
                # need not have caused a later, unrelated target exception.
                filename = event.get("error_filename")
                matching = next((item for item in summary["read_denials"]
                                 if filename and item["path"] == str(Path(filename).resolve())
                                 and event.get("error_errno") == 13), None)
                event["gap"] = (matching["gap"] if matching else
                                "target_error_after_observed_read_denials")
        details["probe_event"] = event
        if verify_obligations:
            return _verification_result(
                manifest, checkout, runtime, probe_path, control_path, event,
                assumption_gaps, details, diagnostic_read_grants,
                diagnostic_trace_path, diagnostic_stack_capture,
                derive_recorder,
            )
        if diagnostic_only:
            return _diagnostic_result(
                manifest, checkout, runtime, probe_path, event, assumption_gaps, details,
            )
        if event.get("kind") != "command_event":
            return _unresolved(event.get("gap", "command_boundary_not_reached"), details=details)
        if event.get("phase") != "invoke" or event.get("candidate_frame") is None:
            gap = "import_time_command_event" if event.get("phase") == "import" else "event_outside_candidate_frame"
            return _unresolved(gap, details=details)
        if not _bound_emitter(event, manifest, checkout):
            return _unresolved("emitter_source_not_bound", details=details)
        if not event.get("authentic_subprocess_popen"):
            return _unresolved("audit_event_not_authenticated", details=details)
        if not event.get("preexec_verified_none"):
            return _unresolved("preexec_not_verified", details=details)
        if not event.get("actual_executable_is_bash"):
            return _unresolved("actual_executable_not_verified_bash", details=details)
        if event.get("captured_cwd") is not None:
            return _unresolved("captured_cwd_not_replayed", details=details)
        if not event.get("seccomp_selftest") or not event.get("hook_selftest"):
            return _unresolved("isolation_selftest_failed", details=details)
        if event.get("loaded_source_gaps"):
            return _unresolved(*event["loaded_source_gaps"], details=details)
        argv = event.get("argv")
        marker = f"$(printf {nonce})"
        if not isinstance(argv, list) or not any(marker in part for part in argv):
            return _unresolved("probe_not_in_argv" if event.get("env_has_probe") else
                               "preempted_by_unrelated_command_event", details=details)
        command = _verified_bash_command(
            argv, manifest.bash_path, manifest.python_executable,
        )
        if command is None:
            return _unresolved("unsupported_shell_argv", details=details)
        if event.get("shell_env_keys"):
            return _unresolved("captured_shell_environment_not_replayed", details=details)
        if not _simple_recorder_command(command, manifest, probe_path):
            return _unresolved("unsupported_shell_command_shape", details=details)
        probe_replay = _replay(command, manifest, runtime)
        details["probe_replay"] = probe_replay
        if not probe_replay.get("ok"):
            return _unresolved(probe_replay.get("gap", "bash_replay_failed"), details=details)
        control_event = _run_worker(manifest, runtime, control_path)
        details["control_event"] = control_event
        if (control_event.get("kind") != "command_event"
                or control_event.get("phase") != "invoke"
                or control_event.get("candidate_frame") is None
                or not control_event.get("seccomp_selftest")
                or not control_event.get("hook_selftest")
                or not control_event.get("authentic_subprocess_popen")
                or not control_event.get("preexec_verified_none")
                or not control_event.get("actual_executable_is_bash")
                or control_event.get("captured_cwd") is not None
                or control_event.get("loaded_source_gaps")
                or not _bound_emitter(control_event, manifest, checkout)
                or control_event.get("event") != event.get("event")
                or not isinstance(control_event.get("argv"), list)
                or control_event["argv"][:2] != argv[:2]):
            return _unresolved("benign_control_failed", details=details)
        control_command = _verified_bash_command(
            control_event.get("argv"), manifest.bash_path, manifest.python_executable,
        )
        if (control_command is None or control_event.get("shell_env_keys")
                or not _simple_recorder_command(control_command, manifest, control_path)):
            return _unresolved("benign_control_failed", details=details)
        control_replay = _replay(control_command, manifest, runtime)
        details["control_replay"] = control_replay
        if not control_replay.get("ok"):
            return _unresolved("benign_control_failed", details=details)
        control_args = control_replay["arguments"]
        if str(control_path) not in control_args or any(marker in arg for arg in control_args):
            return _unresolved("benign_control_failed", details=details)
        probe_args = probe_replay["arguments"]
        expanded = str(probe_path).replace(marker, nonce)
        if expanded in probe_args and str(probe_path) not in probe_args:
            return WitnessResult(status=ValidationStatus.CONFIRMED,
                                 raw_status="EXPANDED_OBSERVED", details=details)
        if str(probe_path) in probe_args and expanded not in probe_args:
            return WitnessResult(status=ValidationStatus.UNRESOLVED,
                                 raw_status="LITERAL_OBSERVED", details=details)
        return _unresolved("ambiguous_replay_observation", details=details)


def _main() -> None:
    if len(sys.argv) == 7 and sys.argv[1] == "--replay-worker":
        _replay_worker(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]),
                       Path(sys.argv[5]), sys.stdin.buffer.read().decode("utf-8"),
                       Path(sys.argv[6]) if sys.argv[6] else None)
        return
    if len(sys.argv) != 7 or sys.argv[1] != "--worker":
        raise SystemExit("this module is an internal witness worker")
    result_fd = int(sys.argv[2])
    runtime = Path(sys.argv[3])
    probe_path = Path(sys.argv[4])
    manifest_path = Path(sys.argv[5])
    manifest_digest = sys.argv[6]
    try:
        if not _inside(manifest_path, runtime):
            raise ValueError("worker manifest is outside its runtime directory")
        manifest_bytes = manifest_path.read_bytes()
        if len(manifest_bytes) > 5_000_000 or hashlib.sha256(manifest_bytes).hexdigest() != manifest_digest:
            raise ValueError("worker manifest identity differs from its launcher")
        envelope = json.loads(manifest_bytes)
        manifest = WitnessManifest.model_validate(envelope["manifest"])
        read_grants = tuple(IsolationReadGrant.model_validate(item)
                            for item in envelope["read_grants"])
        record_open_attempts = envelope["record_open_attempts"] is True
        stack_result_fd = envelope["stack_result_fd"]
        worker_deadline = envelope["worker_deadline"]
        verify_obligations = envelope['verify_obligations'] is True
        if stack_result_fd is not None and (
                type(stack_result_fd) is not int or stack_result_fd <= 2
                or stack_result_fd == result_fd
                or not isinstance(worker_deadline, (int, float))):
            raise ValueError("invalid diagnostic stack transport")
    except BaseException as error:
        _write_result(result_fd, {"kind": "error", "gap": "invalid_worker_manifest",
                                  "error": f"{type(error).__name__}: {error}",
                                  "interpreter": _interpreter_identity(None)})
        return
    _worker(manifest, result_fd, runtime, probe_path, read_grants, record_open_attempts,
            stack_result_fd, worker_deadline, verify_obligations)


if __name__ == "__main__":
    _main()
