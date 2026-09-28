"""Source-bound, positive-only command witness for one concrete input.

The target runs in a fresh, restricted Python process. An audit hook records the
first command event and terminates that process. A separate restricted process
replays only a verified Bash ``-c`` command with a local argument recorder.
This is a bounded observation, not a general Python sandbox or a SAFE proof.
"""

from __future__ import annotations

import hashlib
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
import time
from contextlib import nullcontext
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from uuid import uuid4

from pydantic import Field, model_validator

from cv_agent.domain.evidence import ValidationStatus, ValidationSubject
from cv_agent.domain.types import FrozenModel
from cv_agent.runtime.fixture_isolation import restrict_fixture_filesystem
from cv_agent.evaluation.diagnostics.isolation_read_policy import IsolationReadGrant
from cv_agent.tools.validation.fixtures import (
    _apply_fixture_limits,
    _install_fixture_isolation,
)


_COMMAND_EVENTS = frozenset({
    "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn",
    "os.fork", "os.forkpty", "pty.spawn",
})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DOTTED_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*\Z")
_COMMAND_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9-]*\Z")
_NONCE = re.compile(r"[A-Za-z0-9]{12,64}\Z")
_RESULT_LIMIT = 64_000
_WORKER_TIMEOUT = 12.0
_REPLAY_TIMEOUT = 5.0
_TRACE_LIMIT = 16_000_000


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
    module_name: str
    class_name: str
    method_name: str
    entry_relative_path: str
    entry_file_sha256: str
    entry_first_line: int = Field(ge=1)
    source_modules: tuple[SourceFileBinding, ...]
    probe_argument: str
    recorder_command: str
    recorder_arguments: tuple[str, ...] = ()
    bash_path: Path = Path("/bin/bash")
    python_executable: Path | None = None
    constructor_args: tuple[Any, ...] = ()
    constructor_kwargs: dict[str, Any] = Field(default_factory=dict)
    call_args: tuple[Any, ...] = ()
    call_kwargs: dict[str, Any] = Field(default_factory=dict)
    precondition_files: dict[str, str] = Field(default_factory=dict)
    probe_directory_prefix: str = "model"

    @model_validator(mode="after")
    def check_manifest(self) -> WitnessManifest:
        if not _DOTTED_NAME.fullmatch(self.module_name):
            raise ValueError("module_name must be a dotted Python name")
        if not all(_DOTTED_NAME.fullmatch(x) and "." not in x for x in (
            self.class_name, self.method_name, self.probe_argument,
        )):
            raise ValueError("class, method, and probe argument must be simple Python names")
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
                   trusted_popen_codes: tuple[Any, Any]) -> dict[str, Any]:
    frames: list[dict[str, Any]] = []
    code_objects: list[Any] = []
    preexec_values: list[Any] = []
    frame = sys._getframe(2)
    matched_code = False
    while frame is not None and len(frames) < 24:
        frames.append(_frame_data(frame, checkout))
        code_objects.append(frame.f_code)
        if any(frame.f_code is trusted for trusted in trusted_popen_codes):
            preexec_values.append(frame.f_locals.get("preexec_fn", object()))
        if expected_code is not None and frame.f_code is expected_code:
            matched_code = True
        frame = frame.f_back
    entry_file = str((checkout / manifest.entry_relative_path).resolve())
    candidate = next((item for item in frames if matched_code and
                      item["file"] == entry_file
                      and item["qualname"] == f"{manifest.class_name}.{manifest.method_name}"
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
            record_open_attempts: bool = False) -> None:
    interpreter = _interpreter_identity(manifest.python_executable)
    phase = "preflight"
    open_attempts: list[dict[str, Any]] = []
    open_attempt_count = 0
    read_roots: tuple[Path, ...] = ()

    def emit(payload: dict[str, Any]) -> None:
        if record_open_attempts:
            payload.update(phase=phase, open_attempts=open_attempts,
                           open_attempt_count=open_attempt_count,
                           attempts_truncated=open_attempt_count > len(open_attempts),
                           isolation_read_roots=[str(path) for path in read_roots])
        _write_result(result_fd, payload)

    def progress() -> None:
        if record_open_attempts:
            _write_result(result_fd, {"kind": "progress", "phase": phase,
                                      "isolation_read_roots": [str(path) for path in read_roots],
                                      "interpreter": interpreter})

    try:
        if not interpreter["matches_manifest"]:
            _write_result(result_fd, {"kind": "error", "gap": "worker_interpreter_mismatch",
                                      "interpreter": interpreter})
            return
        checkout = manifest.checkout_root.resolve(strict=True)
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
        _apply_fixture_limits()
        _install_fixture_isolation(result_fd, deny_exec=True)
        # _install_fixture_isolation performs an actual execve/execveat EPERM
        # self-test before returning. The audit hook is installed afterward.
        read_roots = (*_read_roots(checkout, runtime), *(grant.path for grant in read_grants))
        restrict_fixture_filesystem(read_roots)
        selftest_seen = False
        phase = "import"
        expected_code: Any = None
        trusted_popen_codes = (subprocess.Popen._execute_child.__code__,
                               subprocess.Popen.__init__.__code__)
        recording_command = False

        def audit(event: str, args: tuple[Any, ...]) -> None:
            nonlocal selftest_seen, open_attempt_count, recording_command
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
            recording_command = True
            payload = _capture_event(event, args, checkout, manifest, expected_code,
                                     trusted_popen_codes)
            payload["loaded_source_gaps"] = _verify_module_sources(manifest, checkout)
            payload["phase"] = phase
            payload["seccomp_selftest"] = True
            payload["hook_selftest"] = selftest_seen
            payload["interpreter"] = interpreter
            emit(payload)
            os._exit(0)

        sys.addaudithook(audit)
        sys.audit("cv_agent.witness.hook_selftest")
        if not selftest_seen:
            emit({"kind": "error", "gap": "hook_selftest_failed",
                                      "interpreter": interpreter})
            return
        sys.path.insert(0, str(checkout))
        import importlib
        progress()
        module = importlib.import_module(manifest.module_name)
        source_gaps = _verify_module_sources(manifest, checkout)
        if source_gaps:
            emit({"kind": "error", "gap": "source_mismatch",
                                      "source_gaps": source_gaps,
                                      "interpreter": interpreter})
            return
        target_class = getattr(module, manifest.class_name)
        phase = "construct"
        progress()
        target = target_class(*manifest.constructor_args, **manifest.constructor_kwargs)
        expected_code = getattr(target_class, manifest.method_name).__code__
        call_kwargs = dict(manifest.call_kwargs)
        call_kwargs[manifest.probe_argument] = str(probe_path)
        phase = "invoke"
        progress()
        getattr(target, manifest.method_name)(*manifest.call_args, **call_kwargs)
        emit({"kind": "no_event", "seccomp_selftest": True,
                                  "hook_selftest": True, "source_verified": True,
                                  "interpreter": interpreter})
    except BaseException as error:
        emit({"kind": "error", "gap": "target_or_isolation_error",
                                  "error": f"{type(error).__name__}: {error}",
                                  "error_filename": error.filename if isinstance(error, OSError) else None,
                                  "error_errno": error.errno if isinstance(error, OSError) else None,
                                  "interpreter": interpreter})
    finally:
        os._exit(0)


def _run_worker(manifest: WitnessManifest, runtime: Path, probe_path: Path,
                read_grants: tuple[IsolationReadGrant, ...] = (),
                trace_path: Path | None = None) -> dict[str, Any]:
    read_fd, write_fd = os.pipe()
    manifest_path: Path | None = None
    process: subprocess.Popen | None = None
    try:
        deadline = time.monotonic() + _WORKER_TIMEOUT
        manifest_bytes = json.dumps({
            "manifest": manifest.model_dump(mode="json"),
            "read_grants": [grant.model_dump(mode="json") for grant in read_grants],
            "record_open_attempts": trace_path is not None,
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
            from cv_agent.evaluation.diagnostics.isolation_read_diagnostics import trace_command
            command = trace_command(command, trace_path)
        environment = {"PATH": _worker_path(manifest.python_executable),
                       "LC_ALL": "C", "LANG": "C",
                       "PYTHONDONTWRITEBYTECODE": "1",
                       "PYTHONPYCACHEPREFIX": str(cache_prefix),
                       "PYTHONPATH": str(Path(__file__).resolve().parents[3])}
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, pass_fds=(write_fd,),
                                   env=environment, cwd=runtime, start_new_session=True)
        os.close(write_fd)
        write_fd = -1
        chunks: list[bytes] = []
        size = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                return {"kind": "error", "gap": "worker_timeout"}
            if trace_path is not None and trace_path.stat().st_size > _TRACE_LIMIT:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                return {"kind": "error", "gap": "read_trace_too_large"}
            ready, _, _ = select.select([read_fd], [], [], min(remaining, 0.1))
            if not ready:
                continue
            chunk = os.read(read_fd, 16_384)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _RESULT_LIMIT:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                return {"kind": "error", "gap": "worker_result_too_large"}
        try:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            return {"kind": "error", "gap": "worker_timeout_after_result"}
        encoded = b"".join(chunks)
        try:
            messages = [json.loads(line) for line in encoded.splitlines() if line]
        except json.JSONDecodeError as error:
            return {"kind": "error", "gap": "worker_invalid_json",
                    "error": str(error), "raw": encoded[:4000].decode(errors="replace")}
        observed = next((item for item in reversed(messages)
                         if isinstance(item, dict) and item.get("kind") == "progress"), {})
        final = next((item for item in reversed(messages)
                      if isinstance(item, dict) and item.get("kind") != "progress"), None)
        if process.returncode != 0 or final is None:
            gap = "worker_missing_or_invalid_result"
            if process.returncode < 0:
                gap = f"worker_terminated:{signal.Signals(-process.returncode).name}"
            return {**observed, "kind": "error", "gap": gap,
                    "returncode": process.returncode}
        return final
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return {"kind": "error", "gap": "worker_launch_error",
                "error": f"{type(error).__name__}: {error}"}
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
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


def run_witness(
    manifest: WitnessManifest, *, nonce: str | None = None, diagnostic_only: bool = False,
    diagnostic_runtime_dir: Path | None = None,
    diagnostic_read_grants: tuple[IsolationReadGrant, ...] = (),
    diagnostic_trace_path: Path | None = None,
) -> WitnessResult:
    """Observe one candidate-bound input and an independent benign control.

    ``CONFIRMED`` requires actual Bash expansion at the first source-bound
    command event. Every negative or incomplete observation remains unresolved.
    The caller must separately validate ``subject.source_digest`` against its
    trusted repository index before registering the result as candidate proof.
    """
    if nonce is None:
        nonce = uuid4().hex
    if not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be 12-64 ASCII letters or digits")
    if diagnostic_runtime_dir is not None and not diagnostic_only:
        raise ValueError("a persistent probe directory is diagnostic-only")
    if (diagnostic_read_grants or diagnostic_trace_path is not None) and not diagnostic_only:
        raise ValueError("read grants and syscall tracing are diagnostic-only")
    if diagnostic_read_grants and diagnostic_trace_path is None:
        raise ValueError("diagnostic read grants require syscall tracing")
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
    if assumption_gaps and not diagnostic_only:
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
            "isolation_read_grants": [grant.model_dump(mode="json")
                                      for grant in diagnostic_read_grants],
        }
        if diagnostic_trace_path is None:
            event = _run_worker(manifest, runtime, probe_path)
        else:
            event = _run_worker(manifest, runtime, probe_path,
                                diagnostic_read_grants, diagnostic_trace_path)
            from cv_agent.evaluation.diagnostics.isolation_read_diagnostics import summarize_trace
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
    except BaseException as error:
        _write_result(result_fd, {"kind": "error", "gap": "invalid_worker_manifest",
                                  "error": f"{type(error).__name__}: {error}",
                                  "interpreter": _interpreter_identity(None)})
        return
    _worker(manifest, result_fd, runtime, probe_path, read_grants, record_open_attempts)


if __name__ == "__main__":
    _main()
