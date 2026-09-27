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
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from uuid import uuid4

from pydantic import Field, model_validator

from cv_agent.domain.evidence import ValidationStatus, ValidationSubject
from cv_agent.domain.types import FrozenModel
from cv_agent.runtime.fixture_isolation import restrict_fixture_filesystem
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


def _worker_path() -> str:
    return f"{Path(sys.executable).parent}:/bin:/usr/bin"


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
    view = memoryview(encoded)
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
            probe_path: Path) -> None:
    try:
        checkout = manifest.checkout_root.resolve(strict=True)
        for binding in manifest.source_modules:
            source = checkout / binding.relative_path
            if not _inside(source, checkout) or _sha256(source) != binding.sha256:
                _write_result(result_fd, {"kind": "error", "gap": "source_mismatch",
                                          "module": binding.module_name})
                return
        _apply_fixture_limits()
        _install_fixture_isolation(result_fd, deny_exec=True)
        # _install_fixture_isolation performs an actual execve/execveat EPERM
        # self-test before returning. The audit hook is installed afterward.
        restrict_fixture_filesystem(_read_roots(checkout, runtime))
        selftest_seen = False
        phase = "import"
        expected_code: Any = None
        trusted_popen_codes = (subprocess.Popen._execute_child.__code__,
                               subprocess.Popen.__init__.__code__)

        def audit(event: str, args: tuple[Any, ...]) -> None:
            nonlocal selftest_seen
            if event == "cv_agent.witness.hook_selftest":
                selftest_seen = True
                return
            if event not in _COMMAND_EVENTS:
                return
            payload = _capture_event(event, args, checkout, manifest, expected_code,
                                     trusted_popen_codes)
            payload["loaded_source_gaps"] = _verify_module_sources(manifest, checkout)
            payload["phase"] = phase
            payload["seccomp_selftest"] = True
            payload["hook_selftest"] = selftest_seen
            _write_result(result_fd, payload)
            os._exit(0)

        sys.addaudithook(audit)
        sys.audit("cv_agent.witness.hook_selftest")
        if not selftest_seen:
            _write_result(result_fd, {"kind": "error", "gap": "hook_selftest_failed"})
            return
        sys.path.insert(0, str(checkout))
        import importlib
        module = importlib.import_module(manifest.module_name)
        source_gaps = _verify_module_sources(manifest, checkout)
        if source_gaps:
            _write_result(result_fd, {"kind": "error", "gap": "source_mismatch",
                                      "source_gaps": source_gaps})
            return
        target_class = getattr(module, manifest.class_name)
        target = target_class(*manifest.constructor_args, **manifest.constructor_kwargs)
        expected_code = getattr(target_class, manifest.method_name).__code__
        call_kwargs = dict(manifest.call_kwargs)
        call_kwargs[manifest.probe_argument] = str(probe_path)
        phase = "invoke"
        getattr(target, manifest.method_name)(*manifest.call_args, **call_kwargs)
        _write_result(result_fd, {"kind": "no_event", "seccomp_selftest": True,
                                  "hook_selftest": True, "source_verified": True})
    except BaseException as error:
        _write_result(result_fd, {"kind": "error", "gap": "target_or_isolation_error",
                                  "error": f"{type(error).__name__}: {error}"})
    finally:
        os._exit(0)


def _run_worker(manifest: WitnessManifest, runtime: Path, probe_path: Path) -> dict[str, Any]:
    read_fd, write_fd = os.pipe()
    try:
        command = [sys.executable, "-m", __name__, "--worker", str(write_fd),
                   str(runtime), str(probe_path)]
        environment = {"PATH": _worker_path(), "LC_ALL": "C", "LANG": "C",
                       "PYTHONDONTWRITEBYTECODE": "1",
                       "PYTHONPATH": str(Path(__file__).resolve().parents[3])}
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, pass_fds=(write_fd,),
                                   env=environment, cwd=runtime)
        os.close(write_fd)
        write_fd = -1
        assert process.stdin is not None
        process.stdin.write(manifest.model_dump_json().encode())
        process.stdin.close()
        chunks: list[bytes] = []
        size = 0
        deadline = time.monotonic() + _WORKER_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                return {"kind": "error", "gap": "worker_timeout"}
            ready, _, _ = select.select([read_fd], [], [], remaining)
            if not ready:
                continue
            chunk = os.read(read_fd, 16_384)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _RESULT_LIMIT:
                process.kill()
                process.wait()
                return {"kind": "error", "gap": "worker_result_too_large"}
        try:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            return {"kind": "error", "gap": "worker_timeout_after_result"}
        encoded = b"".join(chunks)
        if process.returncode != 0 or not encoded or len(encoded) > _RESULT_LIMIT:
            return {"kind": "error", "gap": "worker_missing_or_invalid_result",
                    "returncode": process.returncode}
        try:
            return json.loads(encoded)
        except json.JSONDecodeError as error:
            return {"kind": "error", "gap": "worker_invalid_json",
                    "error": str(error), "raw": encoded[:4000].decode(errors="replace")}
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return {"kind": "error", "gap": "worker_launch_error",
                "error": f"{type(error).__name__}: {error}"}
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def _verified_bash_command(argv: Any, bash_path: Path) -> str | None:
    if (not isinstance(argv, list) or len(argv) != 3
            or argv[1] != "-c" or not all(isinstance(x, str) for x in argv)):
        return None
    executable = argv[0]
    if executable not in {"bash", "sh"} and not Path(executable).is_absolute():
        return None
    resolved = (shutil.which(executable, path=_worker_path())
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
    recorder_dir.mkdir(exist_ok=True)
    recorder = recorder_dir / manifest.recorder_command
    receipt = uuid4().hex
    recorder.write_text(
        "#!/bin/bash\n"
        f"printf '{receipt}\\0'\n"
        "printf '%s\\0' \"$@\"\n"
    )
    recorder.chmod(0o755)
    bash_path = manifest.bash_path.resolve(strict=True)
    if len(command.encode("utf-8")) > 16_384:
        return {"ok": False, "gap": "bash_command_too_large"}
    try:
        process = subprocess.Popen(
            [sys.executable, "-m", __name__, "--replay-worker", str(runtime),
             str(manifest.checkout_root.resolve()), str(bash_path), str(recorder)],
            cwd=runtime,
            env={"PATH": _worker_path(), "LC_ALL": "C",
                 "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1",
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
                   command: str) -> None:
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
    path.mkdir()
    hashes: dict[str, str] = {}
    for relative, content in manifest.precondition_files.items():
        target = path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        hashes[relative] = _sha256(target)
    return path, hashes


def run_witness(manifest: WitnessManifest, *, nonce: str | None = None) -> WitnessResult:
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
    assumption_gaps = _assumption_gaps(manifest)
    if assumption_gaps:
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
    with tempfile.TemporaryDirectory(prefix="cv-agent-witness-") as name:
        runtime = Path(name)
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
        }
        event = _run_worker(manifest, runtime, probe_path)
        details["probe_event"] = event
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
        command = _verified_bash_command(argv, manifest.bash_path)
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
        control_command = _verified_bash_command(control_event.get("argv"), manifest.bash_path)
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
    if len(sys.argv) == 6 and sys.argv[1] == "--replay-worker":
        _replay_worker(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]),
                       Path(sys.argv[5]), sys.stdin.buffer.read().decode("utf-8"))
        return
    if len(sys.argv) != 5 or sys.argv[1] != "--worker":
        raise SystemExit("this module is an internal witness worker")
    result_fd = int(sys.argv[2])
    runtime = Path(sys.argv[3])
    probe_path = Path(sys.argv[4])
    try:
        manifest = WitnessManifest.model_validate_json(sys.stdin.buffer.read())
    except BaseException as error:
        _write_result(result_fd, {"kind": "error", "gap": "invalid_worker_manifest",
                                  "error": f"{type(error).__name__}: {error}"})
        return
    _worker(manifest, result_fd, runtime, probe_path)


if __name__ == "__main__":
    _main()
