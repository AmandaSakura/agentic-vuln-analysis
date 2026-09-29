"""Measure a checkout import without fixture limits or syscall tracing.

The caller runs this supervisor in its chosen network namespace. It launches
only GNU time and the requested Python interpreter. Procfs samples describe
observed lower bounds; GNU time supplies the timed command's final CPU/RSS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any

from cv_agent.evaluation.diagnostics.process_resource_accounting import ProcessResourceSampler


_DEADLINE_SECONDS = 60.0
_SAMPLE_SECONDS = 0.01
_DOTTED_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*\Z")
_IDENTITY_PREFIX = "CV_AGENT_IMPORT_RESOURCE_IDENTITY="
_IMPORT_CODE = """import hashlib, importlib, json, os, pathlib, platform, sys
module = importlib.import_module(sys.argv[1])
root = pathlib.Path(sys.argv[2]).resolve(strict=True)
raw_file = vars(module).get('__file__')
source = pathlib.Path(raw_file).resolve(strict=True) if raw_file else None
identity = {
    'pid': os.getpid(), 'uid': os.getuid(), 'gid': os.getgid(),
    'executable': str(pathlib.Path(sys.executable).absolute()),
    'prefix': str(pathlib.Path(sys.prefix).resolve()),
    'base_prefix': str(pathlib.Path(sys.base_prefix).resolve()),
    'python_version': platform.python_version(),
    'module_name': sys.argv[1],
    'module_file': str(source) if source else None,
    'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest() if source else None,
    'source_inside_checkout': source.is_relative_to(root) if source else False,
}
print('CV_AGENT_IMPORT_RESOURCE_IDENTITY=' + json.dumps(identity, sort_keys=True), flush=True)
"""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _paths(prefix: Path) -> dict[str, Path]:
    return {name: Path(str(prefix) + suffix) for name, suffix in {
        "record": ".json", "time": ".time.log", "importtime": ".importtime.log",
        "stdout": ".stdout.log",
    }.items()}


def _time_measurements(path: Path) -> dict[str, Any]:
    text = path.read_text(errors="replace")
    fields: dict[str, Any] = {
        "accounting_scope": "gnu_time_timed_command", "user_cpu_seconds": None,
        "system_cpu_seconds": None, "max_rss_kib": None, "exit_status": None,
    }
    names = {
        "User time (seconds)": ("user_cpu_seconds", float),
        "System time (seconds)": ("system_cpu_seconds", float),
        "Maximum resident set size (kbytes)": ("max_rss_kib", int),
        "Exit status": ("exit_status", int),
    }
    for line in text.splitlines():
        for label, (name, convert) in names.items():
            if line.strip().startswith(label + ":"):
                try:
                    fields[name] = convert(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
    return fields


def _child_pid(time_pid: int) -> int | None:
    try:
        children = Path(f"/proc/{time_pid}/task/{time_pid}/children").read_text().split()
    except OSError:
        return None
    return int(children[0]) if len(children) == 1 and children[0].isdecimal() else None


def _supervisor_identity() -> dict[str, Any]:
    try:
        network_namespace = os.readlink("/proc/self/ns/net")
    except OSError as error:
        network_namespace = f"unavailable:{type(error).__name__}:{error.errno}"
    try:
        interfaces = [name for _, name in socket.if_nameindex()]
    except OSError:
        interfaces = None
    return {
        "pid": os.getpid(), "uid": os.getuid(), "gid": os.getgid(),
        "executable": str(Path(sys.executable).absolute()),
        "network_namespace": network_namespace, "network_interfaces": interfaces,
        "network_namespace_management": "caller",
        "fixture_resource_limits_applied": False, "syscall_tracing": False,
        "landlock_applied": False, "seccomp_applied": False,
    }


def measure_import(checkout_root: Path, python_executable: Path, module_name: str,
                   output_prefix: Path, *, worker_command: list[str] | None = None,
                   worker_identity_path: Path | None = None) -> dict[str, Any]:
    """Save one real import baseline using new, absolute artifact paths."""
    if not _DOTTED_NAME.fullmatch(module_name):
        raise ValueError("module_name must be a dotted Python name")
    if (worker_command is None) != (worker_identity_path is None):
        raise ValueError("restricted measurement requires command and identity artifact")
    if worker_command is not None and (not worker_command or
            any(type(value) is not str or not value for value in worker_command)
            or not worker_identity_path.is_absolute()):
        raise ValueError("restricted measurement command must be explicit argv")
    if not all(path.is_absolute() for path in (checkout_root, python_executable, output_prefix)):
        raise ValueError("checkout, interpreter, and output prefix must be absolute paths")
    checkout = checkout_root.resolve(strict=True)
    if not checkout.is_dir():
        raise ValueError("checkout must be a directory")
    if not python_executable.is_file() or not os.access(python_executable, os.X_OK):
        raise ValueError("interpreter must be an existing executable file")
    paths = _paths(output_prefix)
    for path in paths.values():
        if path.exists() or path.is_symlink():
            raise FileExistsError(path)
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    # Reserve every artifact before launching; an existing historical result
    # never authorizes replacing that file or starting another target import.
    descriptors: dict[str, int] = {}
    try:
        for name, path in paths.items():
            descriptors[name] = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except BaseException:
        for descriptor in descriptors.values():
            os.close(descriptor)
        raise
    os.close(descriptors.pop("time"))
    cache = Path(tempfile.mkdtemp(prefix="import-baseline-pycache-", dir=output_prefix.parent))
    environment = {
        "PATH": f"{python_executable.parent}:/bin:/usr/bin", "LC_ALL": "C", "LANG": "C",
        "PYTHONPATH": str(checkout), "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": str(cache),
    }
    target_command = (worker_command if worker_command is not None else
                      [str(python_executable), "-X", "importtime", "-c", _IMPORT_CODE,
                       module_name, str(checkout)])
    command = ["/usr/bin/time", "-v", "-o", str(paths["time"]), *target_command]
    sampler: ProcessResourceSampler | None = None
    process: subprocess.Popen | None = None
    timed_out = False
    start = time.monotonic()
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=descriptors["stdout"], stderr=descriptors["importtime"],
                                   env=environment, cwd=checkout, start_new_session=True)
        deadline = start + _DEADLINE_SECONDS
        while process.poll() is None:
            if sampler is None:
                child_pid = _child_pid(process.pid)
                if child_pid is not None:
                    sampler = ProcessResourceSampler(child_pid)
            if sampler is not None:
                sampler.sample()
            if time.monotonic() >= deadline:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                break
            time.sleep(_SAMPLE_SECONDS)
        if sampler is not None:
            sampler.sample()
        elapsed = time.monotonic() - start
        os.close(descriptors.pop("stdout"))
        os.close(descriptors.pop("importtime"))
        identity = None
        for line in paths["stdout"].read_text(errors="replace").splitlines():
            if line.startswith(_IDENTITY_PREFIX):
                identity = json.loads(line[len(_IDENTITY_PREFIX):])
        restricted = None
        if worker_identity_path is not None and worker_identity_path.is_file():
            restricted = json.loads(worker_identity_path.read_text())
            if restricted.get("target_import_ready"):
                identity = restricted["import_identity"]
        measured = _time_measurements(paths["time"])
        gaps = []
        if identity is None:
            gaps.append("import_identity_missing")
        elif not identity.get("source_inside_checkout"):
            gaps.append("import_source_outside_checkout")
        if sampler is None:
            gaps.append("target_pid_not_observed")
        if any(measured[name] is None for name in (
            "user_cpu_seconds", "system_cpu_seconds", "max_rss_kib",
        )):
            gaps.append("gnu_time_measurement_incomplete")
        record = {
            "checkout_root": str(checkout), "module_name": module_name,
            "python_executable": str(python_executable), "argv": command,
            "target_environment": environment, "supervisor": _supervisor_identity(),
            "deadline_seconds": _DEADLINE_SECONDS, "sample_period_seconds": _SAMPLE_SECONDS,
            "elapsed_seconds": elapsed, "returncode": process.returncode,
            "timed_out": timed_out, "import_identity": identity, "gnu_time": measured,
            "target_samples": sampler.summary() if sampler else None,
            "gaps": gaps,
            "logs": {name: {"path": str(path), "sha256": _sha256(path),
                            "size_bytes": path.stat().st_size}
                     for name, path in paths.items() if name != "record"},
            **({"target_isolation": restricted, "measurement_mode": "restricted_worker"}
               if worker_command is not None else {}),
        }
        with os.fdopen(descriptors.pop("record"), "w") as stream:
            json.dump(record, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        return record
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        for descriptor in descriptors.values():
            os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout_root", type=Path)
    parser.add_argument("python_executable", type=Path)
    parser.add_argument("module_name")
    parser.add_argument("output_prefix", type=Path)
    parser.add_argument("--worker-configuration", type=Path)
    args = parser.parse_args()
    options = {}
    if args.worker_configuration is not None:
        config = json.loads(args.worker_configuration.read_text())
        worker = Path(__file__).resolve().parents[1] / "preparation/witness_import_worker.py"
        options = {"worker_command": [str(args.python_executable), "-I", "-S", str(worker),
                                       str(args.worker_configuration)],
                   "worker_identity_path": Path(config["result"])}
    record = measure_import(args.checkout_root, args.python_executable,
                            args.module_name, args.output_prefix, **options)
    print(json.dumps({"returncode": record["returncode"], "gaps": record["gaps"],
                      "record": str(_paths(args.output_prefix)["record"])}, sort_keys=True))
    if record["returncode"] != 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
