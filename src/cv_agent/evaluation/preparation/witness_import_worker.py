"""Stdlib bootstrap: isolate before importing any target or site package."""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import site
import socket
import sys
import platform
from types import ModuleType


def _load(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    config = json.loads(Path(sys.argv[1]).read_text())
    result_path = Path(config["result"])
    fd = os.open(result_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    syscall = _load(config["syscalls"], "trusted_fixture_syscalls")
    filesystem = _load(config["filesystem"], "trusted_fixture_filesystem")
    record = {"ok": False, "target_import_ready": False, "kernel_bootstrap_ready": False}
    try:
        syscall._install_fixture_isolation(fd, deny_exec=True)
        denied = False
        try:
            socket.socket()
        except PermissionError:
            denied = True
        if not denied:
            raise RuntimeError("network_isolation_selftest_failed")
        if config["apply_limits"]:
            resource.setrlimit(resource.RLIMIT_CPU, (config["cpu_soft"], config["cpu_hard"]))
            resource.setrlimit(resource.RLIMIT_AS, (config["address_space"], config["address_space"]))
            resource.setrlimit(resource.RLIMIT_NOFILE, (config["open_files"], config["open_files"]))
            resource.setrlimit(resource.RLIMIT_FSIZE, (1_000_000, 1_000_000))
        filesystem.restrict_fixture_filesystem(tuple(Path(path) for path in config["read_roots"]))
        sys.dont_write_bytecode = True
        site.addsitedir(config["site"])
        sys.path.insert(0, config["import_root"])
        module = importlib.import_module(config["module_name"])
        if type(module) is not ModuleType:
            raise RuntimeError("import_module_identity_unsupported")
        dictionary = ModuleType.__dict__["__dict__"].__get__(module, ModuleType)
        file = dictionary.get("__file__")
        if type(file) is not str:
            raise RuntimeError("import_source_file_missing")
        path = Path(file).resolve(strict=True)
        checkout = Path(config["checkout"]).resolve(strict=True)
        if not path.is_relative_to(checkout):
            raise RuntimeError("import_source_outside_checkout")
        loaded = []
        prefix = config["module_name"].split(".", 1)[0]
        for name, candidate in tuple(sys.modules.items()):
            if name != prefix and not name.startswith(prefix + "."):
                continue
            if type(candidate) is not ModuleType:
                raise RuntimeError("import_target_module_identity_unsupported")
            raw_file = vars(candidate).get("__file__")
            if type(raw_file) is not str:
                raise RuntimeError("import_target_module_source_missing")
            source = Path(raw_file).resolve(strict=True)
            if not source.is_relative_to(checkout):
                raise RuntimeError("import_target_module_outside_checkout")
            loaded.append({"module": name, "file": str(source),
                           "sha256": hashlib.sha256(source.read_bytes()).hexdigest()})
        record.update({"ok": True, "target_import_ready": True,
                  "source_inside_checkout": True, "module_file": str(path),
                  "module_name": config["module_name"], "loaded_target_modules": loaded,
                  "network_selftest": True, "exec_selftest": True,
                  "filesystem_policy": "all_new_writes_denied", "diagnostic_only": True,
                  "resource_limits_applied": config["apply_limits"],
                  "import_identity": {"pid": os.getpid(), "uid": os.getuid(), "gid": os.getgid(),
                      "executable": str(Path(sys.executable).absolute()),
                      "prefix": str(Path(sys.executable).parent.parent.resolve()),
                      "base_prefix": str(Path(sys.base_prefix).resolve()),
                      "python_version": platform.python_version(), "module_name": config["module_name"],
                      "module_file": str(path), "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                      "source_inside_checkout": True}})
        if config["check_kernel"]:
            sys.path.insert(0, config["harness_source"])
            kernel = importlib.import_module(config["kernel_module"])
            if Path(kernel.__file__).resolve(strict=True) != Path(config["kernel_file"]).resolve(strict=True):
                raise RuntimeError("witness_kernel_source_mismatch")
            record["kernel_bootstrap_ready"] = True
            record["kernel_file_sha256"] = hashlib.sha256(Path(kernel.__file__).read_bytes()).hexdigest()
            harness = Path(config["harness_source"]).resolve(strict=True)
            record["loaded_kernel_modules"] = []
            for name, imported in tuple(sys.modules.items()):
                if name != "cv_agent" and not name.startswith("cv_agent."):
                    continue
                file = vars(imported).get("__file__") if type(imported) is ModuleType else None
                if type(file) is not str or not Path(file).resolve().is_relative_to(harness):
                    raise RuntimeError("witness_kernel_module_source_mismatch")
                record["loaded_kernel_modules"].append({"module": name, "file": file,
                    "sha256": hashlib.sha256(Path(file).read_bytes()).hexdigest()})
    except BaseException as error:
        record.update({"ok": False, "gap": str(error), "error_type": type(error).__name__,
                       "diagnostic_only": True})
    os.write(fd, (json.dumps(record, sort_keys=True) + "\n").encode())
    os.close(fd)


if __name__ == "__main__":
    main()
