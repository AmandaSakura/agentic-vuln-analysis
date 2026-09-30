"""Prepare an explicit, hash-locked development witness environment."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tomllib
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from cv_agent.domain.types import FrozenModel
from cv_agent.runtime.witness.tracer import summarize_trace, trace_command
from cv_agent.runtime.witness.isolation_policy import IsolationReadGrant
from cv_agent.runtime.provenance import git_identity
from cv_agent.runtime.witness_resources import WitnessResourceProfile


_SOURCE = Path(__file__).resolve().parents[3]
_INHERITED = frozenset({"/dev/urandom", "/etc/passwd", "/etc/ssl/openssl.cnf", "/usr/share/zoneinfo/UTC"})
_ALLOWED_DOWNLOAD_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org"})


class HashBoundRequirements(FrozenModel):
    path: Path
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class WitnessEnvironmentSpec(FrozenModel):
    repository_url: str
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    checkout_root: Path
    python_executable: Path
    python_version: Literal["3.12"] = "3.12"
    dependency_source: Literal["uv_lock", "requirements", "pyproject"]
    requirements_locked: bool = Field(default=False, strict=True)
    dependency_path: Path
    extras: tuple[str, ...] = ()
    target_distribution: str
    target_module: str = Field(pattern=r"^[A-Za-z_][A-Za-z_0-9]*(\.[A-Za-z_][A-Za-z_0-9]*)*$")
    import_root: str = "."
    target_wheel: Path
    target_wheel_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    wheelhouse: Path
    output_directory: Path
    allow_network: bool = Field(default=False, strict=True)
    dependency_mode: Literal["wheelhouse", "cached_pypi"] = "wheelhouse"
    runtime_requirements: tuple[HashBoundRequirements, ...] = ()
    inherited_grants_file: Path | None = None
    accepted_grants_file: Path | None = None
    resource_profile_name: str = "import_baseline"

    @model_validator(mode="after")
    def explicit_inputs(self):
        for path in (self.checkout_root, self.python_executable, self.dependency_path,
                     self.target_wheel, self.wheelhouse, self.output_directory):
            if not path.is_absolute():
                raise ValueError("environment preparation paths must be absolute")
        parsed = urlsplit(self.repository_url)
        if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username or parsed.password:
            raise ValueError("repository_url must identify an explicit public GitHub repository")
        relative = Path(self.import_root)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("import_root must stay inside checkout")
        if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", value) for value in self.extras):
            raise ValueError("extras must be explicit dependency names")
        if self.resource_profile_name == "fixture_default":
            raise ValueError("a measured environment needs a distinct named resource profile")
        if self.dependency_mode == "cached_pypi" and self.allow_network:
            raise ValueError("cached_pypi is an explicitly offline mode")
        if self.requirements_locked and self.dependency_source != "requirements":
            raise ValueError("requirements_locked applies only to explicit requirements input")
        if any(not requirement.path.is_absolute() for requirement in self.runtime_requirements):
            raise ValueError("runtime requirements paths must be absolute")
        return self


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _proposal_leaf_eligible(path: Path) -> bool:
    try:
        info = path.stat()
    except OSError:
        return False
    return (stat.S_ISREG(info.st_mode) and info.st_size <= 8_000_000
            or stat.S_ISCHR(info.st_mode))


def _json(path: Path, value) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def derive_profile(baseline: dict, name: str) -> WitnessResourceProfile:
    if (baseline.get("returncode") != 0 or baseline.get("timed_out") or baseline.get("gaps")
            or baseline.get("import_identity", {}).get("source_inside_checkout") is not True):
        raise ValueError("successful source-bound import baseline required")
    timed, sampled = baseline["gnu_time"], baseline["target_samples"]
    cpu = timed["user_cpu_seconds"] + timed["system_cpu_seconds"]
    virtual_kib = sampled.get("max_virtual_memory_kib")
    fd = sampled["fd_observed_peak"]
    if type(virtual_kib) is not int or type(fd) is not int:
        raise ValueError("import baseline measurements are incomplete")
    virtual = virtual_kib * 1024
    if min(cpu, virtual, fd, baseline["elapsed_seconds"]) < 0 or virtual == 0 or fd == 0:
        raise ValueError("import baseline measurements are incomplete")
    soft = max(5, 5 * math.ceil(cpu * 3 / 5))
    return WitnessResourceProfile(name=name, cpu_soft_seconds=soft, cpu_hard_seconds=soft + 5,
        address_space_bytes=math.ceil(virtual * 2 / (1 << 30)) * (1 << 30),
        file_size_bytes=1_000_000, open_files=max(64, 4 * fd + 8),
        wall_seconds=float(max(30, 4 * baseline["elapsed_seconds"])))


def accepted_grants(spec: WitnessEnvironmentSpec) -> tuple[IsolationReadGrant, ...]:
    grants = []
    if spec.inherited_grants_file is not None:
        inherited = json.loads(spec.inherited_grants_file.read_text())
        if {item["requested_path"] for item in inherited} != _INHERITED or len(inherited) != 4:
            raise ValueError("inherited_policy_leaf_mismatch")
        grants.extend(IsolationReadGrant.model_validate(item) for item in inherited)
    if spec.accepted_grants_file is not None:
        accepted = json.loads(spec.accepted_grants_file.read_text())
        if accepted.get("accepted") is not True or not accepted.get("reason", "").strip():
            raise ValueError("read_grant_acceptance_missing")
        grants.extend(IsolationReadGrant.model_validate(item) for item in accepted["grants"])
    if any(not grant.is_current() for grant in grants):
        raise ValueError("accepted_read_grant_stale")
    if len({grant.path for grant in grants}) != len(grants):
        raise ValueError("accepted_read_grant_duplicate")
    return tuple(grants)


def _external_sources(path: Path, source: str) -> None:
    text = path.read_text()
    if source == "pyproject":
        project = tomllib.loads(text)
        dependencies = project.get("project", {}).get("dependencies", [])
        for values in project.get("project", {}).get("optional-dependencies", {}).values():
            dependencies.extend(values)
        sources = project.get("tool", {}).get("uv", {}).get("sources", {})
        if sources:
            raise ValueError("dependency_source_override_unsupported")
        text = "\n".join(dependencies)
    if source == "uv_lock":
        locked = tomllib.loads(text)
        for package in locked.get("package", []):
            origin = package.get("source", {})
            if "git" in origin or "directory" in origin:
                raise ValueError("dependency_source_not_pypi")
    for url in re.findall(r"https?://[^\s\"'<>]+", text):
        if urlsplit(url).hostname not in _ALLOWED_DOWNLOAD_HOSTS:
            raise ValueError("dependency_source_not_pypi")
    if source == "requirements" and re.search(r"(?m)^\s*-(?!-hash=sha256:)", text):
        raise ValueError("dependency_source_not_pypi")
    if re.search(r"(?m)(?:\s@\s|git\+|file://|^\s*(?:/|\./|\.\./))", text):
        raise ValueError("dependency_source_not_pypi")


def prepare_environment(spec: WitnessEnvironmentSpec) -> dict:
    """Save each failed stage without changing its configuration or retrying."""
    spec = WitnessEnvironmentSpec.model_validate(spec.model_dump())
    output = spec.output_directory
    output.mkdir(parents=True, exist_ok=False)
    _json(output / "configuration.json", spec.model_dump(mode="json"))
    report = {"environment_status": "environment_unavailable", "claim_eligible": False,
              "allow_network": spec.allow_network, "dependency_mode": spec.dependency_mode,
              "target_import_ready": False, "kernel_bootstrap_ready": False,
              "stages": [], "gaps": [],
              "network_urls": [], "accepted_grants": [], "read_grant_proposals": []}
    stage = "identity"
    environment = {"PATH": os.defpath, "LC_ALL": "C", "LANG": "C",
                   "UV_PYTHON_DOWNLOADS": "never", "PYTHONDONTWRITEBYTECODE": "1"}
    uv = shutil.which("uv")
    def run(name, argv, *, timeout=120):
        nonlocal stage
        stage = name
        log = output / (name + ".log")
        with log.open("xb") as stream:
            process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, env=environment, start_new_session=True)
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                returncode = -signal.SIGKILL
        urls = sorted(set(re.findall(r"https?://[^\s\"'<>]+", log.read_text(errors="replace"))))
        report["network_urls"] = sorted(set(report["network_urls"]) | set(urls)) if spec.allow_network else []
        report["stages"].append({"name": name, "argv": argv, "returncode": returncode,
                                "log": str(log), "log_sha256": _hash(log)})
        if returncode != 0:
            raise RuntimeError(f"{name}_failed:{returncode}")
    try:
        identity = git_identity(spec.checkout_root)
        if identity.revision != spec.commit or identity.dirty:
            raise ValueError("checkout_identity_mismatch")
        origin = subprocess.run(["git", "-C", str(spec.checkout_root), "remote", "get-url", "origin"],
            check=True, capture_output=True, text=True).stdout.strip().removesuffix(".git").rstrip("/")
        if origin != spec.repository_url.removesuffix(".git").rstrip("/"):
            raise ValueError("checkout_repository_mismatch")
        if _hash(spec.target_wheel) != spec.target_wheel_sha256:
            raise ValueError("target_wheel_hash_mismatch")
        _external_sources(spec.dependency_path, spec.dependency_source)
        for requirement in spec.runtime_requirements:
            if _hash(requirement.path) != requirement.sha256:
                raise ValueError("runtime_requirements_hash_mismatch")
            _external_sources(requirement.path, "requirements")
        grants = accepted_grants(spec)
        report["accepted_grants"] = [grant.model_dump(mode="json") for grant in grants]
        report["source_identity"] = {"repository_url": spec.repository_url, "commit": spec.commit,
            "dependency_sha256": _hash(spec.dependency_path), "target_wheel_sha256": spec.target_wheel_sha256}
        report["source_identity"]["runtime_requirements"] = [item.model_dump(mode="json")
                                                               for item in spec.runtime_requirements]
        report["approval_file_hashes"] = {str(path): _hash(path) for path in
            (spec.inherited_grants_file, spec.accepted_grants_file) if path is not None}
        python_version = subprocess.run([str(spec.python_executable), "-I", "-S", "--version"],
            check=True, capture_output=True, text=True).stdout.strip()
        if not python_version.startswith("Python 3.12."):
            raise ValueError("python_version_mismatch")
        network = ([] if spec.allow_network else ["--offline"])
        index = (["--index-url", "https://pypi.org/simple"]
                 if spec.allow_network or spec.dependency_mode == "cached_pypi" else ["--no-index"])
        report["dependency_index"] = "https://pypi.org/simple" if index[0] == "--index-url" else None
        locked = output / "requirements.lock.txt"
        if spec.requirements_locked:
            locked.write_bytes(spec.dependency_path.read_bytes())
            report["stages"].append({"name": "dependency_lock", "action": "preserve_supplied_hash_lock",
                                    "source_sha256": _hash(spec.dependency_path)})
        elif spec.dependency_source == "uv_lock":
            run("dependency_lock", [uv, "--no-config", "export", "--locked", "--no-dev",
                "--no-emit-workspace", "--project", str(spec.dependency_path.parent),
                *[arg for extra in spec.extras for arg in ("--extra", extra)],
                *network, "--output-file", str(locked)])
        else:
            run("dependency_lock", [uv, "--no-config", "-v", "pip", "compile", str(spec.dependency_path),
                "--python", str(spec.python_executable), "--generate-hashes", "--only-binary", ":all:",
                *[arg for extra in spec.extras for arg in ("--extra", extra)],
                *network, *index, "--find-links", str(spec.wheelhouse), "--output-file", str(locked)])
        _external_sources(locked, "requirements")
        if spec.runtime_requirements:
            with locked.open("a") as stream:
                for requirement in spec.runtime_requirements:
                    stream.write("\n" + requirement.path.read_text() + "\n")
        venv = output / "venv"
        run("venv", [uv, "--no-config", "venv", "--python", str(spec.python_executable), "--offline", str(venv)])
        python = venv / "bin/python"
        site = venv / "lib/python3.12/site-packages"
        run("dependency_install", [uv, "--no-config", "-v", "pip", "install", "--python", str(python),
            "--require-hashes", "--no-deps", "--only-binary", ":all:", *network, *index,
            "--find-links", str(spec.wheelhouse), "-r", str(locked)])
        metadata_config = output / "metadata-configuration.json"
        _json(metadata_config, {"wheel": str(spec.target_wheel), "sha256": spec.target_wheel_sha256,
            "distribution": spec.target_distribution, "module_name": spec.target_module,
            "site": str(site), "result": str(output / "metadata-install.json")})
        run("metadata_install", [str(python), "-I", "-S", str(Path(__file__).with_name("witness_metadata.py")), str(metadata_config)])
        run("pip_check", [uv, "--no-config", "pip", "check", "--python", str(python)])
        run("freeze", [uv, "--no-config", "pip", "freeze", "--python", str(python)])
        import_root = (spec.checkout_root / spec.import_root).resolve(strict=True)
        if not import_root.is_relative_to(spec.checkout_root.resolve()) or not import_root.is_dir():
            raise ValueError("import_root_outside_checkout")
        baseline_prefix = output / "import-baseline"
        roots = tuple(dict.fromkeys(path.resolve() for path in (
            spec.checkout_root, venv, spec.python_executable.resolve().parent.parent,
            Path(sys.base_prefix), _SOURCE,
            Path("/lib"), Path("/lib64"), Path("/usr/lib"), Path("/etc/ld.so.cache"),
            *(grant.path for grant in grants)) if path.exists()))
        kernel_file = _SOURCE / "cv_agent/runtime/witness/kernel.py"
        common = {"checkout": str(spec.checkout_root), "import_root": str(import_root),
            "module_name": spec.target_module, "site": str(site), "read_roots": [str(path) for path in roots],
            "syscalls": str(_SOURCE / "cv_agent/runtime/fixture_syscalls.py"),
            "filesystem": str(_SOURCE / "cv_agent/runtime/fixture_isolation.py"),
            "harness_source": str(_SOURCE), "kernel_module": "cv_agent.runtime.witness.kernel",
            "kernel_file": str(kernel_file)}
        baseline_config = output / "baseline-configuration.json"
        _json(baseline_config, {**common, "result": str(output / "baseline-import-identity.json"),
                                "apply_limits": False, "check_kernel": False})
        run("import_baseline", ["/usr/bin/unshare", "--user", "--map-current-user", "--net", "--",
            str(Path(sys.executable)), "-m", "cv_agent.evaluation.diagnostics.measure_import_resources",
            str(import_root), str(python), spec.target_module, str(baseline_prefix),
            "--worker-configuration", str(baseline_config)], timeout=75)
        baseline = json.loads(baseline_prefix.with_suffix(".json").read_text())
        profile = derive_profile(baseline, spec.resource_profile_name)
        _json(output / "resource-profile.json", {"profile": profile.model_dump(mode="json"),
            "baseline_sha256": _hash(baseline_prefix.with_suffix(".json")),
            "formula": "CPU ceil5(3*cpu), hard+5; AS ceilGiB(2*VmPeak); FD max(64,4*peak+8); wall max(30,4*elapsed)",
            "observed_peaks_are_lower_bounds": True})
        config = output / "import-configuration.json"
        _json(config, {**common, "apply_limits": True, "check_kernel": True,
            "result": str(output / "import-check.json"), "cpu_soft": profile.cpu_soft_seconds,
            "cpu_hard": profile.cpu_hard_seconds, "address_space": profile.address_space_bytes,
            "open_files": profile.open_files})
        trace = output / "import.strace.log"
        run("import_check", trace_command([str(python), "-I", "-S",
            str(Path(__file__).with_name("witness_import_worker.py")), str(config)], trace),
            timeout=profile.wall_seconds)
        checked = json.loads((output / "import-check.json").read_text())
        report["target_import_ready"] = checked["target_import_ready"]
        report["kernel_bootstrap_ready"] = checked["kernel_bootstrap_ready"]
        summary = summarize_trace(trace, roots)
        _json(output / "read-diagnostics.json", summary)
        report["read_denials"] = summary["read_denials"]
        report["import_trace_gaps"] = summary["gaps"]
        report["read_grant_proposals"] = [{"path": item["canonical_path"], "accepted": False,
            "identity_bound": False, "leaf_eligible": _proposal_leaf_eligible(Path(item["canonical_path"])),
            "reason": "Observed restricted import denial; no read authority added."}
            for item in summary["read_denials"]]
        if checked.get("ok") is not True:
            reason = "witness_kernel_bootstrap_unavailable" if checked["target_import_ready"] else "isolated_import_failed"
            raise ValueError(reason + ":" + checked.get("gap", "missing_import_identity"))
        blocking_trace_gaps = [gap for gap in summary["gaps"]
                               if not gap.startswith("isolation_read_denied:")]
        if blocking_trace_gaps:
            raise ValueError("restricted_import_trace_gaps:" + ",".join(blocking_trace_gaps))
        size = sum(path.stat().st_size for path in venv.rglob("*") if path.is_file() and not path.is_symlink())
        if size >= 3_000_000_000:
            raise ValueError("environment_size_limit_exceeded")
        if git_identity(spec.checkout_root) != identity:
            raise ValueError("checkout_changed_during_preparation")
        report.update(environment_status="environment_ready", python_executable=str(python),
            checkout_root=str(spec.checkout_root), import_root=spec.import_root,
            resource_profile=profile.model_dump(mode="json"), venv_size_bytes=size,
            freeze_sha256=_hash(output / "freeze.log"), requirements_sha256=_hash(locked),
            readiness_scope="Target source import and current witness kernel bootstrap succeeded under the accepted read grants. Observed read denials remain unaccepted; future witness execution and branch equivalence require independent verification.")
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        report["gaps"].append({"stage": stage, "reason": str(error), "error_type": type(error).__name__})
    report["artifact_hashes"] = {path.name: _hash(path) for path in sorted(output.iterdir()) if path.is_file()}
    _json(output / "witness_context.json", report)
    return report


def load_execution_context(record_path: Path, *, response_mode: Literal["full", "compact"] = "full"):
    """Load only complete, unchanged preparation artifacts as trusted context."""
    from cv_agent.tools.validation.witness_manifest import WitnessExecutionContext
    report = json.loads(record_path.read_text())
    if report["environment_status"] != "environment_ready" or report["gaps"]:
        raise ValueError("witness_environment_not_ready")
    output = record_path.parent
    for name, digest in report["artifact_hashes"].items():
        if Path(name).name != name or _hash(output / name) != digest:
            raise ValueError("witness_environment_artifact_changed")
    spec = WitnessEnvironmentSpec.model_validate_json((output / "configuration.json").read_text())
    if (git_identity(spec.checkout_root).revision != spec.commit or git_identity(spec.checkout_root).dirty
            or _hash(spec.dependency_path) != report["source_identity"]["dependency_sha256"]
            or _hash(spec.target_wheel) != spec.target_wheel_sha256):
        raise ValueError("witness_environment_source_changed")
    for path, digest in report.get("approval_file_hashes", {}).items():
        if _hash(Path(path)) != digest:
            raise ValueError("witness_environment_approval_changed")
    for requirement in spec.runtime_requirements:
        if _hash(requirement.path) != requirement.sha256:
            raise ValueError("witness_environment_runtime_requirements_changed")
    grants = accepted_grants(spec)
    if [grant.model_dump(mode="json") for grant in grants] != report["accepted_grants"]:
        raise ValueError("witness_environment_grants_changed")
    checked = json.loads((output / "import-check.json").read_text())
    for module in checked["loaded_target_modules"]:
        path = Path(module["file"]).resolve(strict=True)
        if not path.is_relative_to(spec.checkout_root.resolve()) or _hash(path) != module["sha256"]:
            raise ValueError("witness_environment_import_source_changed")
    if checked.get("kernel_bootstrap_ready") is not True:
        raise ValueError("witness_environment_kernel_not_ready")
    for module in checked["loaded_kernel_modules"]:
        path = Path(module["file"]).resolve(strict=True)
        if not path.is_relative_to(_SOURCE) or _hash(path) != module["sha256"]:
            raise ValueError("witness_environment_kernel_source_changed")
    return WitnessExecutionContext(checkout_root=spec.checkout_root,
        python_executable=Path(report["python_executable"]), import_root=spec.import_root,
        resource_profile=WitnessResourceProfile.model_validate(report["resource_profile"]),
        read_grants=grants, runtime_root=output / "witness-runtime", response_mode=response_mode)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("configuration", type=Path)
    args = parser.parse_args()
    spec = WitnessEnvironmentSpec.model_validate_json(args.configuration.read_text())
    report = prepare_environment(spec)
    print(json.dumps({"environment_status": report["environment_status"], "gaps": report["gaps"]}))
    if report["environment_status"] != "environment_ready":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
