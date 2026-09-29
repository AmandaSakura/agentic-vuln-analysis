"""Actual local wheels and independent venvs; no dependency or model network."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from zipfile import ZipFile

import pytest

from cv_agent.evaluation.diagnostics.isolation_read_policy import IsolationReadGrant
from cv_agent.evaluation.preparation.prepare_witness_environment import (
    HashBoundRequirements, WitnessEnvironmentSpec, accepted_grants, derive_profile,
    load_execution_context, prepare_environment,
)
from cv_agent.evaluation.preparation import prepare_witness_environment as preparation
from cv_agent.evaluation.preparation.witness_metadata import install_metadata
from cv_agent.runtime.witness_resources import WitnessResourceProfile


def _wheel(folder, distribution, package, *, requires=(), extra=None):
    normalized = distribution.replace("-", "_")
    root = normalized + "-1.0.dist-info"
    path = folder / (normalized + "-1.0-py3-none-any.whl")
    with ZipFile(path, "w") as archive:
        archive.writestr(package + "/__init__.py", "TOKEN = 'actual dependency'\n")
        archive.writestr(root + "/METADATA", "Metadata-Version: 2.1\nName: " + distribution
            + "\nVersion: 1.0\n" + "".join("Requires-Dist: " + dep + "\n" for dep in requires))
        archive.writestr(root + "/WHEEL", "Wheel-Version: 1.0\nGenerator: local-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        archive.writestr(root + "/RECORD", "")
        if extra is not None:
            archive.writestr(extra, "unexpected")
    return path


def _spec(tmp_path, *, dependency="tiny-dep==1.0", source=None, dependency_source="requirements"):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "target_pkg").mkdir()
    (checkout / "target_pkg/__init__.py").write_text(source or (
        "import tiny_dep\nimport importlib.metadata\n"
        "assert tiny_dep.TOKEN == 'actual dependency'\n"
        "assert importlib.metadata.version('neutral-target') == '1.0'\n"
    ))
    requirements = checkout / ("pyproject.toml" if dependency_source == "pyproject" else "requirements.in")
    if dependency_source == "pyproject":
        requirements.write_text('[project]\nname="neutral-target"\nversion="1.0"\n'
            'dependencies=["tiny-dep==1.0"]\n[project.urls]\n'
            'Repository="https://github.com/example/neutral-project"\n')
    else:
        requirements.write_text(dependency + "\n")
    subprocess.run(["git", "init", "--quiet", str(checkout)], check=True)
    subprocess.run(["git", "-C", str(checkout), "remote", "add", "origin", "https://github.com/example/neutral-project"], check=True)
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(["git", "-C", str(checkout), "-c", "user.name=offline", "-c", "user.email=offline@example.invalid",
                    "commit", "--quiet", "-m", "synthetic source"], check=True)
    commit = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"], check=True,
                            text=True, capture_output=True).stdout.strip()
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _wheel(wheelhouse, "tiny-dep", "tiny_dep")
    wheel = _wheel(wheelhouse, "neutral-target", "target_pkg", requires=("tiny-dep==1.0",))
    python = subprocess.run(["uv", "python", "find", "--offline", "--no-python-downloads", "3.12"],
                            check=True, capture_output=True, text=True).stdout.strip()
    inherited = tmp_path / "inherited-grants.json"
    inherited.write_text(json.dumps([IsolationReadGrant.from_path(Path(name),
        "Previously approved exact operating-system leaf for isolated import.").model_dump(mode="json")
        for name in ("/dev/urandom", "/etc/passwd", "/etc/ssl/openssl.cnf", "/usr/share/zoneinfo/UTC")]))
    return WitnessEnvironmentSpec(repository_url="https://github.com/example/neutral-project", commit=commit,
        checkout_root=checkout, python_executable=Path(python), dependency_source=dependency_source,
        dependency_path=requirements, target_distribution="neutral-target", target_module="target_pkg",
        target_wheel=wheel, target_wheel_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
        wheelhouse=wheelhouse, output_directory=tmp_path / "prepared", inherited_grants_file=inherited)


def test_actual_tiny_wheelhouse_distinguishes_import_from_kernel_readiness(tmp_path):
    spec = _spec(tmp_path)
    result = prepare_environment(spec)
    assert result["environment_status"] == "environment_unavailable", result
    assert result["target_import_ready"] is True
    assert result["kernel_bootstrap_ready"] is False
    assert "witness_kernel_bootstrap_unavailable" in str(result["gaps"])
    assert result["allow_network"] is False
    assert result["network_urls"] == []
    assert result["read_grant_proposals"] == []
    profile = json.loads((spec.output_directory / "resource-profile.json").read_text())["profile"]
    assert profile["name"] == "import_baseline"
    site = spec.output_directory / "venv/lib/python3.12/site-packages"
    assert not (site / "target_pkg").exists()
    assert (site / "neutral_target-1.0.dist-info/METADATA").is_file()
    checked = json.loads((spec.output_directory / "import-check.json").read_text())
    assert checked["target_import_ready"] is True
    assert checked["network_selftest"] is checked["exec_selftest"] is True
    assert checked["filesystem_policy"] == "all_new_writes_denied"
    assert checked["module_file"] == str(spec.checkout_root / "target_pkg/__init__.py")
    assert checked["loaded_target_modules"][0]["sha256"] == hashlib.sha256(
        (spec.checkout_root / "target_pkg/__init__.py").read_bytes()).hexdigest()
    assert json.loads((spec.output_directory / "witness_context.json").read_text()) == result
    with pytest.raises(ValueError, match="not_ready"):
        load_execution_context(spec.output_directory / "witness_context.json")
    with pytest.raises(FileExistsError):
        prepare_environment(spec)


def test_explicit_cached_runtime_hash_lock_bootstraps_actual_kernel(tmp_path):
    spec = _spec(tmp_path)
    runtime = Path(__file__).parent / "fixtures/witness_environment/kernel-runtime.lock.txt"
    approval = tmp_path / "kernel-leaf-approval.json"
    leaf = IsolationReadGrant.from_path(Path("/etc/nsswitch.conf"),
        "The observed native UID lookup during kernel bootstrap reads this exact configuration leaf.")
    approval.write_text(json.dumps({"accepted": True, "reason": "Explicit synthetic kernel bootstrap acceptance.",
                                   "grants": [leaf.model_dump(mode="json")]}))
    spec = spec.model_copy(update={"dependency_mode": "cached_pypi", "accepted_grants_file": approval,
        "runtime_requirements": (
        HashBoundRequirements(path=runtime.resolve(), sha256=hashlib.sha256(runtime.read_bytes()).hexdigest()),)})
    result = prepare_environment(spec)
    assert result["environment_status"] == "environment_ready", result
    assert result["target_import_ready"] is result["kernel_bootstrap_ready"] is True
    assert result["network_urls"] == []
    context = load_execution_context(spec.output_directory / "witness_context.json")
    assert context.python_executable == spec.output_directory / "venv/bin/python"
    assert context.resource_profile.name == "import_baseline"
    assert len(context.read_grants) == 5
    (spec.output_directory / "freeze.log").write_text("altered artifact")
    with pytest.raises(ValueError, match="artifact_changed"):
        load_execution_context(spec.output_directory / "witness_context.json")


def test_successful_restricted_import_with_optional_read_denials_keeps_four_grants(tmp_path):
    spec = _spec(tmp_path)
    runtime = Path(__file__).parent / "fixtures/witness_environment/kernel-runtime.lock.txt"
    spec = spec.model_copy(update={"dependency_mode": "cached_pypi",
        "runtime_requirements": (HashBoundRequirements(path=runtime.resolve(),
            sha256=hashlib.sha256(runtime.read_bytes()).hexdigest()),)})
    result = prepare_environment(spec)
    assert result["environment_status"] == "environment_ready", result
    assert result["target_import_ready"] is result["kernel_bootstrap_ready"] is True
    assert result["gaps"] == []
    assert result["import_trace_gaps"]
    assert all(gap.startswith("isolation_read_denied:") for gap in result["import_trace_gaps"])
    assert result["read_denials"]
    assert result["read_grant_proposals"]
    assert all(not proposal["accepted"] and not proposal["identity_bound"]
               for proposal in result["read_grant_proposals"])
    assert "future witness execution" in result["readiness_scope"]
    assert len(result["accepted_grants"]) == 4
    context = load_execution_context(spec.output_directory / "witness_context.json")
    assert len(context.read_grants) == 4
    assert {grant.path for grant in context.read_grants} == {
        Path(name).resolve() for name in
        ("/dev/urandom", "/etc/passwd", "/etc/ssl/openssl.cnf", "/usr/share/zoneinfo/UTC")}


def test_structural_trace_gap_still_blocks_import_ready_context(tmp_path, monkeypatch):
    spec = _spec(tmp_path)
    runtime = Path(__file__).parent / "fixtures/witness_environment/kernel-runtime.lock.txt"
    spec = spec.model_copy(update={"dependency_mode": "cached_pypi",
        "runtime_requirements": (HashBoundRequirements(path=runtime.resolve(),
            sha256=hashlib.sha256(runtime.read_bytes()).hexdigest()),)})
    original = preparation.summarize_trace

    def summarize_with_structural_gap(*args):
        summary = original(*args)
        summary["gaps"].append("isolation_trace_truncated_log")
        return summary

    monkeypatch.setattr(preparation, "summarize_trace", summarize_with_structural_gap)
    result = prepare_environment(spec)
    assert result["target_import_ready"] is result["kernel_bootstrap_ready"] is True
    assert result["environment_status"] == "environment_unavailable"
    assert "isolation_trace_truncated_log" in str(result["gaps"])
    with pytest.raises(ValueError, match="not_ready"):
        load_execution_context(spec.output_directory / "witness_context.json")


def test_read_proposal_eligibility_matches_single_leaf_grant_kinds(tmp_path):
    regular = tmp_path / "readable-leaf"
    regular.write_text("fixture")
    assert preparation._proposal_leaf_eligible(regular)
    assert preparation._proposal_leaf_eligible(Path("/dev/urandom"))
    assert not preparation._proposal_leaf_eligible(tmp_path)
    assert not preparation._proposal_leaf_eligible(tmp_path / "absent")


def test_hash_mismatch_is_saved_and_no_environment_is_installed(tmp_path):
    spec = _spec(tmp_path).model_copy(update={"target_wheel_sha256": "0" * 64})
    result = prepare_environment(spec)
    assert result["environment_status"] == "environment_unavailable"
    assert "target_wheel_hash_mismatch" in str(result["gaps"])
    assert not (spec.output_directory / "venv").exists()


def test_target_dependency_code_contamination_rejects_metadata_install(tmp_path):
    spec = _spec(tmp_path, dependency="tiny-dep==1.0\nneutral-target==1.0")
    result = prepare_environment(spec)
    assert result["environment_status"] == "environment_unavailable", result
    assert result["gaps"][0]["stage"] == "metadata_install"
    assert "target_source_in_site_packages" in (spec.output_directory / "metadata_install.log").read_text()
    assert not (spec.output_directory / "import-check.json").exists()


def test_isolated_target_cannot_create_network_socket_or_scratch_file(tmp_path):
    forbidden = tmp_path / "forbidden-write"
    source = ("import socket\n"
              "try:\n    socket.socket()\nexcept PermissionError:\n    pass\nelse:\n    raise RuntimeError('socket allowed')\n"
              f"try:\n    open({str(forbidden)!r}, 'w')\nexcept PermissionError:\n    pass\nelse:\n    raise RuntimeError('write allowed')\n")
    spec = _spec(tmp_path, source=source)
    result = prepare_environment(spec)
    assert result["target_import_ready"] is True, result
    baseline = json.loads((spec.output_directory / "import-baseline.json").read_text())
    assert baseline["measurement_mode"] == "restricted_worker"
    assert baseline["target_isolation"]["resource_limits_applied"] is False
    assert baseline["target_isolation"]["filesystem_policy"] == "all_new_writes_denied"
    assert not forbidden.exists()


def test_unaccepted_and_stale_read_grants_never_become_effective(tmp_path):
    spec = _spec(tmp_path)
    leaf = tmp_path / "reviewed-leaf"
    leaf.write_text("old")
    grant = IsolationReadGrant.from_path(leaf, "Synthetic exact leaf required by import.")
    accepted = tmp_path / "acceptance.json"
    accepted.write_text(json.dumps({"accepted": False, "reason": "Pending review.",
                                    "grants": [grant.model_dump(mode="json")]}))
    with pytest.raises(ValueError, match="acceptance_missing"):
        accepted_grants(spec.model_copy(update={"accepted_grants_file": accepted}))
    accepted.write_text(json.dumps({"accepted": True, "reason": "Approved exact leaf.",
                                    "grants": [grant.model_dump(mode="json")]}))
    assert accepted_grants(spec.model_copy(update={"accepted_grants_file": accepted}))[-1] == grant
    leaf.write_text("changed")
    with pytest.raises(ValueError, match="stale"):
        accepted_grants(spec.model_copy(update={"accepted_grants_file": accepted}))


def test_read_denial_proposal_is_saved_without_automatically_granting_it(tmp_path):
    spec = _spec(tmp_path).model_copy(update={"inherited_grants_file": None})
    result = prepare_environment(spec)
    assert result["environment_status"] == "environment_unavailable", result
    assert result["accepted_grants"] == []
    proposal = next(item for item in result["read_grant_proposals"] if item["path"] == "/dev/urandom")
    assert proposal["accepted"] is False
    assert proposal["identity_bound"] is False
    assert result["kernel_bootstrap_ready"] is False


def test_metadata_helper_rejects_traversal_before_any_file_is_written(tmp_path):
    wheel = _wheel(tmp_path, "neutral-target", "target_pkg", extra="neutral_target-1.0.dist-info/../escaped")
    site = tmp_path / "site"
    site.mkdir()
    with pytest.raises(ValueError, match="unsafe_wheel"):
        install_metadata(wheel, hashlib.sha256(wheel.read_bytes()).hexdigest(), "neutral-target", site, "target_pkg")
    assert list(site.iterdir()) == []


def test_pyproject_repository_metadata_is_not_a_dependency_transport(tmp_path):
    result = prepare_environment(_spec(tmp_path, dependency_source="pyproject"))
    assert result["target_import_ready"] is True, result
    assert result["kernel_bootstrap_ready"] is False


def test_missing_offline_dependency_and_nested_inputs_are_explicit_failures(tmp_path):
    missing = tmp_path / "missing"
    missing.mkdir()
    spec = _spec(missing, dependency="uncached-neutral-dependency==1.0")
    result = prepare_environment(spec)
    assert result["environment_status"] == "environment_unavailable"
    assert result["gaps"][0]["stage"] == "dependency_lock"
    assert result["network_urls"] == []
    nested = tmp_path / "nested"
    nested.mkdir()
    result = prepare_environment(_spec(nested, dependency="-r ../unadmitted-input.json"))
    assert "dependency_source_not_pypi" in str(result["gaps"])
    assert result["stages"] == []


def test_supplied_dependency_hash_mismatch_is_rejected_by_real_installer(tmp_path):
    spec = _spec(tmp_path, dependency="tiny-dep==1.0 \\\n    --hash=sha256:" + "0" * 64)
    spec = spec.model_copy(update={"requirements_locked": True})
    result = prepare_environment(spec)
    assert result["environment_status"] == "environment_unavailable"
    assert result["gaps"][0]["stage"] == "dependency_install", result
    assert "hash" in (spec.output_directory / "dependency_install.log").read_text().lower()
    assert not (spec.output_directory / "metadata-install.json").exists()


def test_profile_uses_recorded_virtual_memory_and_unchanged_default():
    before = WitnessResourceProfile.fixture_default().model_dump()
    baseline = {"returncode": 0, "gaps": [], "timed_out": False, "elapsed_seconds": 4.0,
                "import_identity": {"source_inside_checkout": True},
                "gnu_time": {"user_cpu_seconds": 3.6, "system_cpu_seconds": 0.47},
                "target_samples": {"max_virtual_memory_kib": 1026912, "fd_observed_peak": 6}}
    profile = derive_profile(baseline, "opaque_measured_profile")
    assert profile.cpu_soft_seconds == 15
    assert profile.cpu_hard_seconds == 20
    assert profile.address_space_bytes == 2 * (1 << 30)
    assert profile.open_files == 64
    assert profile.wall_seconds == 30.0
    assert WitnessResourceProfile.fixture_default().model_dump() == before
