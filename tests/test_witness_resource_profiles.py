"""Explicit diagnostic budgets must preserve the existing fixture budget."""

from __future__ import annotations

import json
import os
import resource

import pytest

from cv_agent.runtime.witness_resources import WitnessResourceProfile
from cv_agent.tools.validation.fixtures import _apply_fixture_limits


DEFAULT = {
    "name": "fixture_default",
    "cpu_soft_seconds": 5,
    "cpu_hard_seconds": 5,
    "address_space_bytes": 1_500_000_000,
    "file_size_bytes": 1_000_000,
    "open_files": 64,
    "wall_seconds": 12.0,
}


def test_default_profile_is_explicit_and_legacy_manifest_compatible():
    assert WitnessResourceProfile().model_dump() == DEFAULT
    assert WitnessResourceProfile.fixture_default().model_dump() == DEFAULT
    assert WitnessResourceProfile.model_validate_json("{}").model_dump() == DEFAULT


@pytest.mark.parametrize("field,value", [
    ("cpu_soft_seconds", 4),
    ("cpu_hard_seconds", 6),
    ("address_space_bytes", 2_000_000_000),
    ("file_size_bytes", 2_000_000),
    ("open_files", 128),
    ("wall_seconds", 13.0),
])
def test_default_profile_cannot_silently_change_one_limit(field, value):
    with pytest.raises(ValueError, match="fixture_default"):
        WitnessResourceProfile.model_validate({**DEFAULT, field: value})


@pytest.mark.parametrize("name", ["cpu_diagnostic", "heavy_target"])
def test_named_diagnostic_profile_has_finite_explicit_limits(name):
    values = {
        **DEFAULT,
        "name": name,
        "cpu_soft_seconds": 8,
        "cpu_hard_seconds": 10,
        "address_space_bytes": 3_000_000_000,
        "open_files": 128,
        "wall_seconds": 20.0,
    }
    profile = WitnessResourceProfile.model_validate(values)
    assert profile.model_dump() == values
    assert WitnessResourceProfile.model_validate_json(profile.model_dump_json()) == profile


@pytest.mark.parametrize("soft,hard", [(5, 5), (6, 5)])
@pytest.mark.parametrize("name", ["cpu_diagnostic", "heavy_target"])
def test_diagnostic_soft_cpu_limit_precedes_hard_limit(name, soft, hard):
    with pytest.raises(ValueError, match="soft.*hard"):
        WitnessResourceProfile.model_validate({
            **DEFAULT, "name": name, "cpu_soft_seconds": soft, "cpu_hard_seconds": hard,
        })


@pytest.mark.parametrize("field", [
    "cpu_soft_seconds", "cpu_hard_seconds", "address_space_bytes", "file_size_bytes",
    "open_files", "wall_seconds",
])
@pytest.mark.parametrize("value", [0, -1, float("inf"), float("nan"), True])
def test_invalid_or_unlimited_resource_values_are_rejected(field, value):
    with pytest.raises(ValueError):
        WitnessResourceProfile.model_validate({
            **DEFAULT, "name": "heavy_target", "cpu_hard_seconds": 8, field: value,
        })


@pytest.mark.parametrize("field", [
    "cpu_soft_seconds", "cpu_hard_seconds", "address_space_bytes", "file_size_bytes",
    "open_files",
])
def test_integer_limits_do_not_accept_string_or_fractional_coercion(field):
    for value in ("10", 10.5):
        with pytest.raises(ValueError):
            WitnessResourceProfile.model_validate({
                **DEFAULT, "name": "heavy_target", "cpu_hard_seconds": 8, field: value,
            })


def test_unregistered_profile_and_extra_limit_rejected():
    with pytest.raises(ValueError):
        WitnessResourceProfile.model_validate({**DEFAULT, "name": "mlflow"})
    with pytest.raises(ValueError):
        WitnessResourceProfile.model_validate({**DEFAULT, "allow_unlimited": True})


def test_unvalidated_model_copy_cannot_install_mutated_default(monkeypatch):
    installed = []
    monkeypatch.setattr(resource, "setrlimit", lambda *args: installed.append(args))
    invalid = WitnessResourceProfile.fixture_default().model_copy(update={"open_files": 128})
    with pytest.raises(ValueError, match="fixture_default"):
        invalid.apply()
    assert installed == []


def test_python_integer_outside_finite_platform_range_is_rejected():
    with pytest.raises(ValueError):
        WitnessResourceProfile.model_validate({
            **DEFAULT, "name": "heavy_target", "cpu_hard_seconds": 8,
            "address_space_bytes": 1 << 128,
        })


def test_apply_installs_only_declared_limits_and_reports_actual_limits(monkeypatch):
    profile = WitnessResourceProfile.model_validate({
        **DEFAULT, "name": "heavy_target", "cpu_soft_seconds": 8, "cpu_hard_seconds": 10,
        "address_space_bytes": 3_000_000_000, "open_files": 128, "wall_seconds": 20.0,
    })
    expected = {
        resource.RLIMIT_CPU: (8, 10),
        resource.RLIMIT_AS: (3_000_000_000, 3_000_000_000),
        resource.RLIMIT_FSIZE: (1_000_000, 1_000_000),
        resource.RLIMIT_NOFILE: (128, 128),
    }
    applied = {}
    monkeypatch.setattr(resource, "setrlimit", lambda key, pair: applied.__setitem__(key, pair))
    monkeypatch.setattr(resource, "getrlimit", lambda key: applied[key])
    profile.apply()
    assert applied == expected
    assert profile.actual_limits() == {
        "cpu": (8, 10), "address_space": (3_000_000_000, 3_000_000_000),
        "file_size": (1_000_000, 1_000_000), "open_files": (128, 128),
    }


def test_apply_failure_does_not_report_a_successfully_enforced_profile(monkeypatch):
    def fail(key, pair):
        if key == resource.RLIMIT_NOFILE:
            raise OSError("synthetic denied limit")

    monkeypatch.setattr(resource, "setrlimit", fail)
    with pytest.raises(RuntimeError, match="open_files.*synthetic denied limit"):
        WitnessResourceProfile.fixture_default().apply()


def test_actual_limits_reads_kernel_values_without_echoing_the_profile(monkeypatch):
    def read(kind):
        return kind + 10, kind + 20

    monkeypatch.setattr(resource, "getrlimit", read)
    assert WitnessResourceProfile.fixture_default().actual_limits() == {
        "cpu": read(resource.RLIMIT_CPU), "address_space": read(resource.RLIMIT_AS),
        "file_size": read(resource.RLIMIT_FSIZE), "open_files": read(resource.RLIMIT_NOFILE),
    }


def _read_limits_from_child(apply):
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            apply()
            limits = WitnessResourceProfile.fixture_default().actual_limits()
            os.write(write_fd, json.dumps(limits).encode())
            os._exit(0)
        except BaseException as error:
            os.write(write_fd, f"{type(error).__name__}: {error}".encode())
            os._exit(1)
    os.close(write_fd)
    try:
        chunks = []
        while chunk := os.read(read_fd, 4096):
            chunks.append(chunk)
        _, status = os.waitpid(child, 0)
    finally:
        os.close(read_fd)
    assert os.waitstatus_to_exitcode(status) == 0, b"".join(chunks).decode()
    return json.loads(b"".join(chunks))


def test_default_profile_and_existing_fixture_enforce_identical_limits_in_children():
    existing = _read_limits_from_child(_apply_fixture_limits)
    explicit = _read_limits_from_child(WitnessResourceProfile.fixture_default().apply)
    assert existing == explicit == {
        "cpu": [5, 5], "address_space": [1_500_000_000, 1_500_000_000],
        "file_size": [1_000_000, 1_000_000], "open_files": [64, 64],
    }
