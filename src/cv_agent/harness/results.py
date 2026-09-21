"""Shared result-payload shape and run-identity validation."""

from __future__ import annotations

from collections.abc import Mapping


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"result field {name} must be an object")
    return value


def _list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"result field {name} must be an array")
    return value


def _require_keys(container: Mapping[str, object], required: set[str], name: str) -> None:
    missing = sorted(required - set(container))
    if missing:
        raise ValueError(f"result field {name} is missing required keys: {missing}")


def _validate_run_identity(payload: Mapping[str, object]) -> None:
    identity = _mapping(payload.get("run_identity"), "run_identity")
    _require_keys(identity, {"code", "datasets", "uv_lock_tracked_by_code_revision"}, "run_identity")
    if identity["uv_lock_tracked_by_code_revision"] is not True:
        raise ValueError("run_identity must bind uv.lock through the code revision")
    code = _mapping(identity["code"], "run_identity.code")
    _require_keys(code, {"revision", "dirty"}, "run_identity.code")
    if not str(code["revision"]).strip() or not isinstance(code["dirty"], bool):
        raise ValueError("run_identity.code must contain a revision and boolean dirty state")
    datasets = _mapping(identity["datasets"], "run_identity.datasets")
    if not datasets:
        raise ValueError("run_identity must contain at least one dataset revision")
    for name, value in datasets.items():
        dataset = _mapping(value, f"run_identity.datasets.{name}")
        _require_keys(dataset, {"revision", "dirty"}, f"run_identity.datasets.{name}")
        if not str(dataset["revision"]).strip() or not isinstance(dataset["dirty"], bool):
            raise ValueError(f"dataset identity {name} is invalid")
    assessment = _mapping(payload.get("claim_assessment"), "claim_assessment")
    _require_keys(assessment, {"eligible", "reasons"}, "claim_assessment")
    if not isinstance(assessment["eligible"], bool) or not isinstance(
        assessment["reasons"], list
    ):
        raise ValueError("claim_assessment must contain a boolean and reason list")
