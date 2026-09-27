"""Release and research-claim readiness checks for completed experiment artifacts."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


_FINAL_DATASET_ROLES = frozenset({"final-test"})
_USAGE_INTEGRITY_FIELDS = (
    "duplicate_request_starts",
    "invalid_responses",
    "orphaned_responses",
    "requests_without_reported_usage",
    "usage_conflicts",
)


def _read_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        payload = json.loads(path.read_text())
    except OSError as error:
        return None, f"missing {path.name}: {type(error).__name__}: {error}"
    except json.JSONDecodeError as error:
        return None, f"invalid {path.name}: {type(error).__name__}: {error}"
    if not isinstance(payload, dict):
        return None, f"invalid {path.name}: top-level JSON must be an object"
    return payload, None




def _contains_fixture_marker(value: Any) -> bool:
    if isinstance(value, dict):
        if value.get("tool") == "run_fixture_test":
            return True
        if value.get("name") == "run_fixture_test":
            return True
        evidence_ids = value.get("evidence_ids")
        if isinstance(evidence_ids, list) and any(isinstance(item, str) and item.startswith("fixture:") for item in evidence_ids):
            return True
        return any(_contains_fixture_marker(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_fixture_marker(item) for item in value)
    return False


def _observed_fixture_usage(run_dir: Path) -> tuple[bool, str | None]:
    for name in ("results.json", "events.jsonl"):
        path = run_dir / name
        try:
            if name.endswith(".jsonl"):
                for line in path.read_text().splitlines():
                    if line.strip() and _contains_fixture_marker(json.loads(line)):
                        return True, None
            else:
                if _contains_fixture_marker(json.loads(path.read_text())):
                    return True, None
        except FileNotFoundError:
            continue
        except json.JSONDecodeError as error:
            return False, f"could not inspect {name} for fixture usage: {type(error).__name__}: {error}"
    return False, None

def _claim_values(metadata: dict[str, Any], summary: dict[str, Any]) -> list[bool]:
    values: list[bool] = []
    for value in (
        metadata.get("claim_eligible"),
        summary.get("claim_eligible"),
        (metadata.get("config") or {}).get("claim_eligible") if isinstance(metadata.get("config"), dict) else None,
    ):
        if isinstance(value, bool):
            values.append(value)
    return values


def _dataset_role(metadata: dict[str, Any], summary: dict[str, Any]) -> str | None:
    role = summary.get("dataset_role")
    if isinstance(role, str) and role:
        return role
    config = metadata.get("config")
    if isinstance(config, dict) and isinstance(config.get("dataset_role"), str):
        return config["dataset_role"]
    return None


def assess_run_readiness(run_dir: Path, *, final_dataset_roles: frozenset[str] = _FINAL_DATASET_ROLES) -> dict[str, Any]:
    """Classify a completed run without trusting its stored pass boolean alone.

    ``operational_ready`` means the run artifact is internally complete enough to
    inspect. ``claim_ready`` is stricter: it must be a final-role run explicitly
    marked claim-eligible, with clean request accounting and no trusted fixture
    evidence standing in for independent evaluation.
    """
    run_dir = Path(run_dir)
    blockers: list[str] = []
    warnings: list[str] = []

    acceptance, error = _read_json(run_dir / "acceptance.json")
    if error:
        blockers.append(error)
        acceptance = {}
    metadata, error = _read_json(run_dir / "metadata.json")
    if error:
        blockers.append(error)
        metadata = {}
    summary, error = _read_json(run_dir / "summary.json")
    if error:
        blockers.append(error)
        summary = {}
    usage, error = _read_json(run_dir / "usage.json")
    if error:
        blockers.append(error)
        usage = {}

    acceptance_issues = acceptance.get("issues", []) if isinstance(acceptance, dict) else []
    if acceptance.get("passed") is not True:
        blockers.append("acceptance did not pass")
    if acceptance_issues:
        blockers.extend(f"acceptance issue: {issue}" for issue in acceptance_issues)

    requests = usage.get("requests")
    responses = usage.get("responses")
    if not isinstance(requests, int) or requests <= 0:
        blockers.append("usage recorded no model requests")
    if isinstance(requests, int) and isinstance(responses, int) and responses != requests:
        blockers.append("usage responses do not match requests")
    for field in _USAGE_INTEGRITY_FIELDS:
        value = usage.get(field, 0)
        if value not in (0, None):
            blockers.append(f"usage has nonzero {field}: {value}")

    claim_values = _claim_values(metadata, summary)
    claim_eligible = bool(claim_values) and all(claim_values)
    if not claim_eligible:
        blockers.append("run is not explicitly claim_eligible=true in metadata/summary/config")

    role = _dataset_role(metadata, summary)
    if role not in final_dataset_roles:
        blockers.append(f"dataset_role {role!r} is not an allowed final claim role")

    fixture_registry = metadata.get("validation_fixture_registry")
    metadata_uses_fixtures = bool(metadata.get("uses_trusted_fixtures")) or bool(fixture_registry)
    observed_fixtures, fixture_inspection_warning = _observed_fixture_usage(run_dir)
    if fixture_inspection_warning is not None:
        warnings.append(fixture_inspection_warning)
    uses_fixtures = metadata_uses_fixtures or observed_fixtures
    fixture_case_count = 0
    if isinstance(fixture_registry, dict):
        fixture_case_count = sum(len(value) for value in fixture_registry.values() if isinstance(value, list))
    elif fixture_registry:
        warnings.append("validation_fixture_registry is present but not an object")
    if observed_fixtures and not metadata_uses_fixtures:
        warnings.append("trusted fixture usage inferred from results/events because metadata lacks fixture provenance")
    if uses_fixtures:
        blockers.append("trusted fixtures were registered or observed; this is development regression evidence, not an independent claim")

    operational_blockers = [
        item for item in blockers
        if not (
            item.startswith("run is not explicitly claim_eligible")
            or item.startswith("dataset_role ")
            or item.startswith("trusted fixtures were registered")
        )
    ]
    operational_ready = not operational_blockers
    claim_ready = operational_ready and not blockers
    return {
        "run_directory": run_dir.as_posix(),
        "operational_ready": operational_ready,
        "claim_ready": claim_ready,
        "claim_eligible": claim_eligible,
        "dataset_role": role,
        "uses_trusted_fixtures": uses_fixtures,
        "trusted_fixture_case_count": fixture_case_count,
        "requests": requests,
        "responses": responses,
        "blockers": blockers,
        "warnings": warnings,
    }
