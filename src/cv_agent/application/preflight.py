"""Task-specific capabilities; only explicitly registered owned checks may execute."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Literal

from cv_agent.domain.product_result import CapabilityDecision, Diagnosis
from cv_agent.domain.types import FrozenModel


STATIC_TOOLS = frozenset({
    "run_static_check", "inspect_command_construction", "validate_permission_mode", "probe_python_eval",
})
PROPERTY_TO_TOOL = {
    "chmod-mode-others-write": "validate_permission_mode",
    "command-execution": "inspect_command_construction",
    "dynamic-evaluation": "probe_python_eval",
}


def protected_project_root(root: Path) -> bool:
    project_root = Path(__file__).resolve().parents[3]
    return any(root.resolve().is_relative_to(project_root / part)
               for part in ("data", "artifacts", "audit", ".hermes", ".venv", "configs/datasets"))


class PreflightReport(FrozenModel):
    profile_id: Literal["product_triage_v1"] = "product_triage_v1"
    capabilities: tuple[CapabilityDecision, ...]
    diagnoses: tuple[Diagnosis, ...] = ()
    model_requests: Literal[0] = 0

    @property
    def ready(self) -> bool:
        return all(item.state == "AVAILABLE" for item in self.capabilities if item.required)


def preflight(
    source_root: Path, *, language: str = "python", property_id: str | None = None,
    required_methods: tuple[str, ...] = (), available_tools: frozenset[str] = STATIC_TOOLS,
    owned_checks: Mapping[str, Callable[[], tuple[bool, str]]] | None = None,
) -> PreflightReport:
    capabilities = []
    diagnoses = []

    def add(method, state, reason, detail, *, required=False, owner="environment"):
        capabilities.append(CapabilityDecision(language=language, property_id=property_id,
            method=method, state=state, required=required, reason_code=reason, detail=detail))
        if required and state != "AVAILABLE":
            diagnoses.append(Diagnosis(stage="preflight", reason_code=reason, message=detail,
                owner=owner, retry_policy="after_input" if owner == "user" else "after_environment_change",
                required_input=(method,), experiment_failure_class="F1" if owner == "user" else "F4"))

    if protected_project_root(source_root):
        add("source_index", "BLOCKED", "protected_source_root", "Protected project data and run directories cannot be reviewed.",
            required=True, owner="user")
    elif source_root.is_symlink():
        add("source_index", "BLOCKED", "source_root_symlink", "Source root must be an explicit directory.",
            required=True, owner="user")
    elif not source_root.is_dir():
        add("source_index", "BLOCKED", "source_root_unavailable", "Source directory is unavailable.",
            required=True, owner="user")
    else:
        add("source_index", "AVAILABLE", "source_root_present", "Read-only source indexing is available.",
            required=True)

    method = PROPERTY_TO_TOOL.get(property_id, "run_static_check")
    if language != "python":
        add(method, "UNSUPPORTED", "language_not_supported", "This product's semantic checks support Python only.",
            required=method in required_methods)
    elif method not in available_tools:
        add(method, "UNSUPPORTED", "validator_unavailable", "The selected static tool is not registered.",
            required=method in required_methods)
    else:
        add(method, "AVAILABLE", "static_tool_registered", "Static capability is available; no property is proved yet.",
            required=method in required_methods)

    optional = ("model_explanation", "bounded_witness", "private_scratch", "native_build")
    for name in optional:
        add(name, "UNSUPPORTED", "capability_not_enabled", "This capability is disabled in product_triage_v1.",
            required=name in required_methods)

    known = {item.method for item in capabilities}
    for name in required_methods:
        if name in known:
            continue
        if not name.startswith("fixture:"):
            add(name, "UNSUPPORTED", "unknown_capability", "The requested capability is not defined.", required=True)
            continue
        fixture_id = name.removeprefix("fixture:")
        checker = (owned_checks or {}).get(fixture_id)
        if checker is None:
            add(name, "BLOCKED", "owned_fixture_not_registered",
                "An explicitly registered owned functional check is required.", required=True)
            continue
        try:
            ready, detail = checker()
            if type(ready) is not bool or type(detail) is not str:
                raise TypeError("owned check must return a boolean and diagnostic text")
        except Exception as error:
            add(name, "BLOCKED", "owned_fixture_internal_error", f"Owned check failed: {type(error).__name__}",
                required=True, owner="runtime")
        else:
            add(name, "AVAILABLE" if ready else "BLOCKED", "owned_check_ready" if ready else "owned_dependency_missing",
                detail, required=True)
    return PreflightReport(capabilities=tuple(capabilities), diagnoses=tuple(diagnoses))
