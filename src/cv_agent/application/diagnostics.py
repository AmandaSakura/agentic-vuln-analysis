"""Operational attribution is separate from property interpretation."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import platform

from cv_agent.agents.evidence_policy import validation_preparation
from cv_agent.application.preflight import preflight
from cv_agent.domain.evidence import ToolObservation
from cv_agent.domain.product_result import Diagnosis
from cv_agent.harness import FULL_SYSTEM_HARNESS


FAILURE_CLASS_CATALOG = {
    "F1": "The required tool or preparation/protocol did not complete.",
    "F2": "Repeated scenario/input schema rejection.",
    "F3": "An accepted declared scenario did not establish the required witness.",
    "F4": "Validation infrastructure, isolation, resource or timeout failure.",
    "F5": "A confirmed witness was not admitted into the agent's final judgment.",
    "F6": "A local or cumulative budget was exhausted.",
}


def observation_diagnosis(observation: ToolObservation, candidate_id: str) -> Diagnosis | None:
    preparation = validation_preparation(observation)
    if preparation is not None:
        required = tuple(item.field_path for item in preparation.missing_inputs) or ("approved_scenario",)
        return Diagnosis(stage="validation", reason_code="required_input_missing",
            message="Validation preparation is waiting for explicit input; no validator has completed.",
            owner="user", retry_policy="after_input", required_input=required,
            affected_candidate_ids=(candidate_id,), experiment_failure_class="F1")
    if observation.metadata.get("capability_missing") is True:
        return Diagnosis(stage="preflight", reason_code="required_capability_missing",
            message="An enabled task lacks its declared environment capability.", owner="environment",
            retry_policy="after_environment_change", affected_candidate_ids=(candidate_id,),
            experiment_failure_class="F4")
    if observation.metadata.get("observation_truncated") or observation.metadata.get("model_payload_suppressed"):
        return Diagnosis(stage="validation", reason_code="certificate_not_delivered",
            message="The public observation certificate is incomplete or undelivered.", owner="runtime",
            retry_policy="manual", affected_candidate_ids=(candidate_id,), experiment_failure_class="F6")
    if observation.status != "ok":
        return Diagnosis(stage="validation", reason_code="tool_protocol_failed",
            message="The tool returned a blocked or error result; no completed validation is available.",
            owner="runtime", retry_policy="manual", affected_candidate_ids=(candidate_id,),
            experiment_failure_class="F1")
    return None


def doctor(source_root: Path, *, language: str = "python", property_id: str | None = None) -> dict:
    report = preflight(source_root, language=language, property_id=property_id)
    parser_present = importlib.util.find_spec("tree_sitter") is not None
    runtime = FULL_SYSTEM_HARNESS.model
    return {"schema_version": "product-doctor-v1", **report.model_dump(mode="json"),
        "ready": report.ready and parser_present and language == "python",
        "python_version": platform.python_version(), "parser_available": parser_present,
        "configuration_presence": {"base_url_env": runtime.base_url_env in os.environ,
            "model_env": runtime.model_env in os.environ, "api_key_env": runtime.api_key_env in os.environ},
        "provider_probed": False, "pytest_gate_invoked": False,
        "experiment_failure_classes": FAILURE_CLASS_CATALOG,
        "guidance": "Fix the listed environment dependency or supply the listed input before resuming an enabled task."}
