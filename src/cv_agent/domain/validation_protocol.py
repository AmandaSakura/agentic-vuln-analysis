"""Producer-owned preparation state for an unexecuted validation call."""
from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictBool, model_validator

from cv_agent.domain.types import FrozenModel


PREPARATION_METADATA_KEY = "validation_preparation"


class MissingValidationInput(FrozenModel):
    name: str = Field(pattern=r"^[A-Za-z_][A-Za-z_0-9]*$")
    destination: str = Field(min_length=1, max_length=512,
                             pattern=r"^[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*$")
    classified: StrictBool

    @property
    def field_path(self) -> str:
        return f"{self.destination}.{self.name}"


class ValidationPreparation(FrozenModel):
    state: Literal["preparation"] = "preparation"
    mode: Literal["dataset_provided", "model_proposed"]
    action: Literal["propose_scenario", "complete_call_data", "use_dataset_scenario"]
    missing_inputs: tuple[MissingValidationInput, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def check_action(self) -> ValidationPreparation:
        if self.action == "complete_call_data" and not self.missing_inputs:
            raise ValueError("call-data preparation must list the missing inputs")
        if self.action == "propose_scenario" and self.mode != "model_proposed":
            raise ValueError("a declared dataset scenario cannot be proposed again")
        if self.action == "use_dataset_scenario" and (self.mode != "dataset_provided" or self.missing_inputs):
            raise ValueError("dataset-mode correction cannot replace the declared scenario")
        return self

    def continuation(self, validator: str) -> str:
        prefix = (
            f"Preparation continuation for required validator {validator}: no validation execution "
            "has completed. Complete its preparation before optional analysis or finalizing. "
        )
        if self.action == "use_dataset_scenario":
            return prefix + (
                "The candidate already has a dataset scenario. Omit scenario_hypothesis; "
                "preserve all declared premises and use the outer constructor_parameters and "
                "precondition_files only for requested data. Submit the corrected call."
            )
        fields = "; ".join(f"{item.field_path} ({'value, classification, rationale' if item.classified else 'JSON value'})"
                           for item in self.missing_inputs)
        if self.mode == "model_proposed":
            return prefix + (
                f"Required fields: {fields}. Choose values from admitted source evidence or explicit "
                "hypotheses; the system supplies no chosen values. Keep the full existing classified "
                "scenario when filling its missing fields, and keep both outer maps empty. "
                "Boolean argument and condition values must be JSON true/false, never strings. "
                "Submit the completed scenario to the same validator."
            )
        return prefix + (
            f"Required fields: {fields}. Choose values from admitted source evidence or explicit "
            "hypotheses; the system supplies no chosen values. Omit scenario_hypothesis and preserve "
            "the declared dataset scenario. Submit the completed call to the same validator."
        )
