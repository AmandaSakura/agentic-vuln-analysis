"""Classified, data-only premises for one source-bound execution hypothesis.

A classification declares who would need to supply a premise. It does not
establish remote reachability or authority over a deployed application.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from cv_agent.domain.evidence import ValidationSubject
from cv_agent.domain.types import FrozenModel


_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
PremiseClassification = Literal[
    "attacker_controlled_input", "deployment_configuration", "environment_condition",
]


def subject_has_scenario(subject: ValidationSubject) -> bool:
    return bool(subject.input_parameters or subject.entry_boolean_arguments
                or subject.entry_condition_assumptions or subject.entry_value_assumptions)


class ClassifiedScenarioValue(FrozenModel):
    value: Any
    classification: PremiseClassification
    rationale: str

    @field_validator("value", mode="before")
    @classmethod
    def plain_data(cls, value: Any) -> Any:
        # Share the existing supplement boundary; the delayed import avoids
        # making the schema depend on manifest construction at import time.
        from cv_agent.tools.validation.witness_manifest import _json_data
        _json_data(value, reject_metadata=True)
        return value

    @field_validator("rationale", mode="before")
    @classmethod
    def explain_premise(cls, value: Any) -> str:
        if type(value) is not str or not value.strip() or len(value) > 2048:
            raise ValueError("scenario premise requires a bounded nonempty rationale")
        return value


class WitnessScenarioHypothesis(FrozenModel):
    input_parameter: ClassifiedScenarioValue
    entry_boolean_arguments: dict[str, ClassifiedScenarioValue] = Field(default_factory=dict)
    entry_condition_assumptions: dict[str, ClassifiedScenarioValue] = Field(default_factory=dict)
    entry_value_assumptions: dict[str, ClassifiedScenarioValue] = Field(default_factory=dict)
    constructor_parameters: dict[str, ClassifiedScenarioValue] = Field(default_factory=dict)
    precondition_files: dict[str, ClassifiedScenarioValue] = Field(default_factory=dict)

    @field_validator("entry_boolean_arguments", "entry_condition_assumptions", "entry_value_assumptions",
                     "constructor_parameters", "precondition_files", mode="before")
    @classmethod
    def bounded_mapping(cls, value: Any) -> Any:
        if type(value) is not dict or len(value) > 64 or any(type(key) is not str for key in value):
            raise ValueError("scenario premises require bounded string-key mappings")
        return value

    @model_validator(mode="after")
    def check_premises(self) -> WitnessScenarioHypothesis:
        from cv_agent.tools.validation.witness_manifest import _safe_relative
        probe = self.input_parameter
        if (type(probe.value) is not str or not _NAME.fullmatch(probe.value)
                or probe.classification != "attacker_controlled_input"):
            raise ValueError("scenario input must name one attacker-controlled entry parameter")
        for name, premise in self.entry_boolean_arguments.items():
            if not _NAME.fullmatch(name) or type(premise.value) is not bool:
                raise ValueError("scenario boolean arguments require simple names and strict boolean values")
        for expression, premise in self.entry_condition_assumptions.items():
            if len(expression) > 2048 or type(premise.value) is not bool:
                raise ValueError("scenario conditions require bounded expressions and strict boolean values")
            try:
                ast.parse(expression, mode="eval")
            except SyntaxError as error:
                raise ValueError("scenario condition is not a Python expression") from error
        for name in self.entry_value_assumptions:
            if not _NAME.fullmatch(name) and not (name.startswith("self.") and _NAME.fullmatch(name[5:])):
                raise ValueError("scenario value premises require simple names or direct instance attributes")
        if any(not _NAME.fullmatch(name) for name in self.constructor_parameters):
            raise ValueError("scenario constructor parameters require simple names")
        if any(not _safe_relative(name) or type(premise.value) is not str
               for name, premise in self.precondition_files.items()):
            raise ValueError("scenario files require relative paths and literal text")
        if sum(len(premise.value.encode("utf-8")) for premise in self.precondition_files.values()) > 1_000_000:
            raise ValueError("scenario file content exceeds layout limit")
        if probe.value in self.entry_boolean_arguments or probe.value in self.entry_value_assumptions:
            raise ValueError("scenario probe parameter cannot also supply a fixed argument")
        for name in self.entry_boolean_arguments.keys() & self.entry_value_assumptions.keys():
            if self.entry_boolean_arguments[name].value is not self.entry_value_assumptions[name].value:
                raise ValueError("scenario boolean and value premises conflict")
        return self

    def values(self, field: str) -> dict[str, Any]:
        return {name: premise.value for name, premise in getattr(self, field).items()}

    def execution_subject(self, original: ValidationSubject) -> ValidationSubject:
        return original.model_copy(update={
            "input_parameters": (self.input_parameter.value,),
            "entry_boolean_arguments": self.values("entry_boolean_arguments"),
            "entry_condition_assumptions": self.values("entry_condition_assumptions"),
            "entry_value_assumptions": self.values("entry_value_assumptions"),
        })

    def digest(self) -> str:
        data = json.dumps(self.model_dump(mode="json"), sort_keys=True,
                          separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(data.encode()).hexdigest()
