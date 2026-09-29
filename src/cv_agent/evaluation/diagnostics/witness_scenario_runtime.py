"""Measure classified call inputs and layout in the isolated target worker."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from types import FrameType
from typing import TYPE_CHECKING, Any

from cv_agent.evaluation.diagnostics.witness_values import _json_value, _same_json

if TYPE_CHECKING:
    from cv_agent.evaluation.diagnostics.bounded_execution_witness import WitnessManifest


class ScenarioDataObserver:
    def __init__(self, manifest: WitnessManifest, probe_path: Path):
        self.manifest = manifest
        self.scenario = manifest.scenario_hypothesis
        self.path = probe_path
        self.gaps: list[str] = []
        self.input: dict[str, Any] = {}
        self.booleans: dict[str, Any] = {}
        self.constructor: dict[str, Any] = {}
        self.files: dict[str, Any] = {}

    def _value(self, actual: Any, expected: Any, gap: str, *, point: str) -> dict[str, Any]:
        supported, copied = _json_value(actual)
        matched = supported and _same_json(copied, expected)
        if not matched:
            self.gaps.append(gap)
        return {"point": point, "supported_value": supported,
                "actual": copied if supported else None, "matched": matched}

    def observe_constructor(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        if self.scenario is None:
            return
        tree = ast.parse((self.manifest.checkout_root / self.manifest.entry_relative_path).read_bytes())
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                   and node.name == self.manifest.class_name)
        ctor = next((node for node in cls.body if isinstance(node, ast.FunctionDef)
                     and node.name == "__init__"), None)
        names = [argument.arg for argument in (*ctor.args.posonlyargs, *ctor.args.args)][1:] if ctor else []
        actual = dict(zip(names, args)) | kwargs
        for name, premise in self.scenario.constructor_parameters.items():
            self.constructor[name] = self._value(actual.get(name), premise.value,
                f"scenario_constructor_parameter_unverified:{name}", point="constructor_call_boundary")
            if name not in actual:
                self.constructor[name]["matched"] = False
                self.gaps.append(f"scenario_constructor_parameter_unverified:{name}")

    def observe_entry(self, frame: FrameType) -> None:
        if self.scenario is None:
            return
        file = (self.manifest.checkout_root / self.manifest.entry_relative_path).resolve()
        if (type(frame) is not FrameType or Path(frame.f_code.co_filename).resolve() != file
                or frame.f_code.co_firstlineno != self.manifest.entry_first_line
                or frame.f_code.co_qualname != f"{self.manifest.class_name}.{self.manifest.method_name}"
                or hashlib.sha256(file.read_bytes()).hexdigest() != self.manifest.entry_file_sha256):
            self.gaps.append("scenario_entry_binding_mismatch")
            return
        probe = self.scenario.input_parameter.value
        self.input = self._value(frame.f_locals.get(probe), str(self.path),
                                "scenario_input_parameter_unverified", point="candidate_entry_frame")
        self.input["parameter"] = probe
        for name, premise in self.scenario.entry_boolean_arguments.items():
            self.booleans[name] = self._value(frame.f_locals.get(name), premise.value,
                f"scenario_boolean_argument_unverified:{name}", point="candidate_entry_frame")
        self.observe_files()

    def observe_files(self) -> None:
        if self.scenario is None:
            return
        for name, premise in self.scenario.precondition_files.items():
            file = self.path / name
            try:
                raw = file.read_bytes()
                matched = (not file.is_symlink() and file.is_file()
                           and file.resolve().is_relative_to(self.path.resolve())
                           and raw == premise.value.encode("utf-8"))
                record = {"point": "isolated_worker_layout", "matched": matched,
                          "sha256": hashlib.sha256(raw).hexdigest()}
            except (OSError, ValueError):
                matched = False
                record = {"point": "isolated_worker_layout", "matched": False, "sha256": None}
            self.files[name] = record
            if not matched:
                self.gaps.append(f"scenario_precondition_file_unverified:{name}")

    def report(self) -> dict[str, Any]:
        if self.scenario is None:
            return {"enabled": False, "gaps": []}
        self.observe_files()
        if self.input.get("matched") is not True:
            self.gaps.append("scenario_input_parameter_unverified")
        for name in self.scenario.constructor_parameters:
            if self.constructor.get(name, {}).get("matched") is not True:
                self.gaps.append(f"scenario_constructor_parameter_unverified:{name}")
        for name in self.scenario.entry_boolean_arguments:
            if self.booleans.get(name, {}).get("matched") is not True:
                self.gaps.append(f"scenario_boolean_argument_unverified:{name}")
        return {"enabled": True, "gaps": list(dict.fromkeys(self.gaps)),
                "input_parameter": self.input, "constructor_parameters": self.constructor,
                "entry_boolean_arguments": self.booleans, "precondition_files": self.files,
                "authority_scope": "local_caller_hypothesis", "remote_authority_established": False}
