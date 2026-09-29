"""System-produced execution manifests behind a positive-only agent validator."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

from cv_agent.domain.evidence import ToolObservation, ValidationStatus, ValidationSubject
from cv_agent.domain.validation_protocol import (
    PREPARATION_METADATA_KEY, MissingValidationInput, ValidationPreparation,
)
from cv_agent.tools.validation.witness_manifest import (
    WitnessExecutionContext,
    WitnessSupplement,
    build_witness_manifest,
)
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import repository_source_digest
from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.validation.witness_scenario import WitnessScenarioHypothesis, subject_has_scenario


TOOL_NAME = "run_bounded_execution_witness"
_PREPARATION_SCOPE_NOTE = (
    "No witness has executed. Reported call-data gaps describe preparation; "
    "scenario premises require independent runtime verification."
)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _same_json(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if type(actual) is list:
        return len(actual) == len(expected) and all(_same_json(a, b) for a, b in zip(actual, expected))
    if type(actual) is dict:
        return actual.keys() == expected.keys() and all(_same_json(actual[key], expected[key]) for key in actual)
    return actual == expected


def _scenario_verification(details: dict[str, Any]) -> dict[str, Any]:
    phases: dict[str, Any] = {"remote_authority_established": False,
                              "authority_scope": "local_caller_hypothesis"}
    for phase in ("probe", "control"):
        assumptions = details.get(phase + "_event", {}).get("assumption_verification", {})
        data = assumptions.get("scenario_data", {})
        phases[phase] = {
            **data, "ok": assumptions.get("enabled") is True and data.get("enabled") is True
            and not assumptions.get("gaps"), "gaps": assumptions.get("gaps", []),
            "values": assumptions.get("values", {}), "conditions": assumptions.get("conditions", {}),
        }
    return phases


def _scope_note(verification: dict[str, Any], details: dict[str, Any]) -> str:
    # Declarations remain separate from measured facts. A launched worker or
    # a proposed input does not by itself establish candidate execution.
    observed = {
        phase: event.get("phase") == "invoke"
        and isinstance(event.get("candidate_frame"), dict)
        and event.get("authentic_subprocess_popen") is True
        and not event.get("loaded_source_gaps")
        for phase in ("probe", "control")
        for event in (details.get(phase + "_event", {}),)
    }
    if all(observed.values()) and all(verification[phase]["ok"] for phase in observed):
        return (
            "This observation covers only the executed concrete input under the listed premises; "
            "remote reachability is not established."
        )
    if any(observed.values()):
        return (
            "A concrete candidate input was observed. Listed premises are declared requirements; "
            "consult runtime verification for unmet or unverified premises. "
            "Remote reachability is not established."
        )
    return (
        "A bounded execution was attempted; candidate execution and the listed premises were not established. "
        "Remote reachability is not established."
    )


def _visible_provenance(provenance: dict[str, Any]) -> dict[str, Any]:
    # The registry already delivers the immutable original ToolObservation
    # subject. Both complete subjects and all worker records live in the
    # private artifact; repeating them consumes the evidence delivery budget.
    result = {name: value for name, value in provenance.items()
              if name not in {"original_subject", "execution_subject", "scenario"}}
    scenario = provenance.get("scenario")
    premises = []
    if scenario is not None:
        def premise(item: dict[str, Any]) -> dict[str, Any]:
            displayed = {"classification": item["classification"], "value": item["value"]}
            encoded = _json(item["value"]).encode("utf-8")
            if len(encoded) > 512:
                displayed.update(value={"sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded)},
                                 value_representation="canonical_json_sha256")
            return displayed
        # JSON-pointer names preserve arbitrary condition expressions and
        # relative file names without duplicating their classified values.
        for field in sorted(scenario):
            if field == "input_parameter":
                premises.append({"name": "/input_parameter", **premise(scenario[field])})
            else:
                for name, item in sorted(scenario[field].items()):
                    escaped = name.replace("~", "~0").replace("/", "~1")
                    premises.append({"name": f"/{field}/{escaped}", **premise(item)})
    result["premises"] = premises
    return result


def _write_private_json(path: Path, value: Any) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(_json(value))
        stream.write("\n")


def _verification_summary(event: dict[str, Any], checkout_root: Path) -> dict[str, Any]:
    assumptions = event.get("assumption_verification", {})
    preexec = event.get("preexec_verification", {})
    def source_frame(frame: Any) -> dict[str, Any] | None:
        if not isinstance(frame, dict):
            return None
        relative = None
        if type(frame.get("file")) is str:
            try:
                relative = str(Path(frame["file"]).relative_to(checkout_root.resolve()))
            except ValueError:
                pass
        return {"file": relative, **{name: frame.get(name)
                for name in ("line", "qualname", "first_line", "module_name", "sha256")}}
    candidate = source_frame(event.get("candidate_frame"))
    emitter = source_frame(event.get("emitter_frame"))
    return {
        "event": event.get("event"), "phase": event.get("phase"),
        "argv": event.get("argv"),
        "candidate_frame": candidate,
        "emitter_frame": {"same_as_candidate": True} if emitter == candidate and emitter is not None else emitter,
        "authentic_subprocess_popen": event.get("authentic_subprocess_popen") is True,
        "seccomp_selftest": event.get("seccomp_selftest") is True,
        "hook_selftest": event.get("hook_selftest") is True,
        "source_gaps": event.get("loaded_source_gaps", []),
        "assumptions_verified": assumptions.get("enabled") is True and not assumptions.get("gaps"),
        "assumption_gaps": assumptions.get("gaps", []),
        "preexec": {"ok": preexec.get("ok") is True, "kind": preexec.get("kind"),
                    "normal_return": preexec.get("normal_return") is True,
                    "gap": preexec.get("gap"),
                    "forbidden_events": preexec.get("forbidden_events", []),
                    "source_gaps": preexec.get("source_gaps", [])},
        "concurrent_command_events": event.get("concurrent_command_events", []),
    }


class BoundedWitnessService:
    """Freeze execution policy; models propose only classified conditional premises."""

    def __init__(
        self, index: RepositoryIndex, contexts: Mapping[str, WitnessExecutionContext],
        *, nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        self.index = index
        self.contexts = dict(contexts)
        self._nonce_factory = nonce_factory or (lambda: uuid4().hex)

    def supports(self, subject: ValidationSubject) -> bool:
        context = self.contexts.get(subject.repository_id)
        if (context is None or subject.property_id != "command-execution"
                or subject.source_digest != repository_source_digest(self.index)):
            return False
        draft = build_witness_manifest(
            self.index, subject, context,
            WitnessSupplement(constructor_parameters={}, precondition_files={}),
        )
        # Qualification describes the indexed entry, never a completed proof.
        if draft.generated.get("entry_qualified") is not True:
            return False
        if draft.manifest is not None:
            from cv_agent.evaluation.diagnostics.witness_contract import validate_witness_manifest
            try:
                validate_witness_manifest(self.index, subject, draft.manifest)
            except (OSError, ValueError):
                return False
        return True

    def _unresolved(
        self, subject: ValidationSubject | None, gaps: list[str], *,
        missing: tuple[str, ...] | list[str] = (), generated: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> ToolObservation:
        preparation = self._preparation(subject, gaps, provenance or {})
        visible = _visible_provenance(provenance or {})
        # Full hypotheses are already recorded in the original tool arguments.
        # Preparation reports only their digest and required field owners; all
        # classified values still accompany an actual execution result.
        visible["premises"] = []
        return ToolObservation(
            tool=TOOL_NAME, status="ok", validation_status=ValidationStatus.UNRESOLVED,
            subject=subject,
            metadata={"witness_attempted": False,
                      "preparation_generated": generated or {},
                      "preparation_provenance": provenance or {},
                      **({PREPARATION_METADATA_KEY: preparation.model_dump(mode="json")}
                         if preparation is not None else {})},
            content=_json({"status": ValidationStatus.UNRESOLVED.value,
                           "raw_status": "UNRESOLVED", "gaps": list(dict.fromkeys(gaps)),
                           "missing_constructor_parameters": missing,
                           "scope_note": _PREPARATION_SCOPE_NOTE,
                           "generated": {name: value for name, value in (generated or {}).items()
                                         if name in {"entry_qualified", "entry"}},
                           **({"preparation": preparation.model_dump(mode="json")}
                              if preparation is not None else {}), **visible}),
        )

    @staticmethod
    def _preparation(subject: ValidationSubject | None, gaps: list[str],
                     provenance: dict[str, Any]) -> ValidationPreparation | None:
        if subject is None:
            return None
        mode = "dataset_provided" if subject_has_scenario(subject) else "model_proposed"
        if set(gaps) == {"dataset_scenario_cannot_be_replaced"}:
            return ValidationPreparation(mode=mode, action="use_dataset_scenario")
        if (mode == "model_proposed" and provenance.get("scenario_sha256") is None
                and set(gaps) == {"probe_input_parameter_not_unique"}):
            return ValidationPreparation(mode=mode, action="propose_scenario", missing_inputs=(
                MissingValidationInput(name="input_parameter", destination="scenario_hypothesis", classified=True),
            ))
        fields = []
        for gap in dict.fromkeys(gaps):
            kind, separator, name = gap.partition(":")
            if not separator or kind not in {"entry_argument_missing", "constructor_parameter_missing"}:
                return None
            if kind == "entry_argument_missing":
                if mode != "model_proposed":
                    return None
                destination = "scenario_hypothesis.entry_value_assumptions"
            else:
                destination = ("scenario_hypothesis.constructor_parameters"
                               if mode == "model_proposed" else "constructor_parameters")
            fields.append(MissingValidationInput(name=name, destination=destination, classified=mode == "model_proposed"))
        return ValidationPreparation(mode=mode, action="complete_call_data", missing_inputs=tuple(fields)) if fields else None

    def handle(self, supplement: WitnessSupplement, scope: ToolExecutionScope) -> ToolObservation:
        subject = scope.subject
        if subject is None or scope.candidate_path != subject.entry_path:
            return self._unresolved(subject, ["witness_validation_subject_missing_or_mismatched"])
        if subject.entry_path not in scope.admitted_paths:
            return self._unresolved(subject, ["candidate_not_admitted"])
        if subject.property_id != "command-execution":
            return self._unresolved(subject, ["witness_property_not_supported"])
        if subject.source_digest != repository_source_digest(self.index):
            return self._unresolved(subject, ["witness_index_source_digest_mismatch"])
        context = self.contexts.get(subject.repository_id)
        if context is None:
            return self._unresolved(subject, ["witness_execution_context_missing"])
        scenario = supplement.scenario_hypothesis
        origin = "model_proposed" if scenario is not None else "dataset_provided"
        if scenario is not None and subject_has_scenario(subject):
            return self._unresolved(subject, ["dataset_scenario_cannot_be_replaced"], provenance={
                "scenario_origin": origin, "scenario": scenario.model_dump(mode="json"),
                "scenario_sha256": scenario.digest(), "original_subject": subject.model_dump(mode="json"),
            })
        if scenario is None and subject_has_scenario(subject) and context.dataset_scenario is None:
            return self._unresolved(subject, ["scenario_classification_missing"], provenance={
                "scenario_origin": "dataset_provided", "classification_status": "not_supplied",
            })
        if scenario is None and subject_has_scenario(subject) and context.dataset_scenario is not None:
            scenario = WitnessScenarioHypothesis.model_validate(context.dataset_scenario.model_dump())
            if scenario.execution_subject(subject) != subject:
                return self._unresolved(subject, ["dataset_scenario_classification_subject_mismatch"])
        execution_subject = scenario.execution_subject(subject) if scenario is not None else subject
        provenance = {
            "scenario_origin": origin if scenario is not None or subject_has_scenario(subject) else None,
            "classification_status": "complete" if scenario is not None else "not_supplied",
            "scenario": scenario.model_dump(mode="json") if scenario is not None else None,
            "scenario_sha256": scenario.digest() if scenario is not None else None,
            "original_subject": subject.model_dump(mode="json"),
            "execution_subject": execution_subject.model_dump(mode="json"),
        }
        draft = build_witness_manifest(self.index, execution_subject, context, supplement,
            scenario=scenario, scenario_origin=origin if scenario is not None else None,
            original_subject=subject if scenario is not None else None)
        if draft.manifest is None or draft.gaps:
            return self._unresolved(subject, list(draft.gaps),
                                    missing=draft.missing_constructor_parameters,
                                    generated=draft.generated, provenance=provenance)
        manifest = draft.manifest
        if scenario is not None and origin == "dataset_provided":
            declared_files = scenario.values("precondition_files")
            if declared_files != supplement.precondition_files:
                return self._unresolved(subject, ["dataset_scenario_file_supplement_mismatch"],
                                        provenance=provenance)
            declared_constructor = scenario.values("constructor_parameters")
            if any(name not in declared_constructor or not _same_json(value, declared_constructor[name])
                   for name, value in supplement.constructor_parameters.items()):
                return self._unresolved(subject, ["dataset_scenario_constructor_supplement_mismatch"],
                                        provenance=provenance)
        from cv_agent.evaluation.diagnostics.bounded_execution_witness import run_witness
        from cv_agent.evaluation.diagnostics.witness_contract import (
            PositiveOnlyWitnessProofScope, validate_witness_manifest,
        )
        try:
            validate_witness_manifest(self.index, execution_subject, manifest)
        except (OSError, ValueError) as error:
            return self._unresolved(subject, ["witness_source_binding_failed:" + str(error)], provenance=provenance)
        context.runtime_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        # Snapshot pairs can share concrete probe/control paths under a trusted
        # runtime. Complete artifacts live in private sibling directories, so
        # the target cannot consume an earlier version's measured result.
        artifact_root = Path(tempfile.mkdtemp(
            prefix=context.runtime_root.name + "-witness-artifact-",
            dir=context.runtime_root.parent,
        ))
        nonce = self._nonce_factory()
        result = run_witness(
            manifest, nonce=nonce, verify_obligations=True, derive_recorder=True,
            diagnostic_runtime_dir=context.runtime_root, diagnostic_read_grants=context.read_grants,
        )
        if (result.status not in {ValidationStatus.CONFIRMED, ValidationStatus.UNRESOLVED}
                or (result.status == ValidationStatus.CONFIRMED
                    and (result.raw_status != "EXPANDED_OBSERVED" or result.gaps))):
            raise ValueError("witness returned a status outside its positive-only contract")
        manifest_data = manifest.model_dump(mode="json")
        manifest_digest = hashlib.sha256(_json(manifest_data).encode()).hexdigest()
        verification = _scenario_verification(result.details)
        artifact = artifact_root / "witness-result.json"
        _write_private_json(artifact, {
            "producer": TOOL_NAME, "manifest_origin": "system_ast",
            **provenance, "scenario_verification": verification,
            "model_supplement": supplement.model_dump(mode="json"),
            "manifest_sha256": manifest_digest, "manifest": manifest_data,
            "execution_context": {"checkout_root": str(context.checkout_root),
                                  "python_executable": str(context.python_executable),
                                  "resource_profile": context.resource_profile.model_dump(mode="json"),
                                  "read_grants": [grant.model_dump(mode="json")
                                                  for grant in context.read_grants]},
            "generated": draft.generated, "result": result.model_dump(mode="json"),
        })
        details = result.details
        payload = {
            **_visible_provenance(provenance),
            "scenario_verification": {
                "remote_authority_established": False, "authority_scope": "local_caller_hypothesis",
                **{phase: {"ok": verification[phase]["ok"], "gaps": verification[phase]["gaps"]}
                   for phase in ("probe", "control")},
            },
            "status": result.status.value, "raw_status": result.raw_status,
            "gaps": result.gaps, "artifact_path": str(artifact),
            "manifest_sha256": manifest_digest, "manifest_origin": "system_ast",
            "subject_source_digest": subject.source_digest,
            "source_module_count": len(manifest.source_modules),
            "resource_profile": manifest.resource_profile.model_dump(mode="json"),
            "probe": _verification_summary(details.get("probe_event", {}), context.checkout_root),
            "control": _verification_summary(details.get("control_event", {}), context.checkout_root),
            "probe_replay": details.get("probe_replay"),
            "control_replay": details.get("control_replay"),
            "claim_eligible": False,
            "scope_note": _scope_note(verification, details),
        }
        return ToolObservation(
            tool=TOOL_NAME, status="ok", validation_status=result.status, subject=subject,
            fixture_proof=PositiveOnlyWitnessProofScope(), content=_json(payload),
            evidence_ids=(f"witness:{subject.candidate_id}:{manifest_digest}",),
            metadata={"manifest_origin": "system_ast", "artifact_path": str(artifact),
                      "manifest_sha256": manifest_digest, "claim_eligible": False,
                      "witness_attempted": True, "scenario_origin": provenance["scenario_origin"],
                      "scenario_sha256": provenance["scenario_sha256"],
                      # Private producer telemetry survives delivery clipping
                      # for experiment stop rules; it is not supporting proof.
                      "witness_result_status": result.status.value},
        )
