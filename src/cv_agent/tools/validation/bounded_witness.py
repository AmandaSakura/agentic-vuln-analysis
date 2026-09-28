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
from cv_agent.tools.validation.witness_manifest import (
    WitnessExecutionContext,
    WitnessSupplement,
    build_witness_manifest,
)
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import repository_source_digest
from cv_agent.tools.registry import ToolExecutionScope


TOOL_NAME = "run_bounded_execution_witness"
_SCOPE_NOTE = (
    "The caller can create and supply an existing local directory path with shell "
    "metacharacters in its name. The observation covers this concrete input under "
    "the declared candidate assumptions; remote reachability remains unestablished."
)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _write_private_json(path: Path, value: Any) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(_json(value))
        stream.write("\n")


def _verification_summary(event: dict[str, Any]) -> dict[str, Any]:
    assumptions = event.get("assumption_verification", {})
    values = assumptions.get("values", {})
    conditions = assumptions.get("conditions", {})
    preexec = event.get("preexec_verification", {})
    candidate = event.get("candidate_frame")
    emitter = event.get("emitter_frame")
    return {
        "event": event.get("event"), "phase": event.get("phase"),
        "argv": event.get("argv"),
        "candidate_frame": candidate, "emitter_frame": emitter,
        "authentic_subprocess_popen": event.get("authentic_subprocess_popen") is True,
        "seccomp_selftest": event.get("seccomp_selftest") is True,
        "hook_selftest": event.get("hook_selftest") is True,
        "source_gaps": event.get("loaded_source_gaps", []),
        "values_verified": values.get("verified", []),
        "conditions": [{"expression": item.get("expression"),
                         "actual_values": item.get("actual_values"),
                         "line": item.get("line"), "module": item.get("module")}
                        for item in conditions.get("observations", [])],
        "assumption_gaps": assumptions.get("gaps", []),
        "preexec": {"ok": preexec.get("ok") is True, "kind": preexec.get("kind"),
                    "normal_return": preexec.get("normal_return") is True,
                    "gap": preexec.get("gap"),
                    "forbidden_events": preexec.get("forbidden_events", []),
                    "source_gaps": preexec.get("source_gaps", [])},
        "concurrent_command_events": event.get("concurrent_command_events", []),
    }


class BoundedWitnessService:
    """Freeze runtime authorization in the factory; models supply only missing data."""

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
    ) -> ToolObservation:
        return ToolObservation(
            tool=TOOL_NAME, status="ok", validation_status=ValidationStatus.UNRESOLVED,
            subject=subject,
            metadata={"witness_attempted": False},
            content=_json({"status": ValidationStatus.UNRESOLVED.value,
                           "raw_status": "UNRESOLVED", "gaps": list(dict.fromkeys(gaps)),
                           "missing_constructor_parameters": missing,
                           "scope_note": _SCOPE_NOTE,
                           "generated": generated or {}}),
        )

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
        draft = build_witness_manifest(self.index, subject, context, supplement)
        if draft.manifest is None or draft.gaps:
            return self._unresolved(subject, list(draft.gaps),
                                    missing=draft.missing_constructor_parameters,
                                    generated=draft.generated)
        manifest = draft.manifest
        from cv_agent.evaluation.diagnostics.bounded_execution_witness import run_witness
        from cv_agent.evaluation.diagnostics.witness_contract import (
            PositiveOnlyWitnessProofScope, validate_witness_manifest,
        )
        try:
            validate_witness_manifest(self.index, subject, manifest)
        except (OSError, ValueError) as error:
            return self._unresolved(subject, ["witness_source_binding_failed:" + str(error)])
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
        artifact = artifact_root / "witness-result.json"
        _write_private_json(artifact, {
            "producer": TOOL_NAME, "manifest_origin": "system_ast",
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
            "status": result.status.value, "raw_status": result.raw_status,
            "gaps": result.gaps, "artifact_path": str(artifact),
            "manifest_sha256": manifest_digest, "manifest_origin": "system_ast",
            "subject_source_digest": subject.source_digest,
            "source_module_count": len(manifest.source_modules),
            "resource_profile": manifest.resource_profile.model_dump(mode="json"),
            "probe": _verification_summary(details.get("probe_event", {})),
            "control": _verification_summary(details.get("control_event", {})),
            "probe_replay": details.get("probe_replay"),
            "control_replay": details.get("control_replay"),
            "claim_eligible": False,
            "scope_note": _SCOPE_NOTE,
        }
        return ToolObservation(
            tool=TOOL_NAME, status="ok", validation_status=result.status, subject=subject,
            fixture_proof=PositiveOnlyWitnessProofScope(), content=_json(payload),
            evidence_ids=(f"witness:{subject.candidate_id}:{manifest_digest}",),
            metadata={"manifest_origin": "system_ast", "artifact_path": str(artifact),
                      "manifest_sha256": manifest_digest, "claim_eligible": False,
                      "witness_attempted": True},
        )
