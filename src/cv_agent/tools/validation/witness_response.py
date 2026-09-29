"""Compact reporting of one measured, classified model scenario.

The reference names the scenario in this tool call's assistant message. Exact
source bindings, premises and worker records remain in the server observation
and its private report; this projection does not change evidence admission.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any


def compact_witness_preparation(payload: dict[str, Any]) -> dict[str, Any]:
    """Group call-data names without changing the producer's typed protocol."""
    result = {
        "raw_status": payload["raw_status"], "gaps": payload["gaps"],
        "witness_attempted": False, "scope_note": "No witness has executed.",
        "missing_constructor_parameters": payload["missing_constructor_parameters"], "premises": [],
    }
    # Preparation cannot supply proof. Its exact scene digest stays in the
    # producer metadata; repeating it here would crowd out required field names.
    for field in ("scenario_origin",):
        if payload.get(field) is not None:
            result[field] = payload[field]
    preparation = payload.get("preparation")
    if preparation is not None:
        grouped: dict[tuple[str, bool], list[str]] = {}
        for item in preparation["missing_inputs"]:
            grouped.setdefault((item["destination"], item["classified"]), []).append(item["name"])
        result["preparation"] = {
            **{field: preparation[field] for field in ("state", "mode", "action")},
            "missing_inputs": [{"destination": destination, "classified": classified, "names": names}
                               for (destination, classified), names in grouped.items()],
        }
    return result


def compact_witness_response(payload: dict[str, Any], *, details: dict[str, Any]) -> dict[str, Any]:
    if payload.get("scenario_origin") != "model_proposed" or payload.get("classification_status") != "complete":
        raise ValueError("compact witness requires a complete classified model-proposed scenario")
    for field in ("manifest_sha256", "subject_source_digest", "scenario_sha256"):
        value = payload.get(field)
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("compact witness requires complete source, manifest and scenario bindings")
    verification = payload["scenario_verification"]
    if verification.get("remote_authority_established") is not False:
        raise ValueError("compact witness cannot establish remote authority")
    verified = all(verification.get(phase, {}).get("ok") is True for phase in ("probe", "control"))
    observed = {
        phase: event.get("phase") == "invoke" and isinstance(event.get("candidate_frame"), dict)
        and event.get("authentic_subprocess_popen") is True and not event.get("loaded_source_gaps")
        for phase in ("probe", "control")
        for event in (details.get(phase + "_event", {}),)
    }
    if all(observed.values()) and verified:
        scope_note = "Concrete input observed; premises verified."
    elif any(observed.values()):
        scope_note = "Candidate observed; premises not all verified."
    else:
        scope_note = "Attempted; candidate and premises unestablished."
    event = details.get("probe_event", {})
    argv = event.get("argv")
    command_hash = (hashlib.sha256(json.dumps(argv, sort_keys=True, separators=(",", ":"),
                                            allow_nan=False).encode()).hexdigest()
                    if isinstance(argv, list) else None)
    prefix = (argv[2][:20] if isinstance(argv, list) and len(argv) > 2
              and argv[1] == "-c" and type(argv[2]) is str else None)
    emitter = event.get("emitter_frame")
    result = {
        "raw_status": payload["raw_status"], "gaps": payload["gaps"],
        "scenario_origin": payload["scenario_origin"],
        "classified_scenario_ref": {"arguments": "/scenario_hypothesis", "sha256": payload["scenario_sha256"]},
        "manifest_sha256": payload["manifest_sha256"], "remote_authority_established": False,
        "premises_verified": verified,
        "emitter": emitter.get("qualname") if isinstance(emitter, dict) else None,
        "command_sha256": command_hash, "command_prefix": prefix, "scope_note": scope_note,
    }
    adapter = payload.get("entry_adapter")
    if adapter is not None and adapter.get("invocation") == "click_callback":
        if adapter.get("scope") != "direct_click_callback" or adapter.get("public_parser_executed") is not False:
            raise ValueError("compact callback witness cannot establish public CLI parser execution")
        result["scope_note"] = "Direct callback; CLI parser not executed. " + scope_note
        result["public_parser_executed"] = False
        # The full manifest digest remains in server telemetry and the private
        # complete response. Its source/proof binding is unchanged; the small
        # callback projection spends those bytes on the explicit parser scope.
        result.pop("manifest_sha256")
    return result
