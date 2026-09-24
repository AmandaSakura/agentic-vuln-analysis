"""Evidence admissibility and prediction/validation consistency policy."""
from __future__ import annotations

import json
from collections import Counter

from cv_agent.domain.evidence import ReActStep, ToolObservation, ValidationStatus, ValidationSubject
from cv_agent.domain.review import AgentExpertConclusion


def validate_conclusion(
    output: AgentExpertConclusion, trace: list[ReActStep],
    initial_evidence_ids: frozenset[str], required_validators: tuple[str, ...] = (),
    current_trace: list[ReActStep] | None = None,
    subject: ValidationSubject | None = None,
) -> None:
    observations = [
        step.observation for step in trace
        if step.observation.status == "ok"
        and not step.observation.metadata.get("model_payload_suppressed")
    ]
    known = set(initial_evidence_ids)
    for observation in observations:
        known.update(observation.evidence_ids)
        if observation.citation_id:
            known.add(observation.citation_id)
    referenced_ids = {
        *output.evidence_ids,
        *output.supporting_observation_ids,
        *output.counter_observation_ids,
        *output.unresolved_observation_ids,
    }
    if referenced_ids - known:
        available = sorted(item.citation_id for item in observations if item.citation_id)
        raise ValueError(
            f"Unknown evidence reference: {', '.join(sorted(referenced_ids - known))}. "
            f"Available tool citations: {', '.join(available) or 'none'}. "
            "Use only a listed successful tool citation or retrieved evidence ID. "
            "Blocked/error calls are not evidence. Remove an unsupported reference "
            "from every citation array; do not invent a replacement."
        )
    roles = {
        "supporting_observation_ids": set(output.supporting_observation_ids),
        "counter_observation_ids": set(output.counter_observation_ids),
        "unresolved_observation_ids": set(output.unresolved_observation_ids),
    }
    # A citation and the tool's evidence ID may identify the same observation.
    # The general evidence_ids bibliography is intentionally not a fourth role.
    identities = [{reference} for reference in referenced_ids]
    identities.extend(
        {*item.evidence_ids, *([item.citation_id] if item.citation_id else [])}
        for item in observations
    )
    conflicts = set()
    for identity in identities:
        used_roles = [name for name, references in roles.items() if references & identity]
        if len(used_roles) > 1:
            references = identity & set().union(*(roles[name] for name in used_roles))
            conflicts.add(f"{', '.join(sorted(references))}: {' / '.join(used_roles)}")
    errors = []
    if conflicts:
        errors.append(
            "Conflicting observation roles: " + "; ".join(sorted(conflicts)) + ". "
            "Assign each observation to exactly one explicit role; remove its citation "
            "and aliases from the other role arrays. evidence_ids may still list it. "
            "UNRESOLVED validation_status does not require listing supporting evidence "
            "again in unresolved_observation_ids. Keep the label only if the evidence "
            "checks below also support it."
        )
    try:
        _validate_prediction(output, observations, trace, required_validators, current_trace, subject)
    except ValueError as error:
        errors.append(str(error))
    if errors:
        raise ValueError(" ".join(errors))


def _validate_prediction(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
    trace: list[ReActStep],
    required_validators: tuple[str, ...],
    current_trace: list[ReActStep] | None,
    subject: ValidationSubject | None,
) -> None:
    if output.label != "ABSTAIN" and not output.evidence_ids:
        raise ValueError("A material prediction must cite observed evidence.")
    executed = Counter(
        step.observation.tool for step in (current_trace if current_trace is not None else trace)
        if step.observation.status == "ok"
        and not step.observation.metadata.get("observation_truncated")
    )
    if Counter(required_validators) - executed:
        raise ValueError("Assigned validation tools must complete before finalizing the expert tasks.")
    concrete_labels = {
        'VULNERABLE' if item.validation_status == ValidationStatus.CONFIRMED else 'SAFE'
        for item in observations
        if subject is not None and item.subject == subject
        and not item.metadata.get('observation_truncated')
        and item.validation_status in {ValidationStatus.CONFIRMED, ValidationStatus.REFUTED}
    }
    if output.label != 'ABSTAIN' and concrete_labels - {output.label}:
        raise ValueError('Prediction contradicts concrete validator evidence for this candidate and scope; resolve the conflict or abstain.')
    if output.label == "VULNERABLE" and _contradicts_observed_command_evidence(
        output, observations
    ):
        raise ValueError(
            "Prediction contradicts observed command-construction counter-evidence; "
            "cite supporting command construction evidence, resolve the conflict, or abstain."
        )
    if output.label == "VULNERABLE" and _relies_on_unestablished_taint_without_command_support(
        output, observations
    ):
        raise ValueError(
            "A NOT_ESTABLISHED taint trace and sink listings do not support a "
            "VULNERABLE prediction; inspect command construction evidence or abstain."
        )
    if output.label != "ABSTAIN" and _relies_on_static_permission_without_validator(
        output, observations, subject
    ):
        raise ValueError(
            "Static chmod mode matching or an inconclusive permission check does not "
            "support a material permission prediction; cite complete candidate-bound "
            "validate_permission_mode evidence or abstain. Changing citation roles or "
            "omitting the check cannot bypass this requirement."
        )
    if output.label != "ABSTAIN" and _relies_on_static_command_without_inspection(
        output, observations
    ):
        raise ValueError(
            "Static command-execution sink matching does not support a material "
            "prediction; cite inspect_command_construction evidence or abstain."
        )
    if (
        output.label == "SAFE"
        and output.validation_status == ValidationStatus.UNRESOLVED
        and _safe_prediction_lacks_affirmative_evidence(output, observations, subject)
    ):
        raise ValueError(
            "SAFE/UNRESOLVED requires affirmative counter-evidence; empty searches, "
            "missing graph neighbors, static no-finding results, or source reads alone "
            "must be reported as ABSTAIN/UNRESOLVED. "
            "Evidence supporting SAFE belongs in supporting_observation_ids, not "
            "counter_observation_ids or unresolved_observation_ids. Counter means "
            "against your predicted label, not against the vulnerability hypothesis."
        )
    if output.validation_status == ValidationStatus.UNRESOLVED:
        return
    expected = {
        ValidationStatus.CONFIRMED: "VULNERABLE", ValidationStatus.REFUTED: "SAFE",
    }[output.validation_status]
    if output.label != expected:
        raise ValueError("Validation status contradicts the prediction label.")
    missing_bibliography = [
        item.citation_id for item in _supporting_observations(output, observations)
        if item.citation_id and subject is not None and item.subject == subject
        and not item.metadata.get("observation_truncated")
        and item.validation_status == output.validation_status
        and not set(output.evidence_ids) & {*item.evidence_ids, item.citation_id}
    ]
    referenced = [
        item for item in _supporting_observations(output, observations)
        if not item.metadata.get("observation_truncated")
        and set(output.evidence_ids) & {*item.evidence_ids, item.citation_id}
        and item.validation_status not in {None, ValidationStatus.UNRESOLVED}
    ]
    if not referenced or any(item.validation_status != output.validation_status for item in referenced):
        if not referenced and missing_bibliography:
            raise ValueError(
                "CONFIRMED/REFUTED requires matching cited validator output in evidence_ids. "
                "These matching validator citations appear in supporting_observation_ids "
                "but are missing from evidence_ids: " + ", ".join(missing_bibliography)
                + ". Include the supporting validator citation in evidence_ids too; "
                "a local source reference alone is not a validator citation."
            )
        raise ValueError(
            "CONFIRMED/REFUTED requires matching cited validator output; "
            "reading code alone only supports validation_status=UNRESOLVED."
        )
    if subject is None or any(item.subject != subject for item in referenced):
        raise ValueError("Confirmed/refuted evidence subject must match this candidate and source snapshot")


def _json_object(content: str) -> dict | None:
    try:
        value = json.loads(content)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _supporting_observations(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
) -> list[ToolObservation]:
    # evidence_ids is a general bibliography; explicit counter/undecided roles
    # must not silently become support for the proposed label.
    supporting = {*output.evidence_ids, *output.supporting_observation_ids}
    other_roles = {*output.counter_observation_ids, *output.unresolved_observation_ids}
    return [item for item in observations
            if supporting & {*item.evidence_ids, item.citation_id}
            and not other_roles & {*item.evidence_ids, item.citation_id}]


def _has_affirmative_safe_evidence(
    observation: ToolObservation, subject: ValidationSubject | None,
) -> bool:
    if observation.metadata.get("observation_truncated"):
        return False
    if observation.subject is not None and observation.subject != subject:
        return False
    if observation.validation_status == ValidationStatus.REFUTED:
        return subject is not None and observation.subject == subject
    if observation.validation_status == ValidationStatus.CONFIRMED:
        return False
    content = _json_object(observation.content)
    if content is None:
        return False
    # These signals support a safety hypothesis, never typed refutation. Search
    # hits, potential sinks, inconclusive probes and another revision's repair
    # provide no affirmative counter-evidence for the current snapshot.
    if observation.tool == "get_guards":
        return bool(content.get("guards"))
    if observation.tool == "find_sanitizers":
        return bool(content.get("findings"))
    if observation.tool == "compare_route_and_service_guard":
        return content.get("recognized_guard_precedes_actions") is True
    if observation.tool == "inspect_command_construction":
        return content.get("command_construction_status") == "SANITIZED"
    return False


def _safe_prediction_lacks_affirmative_evidence(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
    subject: ValidationSubject | None,
) -> bool:
    referenced = _supporting_observations(output, observations)
    return not any(_has_affirmative_safe_evidence(item, subject) for item in referenced)


def _command_status(observation: ToolObservation) -> str | None:
    if observation.metadata.get("observation_truncated"):
        return None
    if observation.tool != "inspect_command_construction":
        return None
    content = _json_object(observation.content)
    if content is None:
        return None
    status = content.get("command_construction_status")
    return status if isinstance(status, str) else None


def _contradicts_observed_command_evidence(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
) -> bool:
    referenced = _supporting_observations(output, observations)
    if any(_command_status(observation) == "UNSANITIZED" for observation in referenced):
        return False
    return any(_command_status(observation) == "SANITIZED" for observation in referenced)


def _relies_on_unestablished_taint_without_command_support(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
) -> bool:
    referenced = _supporting_observations(output, observations)
    if any(_command_status(observation) == "UNSANITIZED" for observation in referenced):
        return False
    for observation in referenced:
        if observation.tool != "trace_dataflow":
            continue
        content = _json_object(observation.content)
        if content is not None and content.get("flow_status") == "NOT_ESTABLISHED":
            return True
    return False


def _relies_on_static_permission_without_validator(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
    subject: ValidationSubject | None,
) -> bool:
    referenced = _supporting_observations(output, observations)
    permission_observed = False
    cites_permission_validator = False
    for observation in observations:
        content = _json_object(observation.content)
        if content is None:
            continue
        candidate_bound = subject is not None and (
            observation.subject == subject
            or f"permission_mode:{subject.entry_path}" in observation.evidence_ids
            or content.get("path") == subject.entry_path
        )
        if observation.tool == "validate_permission_mode" and (candidate_bound or subject is None):
            permission_observed = True
        if (observation.tool == "run_static_check" and "permission_mode_check" in content
                and (candidate_bound or observation in referenced)):
            permission_observed = True
        if (
            observation.tool == "validate_permission_mode"
            and observation in referenced
            and subject is not None and observation.subject == subject
            and not observation.metadata.get("observation_truncated")
            and observation.validation_status in {
                ValidationStatus.CONFIRMED,
                ValidationStatus.REFUTED,
            }
        ):
            cites_permission_validator = True
    return permission_observed and not cites_permission_validator


def _relies_on_static_command_without_inspection(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
) -> bool:
    referenced = _supporting_observations(output, observations)
    cites_static_command = False
    cites_command_inspection = False
    observed_get_cmd = False
    for observation in referenced:
        if "get_cmd" in observation.content:
            observed_get_cmd = True
        content = _json_object(observation.content)
        if content is None:
            continue
        if observation.tool == "run_static_check":
            findings = content.get("findings")
            if isinstance(findings, list) and any(
                isinstance(item, dict)
                and item.get("category") == "command-execution"
                for item in findings
            ):
                cites_static_command = True
        if observation.tool == "inspect_command_construction" and _command_status(
            observation
        ) in {"SANITIZED", "UNSANITIZED"}:
            cites_command_inspection = True
    return cites_static_command and observed_get_cmd and not cites_command_inspection
