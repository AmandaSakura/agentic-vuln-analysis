"""Evidence admissibility and prediction/validation consistency policy."""
from __future__ import annotations

import json
import re
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
    expected_proof = {"VULNERABLE": ValidationStatus.CONFIRMED, "SAFE": ValidationStatus.REFUTED}.get(output.label)
    cited_proof = any(
        subject is not None and item.subject == subject
        and item.validation_status == expected_proof
        and not item.metadata.get("observation_truncated")
        and set(output.evidence_ids) & {*item.evidence_ids, item.citation_id}
        for item in _supporting_observations(output, observations)
    )
    if not cited_proof and output.label == "VULNERABLE" and _contradicts_observed_command_evidence(
        output, observations, subject
    ):
        raise ValueError(
            "Prediction contradicts observed command-construction counter-evidence; "
            "cite supporting command construction evidence, resolve the conflict, or abstain."
        )
    if not cited_proof and output.label == "VULNERABLE" and _relies_on_unestablished_taint_without_command_support(
        output, observations, subject
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
    if not cited_proof and output.label != "ABSTAIN" and _relies_on_static_command_without_inspection(
        output, observations, subject
    ):
        raise ValueError(
            "Static command-execution sink matching does not support a material "
            "prediction; cite inspect_command_construction evidence or abstain. "
            "If no shell was established, trace_dataflow with sink_category='command-execution' "
            "can supply candidate-bound flow evidence for non-shell execution."
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
        findings = content.get("findings")
        if not isinstance(findings, list) or not findings:
            return False
        if subject is not None and content.get("path") and content.get("path") != subject.entry_path:
            return observation.subject == subject and any(
                isinstance(flow, dict)
                and flow.get("source_path") == subject.entry_path
                and flow.get("helper_path") == content["path"]
                and (subject.entry_line is None or flow.get("sink_line") == subject.entry_line)
                and flow.get("sanitizer_lines")
                for flow in content.get("candidate_sanitizer_flows", [])
            )
        return True
    if observation.tool == "compare_route_and_service_guard":
        return content.get("recognized_guard_precedes_actions") is True
    if observation.tool == "inspect_command_construction":
        return _command_status(observation, subject) == "SANITIZED"
    return False


def _safe_prediction_lacks_affirmative_evidence(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
    subject: ValidationSubject | None,
) -> bool:
    referenced = _supporting_observations(output, observations)
    return not any(_has_affirmative_safe_evidence(item, subject) for item in referenced)


def _candidate_local_line(subject: ValidationSubject) -> int | None:
    if subject.entry_line is None:
        return None
    span = re.search(r"::.+@(\d+)(?:-\d+)?(?:#\d+-\d+)?$", subject.entry_path)
    return subject.entry_line - (int(span.group(1)) - 1 if span else 0)


def _command_status(observation: ToolObservation, subject: ValidationSubject | None = None) -> str | None:
    if observation.metadata.get("observation_truncated"):
        return None
    if observation.tool != "inspect_command_construction":
        return None
    content = _json_object(observation.content)
    if content is None:
        return None
    if subject is not None and content.get("source_path") not in {None, subject.entry_path}:
        return None
    facts = [fact for fact in content.get("sink_facts", []) if isinstance(fact, dict)]
    if subject is not None and subject.entry_line is not None and isinstance(content.get("sink_facts"), list):
        facts = [fact for fact in facts if fact.get("path") == subject.entry_path
            and fact.get("line") == _candidate_local_line(subject)
        ]
    statuses = {
        "SANITIZED" if fact.get("status") == "NOT_ESTABLISHED" and fact.get("numeric_argv") is True
        else fact.get("status") for fact in facts
    }
    if content.get("issues"):
        # One unsafe path remains evidence even when a later path is unsupported.
        # Safety still requires complete interpretation of every candidate path.
        return "UNSANITIZED" if "UNSANITIZED" in statuses else "AMBIGUOUS"
    if subject is not None and subject.entry_line is not None and isinstance(content.get("sink_facts"), list):
        # Safety must cover every sink on the candidate line. An unresolved
        # non-shell sink cannot inherit a neighboring sink's protection.
        return next((status for status in ("UNSANITIZED", "AMBIGUOUS", "NOT_ESTABLISHED", "SANITIZED") if status in statuses), None)
    status = content.get("command_construction_status")
    return status if isinstance(status, str) else None


def _contradicts_observed_command_evidence(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
    subject: ValidationSubject | None,
) -> bool:
    referenced = _supporting_observations(output, observations)
    statuses = {_command_status(observation, subject) for observation in referenced}
    if "UNSANITIZED" in statuses or "AMBIGUOUS" in statuses:
        return False
    if "SANITIZED" in statuses and subject is not None and subject.entry_line is not None:
        return True
    findings = [finding for observation in observations
                for finding in _candidate_static_findings(observation, subject)]
    has_scoped_static = any(
        observation.tool == "run_static_check"
        and not observation.metadata.get("observation_truncated")
        and (content := _json_object(observation.content)) is not None
        and isinstance(content.get("findings"), list)
        and (subject is None or content.get("path") in {None, subject.entry_path})
        for observation in observations
    )
    if (findings or (has_scoped_static and subject is not None and subject.entry_line is not None)) and not any(
        item.get("category") == "command-execution" for item in findings
    ):
        return False
    if any(_command_status(observation, subject) == "UNSANITIZED" for observation in referenced):
        return False
    return any(_command_status(observation, subject) == "SANITIZED" for observation in referenced)


def _relies_on_unestablished_taint_without_command_support(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
    subject: ValidationSubject | None,
) -> bool:
    referenced = _supporting_observations(output, observations)
    if any(_command_status(observation, subject) == "UNSANITIZED" for observation in referenced):
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


def _candidate_static_findings(
    observation: ToolObservation, subject: ValidationSubject | None,
) -> list[dict]:
    if observation.tool != "run_static_check":
        return []
    content = _json_object(observation.content)
    if content is None or not isinstance(content.get("findings"), list):
        return []
    if subject is not None and content.get("path") not in {None, subject.entry_path}:
        return []
    findings = [item for item in content["findings"] if isinstance(item, dict)]
    if subject is not None and subject.entry_line is not None:
        # Static findings use slice-local lines; candidate identity uses file lines.
        return [item for item in findings if item.get("line") == _candidate_local_line(subject)]
    # Only subjects without a candidate line use document-level findings.
    return findings


def _relies_on_static_command_without_inspection(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
    subject: ValidationSubject | None,
) -> bool:
    referenced = _supporting_observations(output, observations)
    observed_static_command = any(
        finding.get("category") == "command-execution"
        for observation in observations
        for finding in _candidate_static_findings(observation, subject)
    )
    cites_command_inspection = False
    observed_command_inspection = False
    observed_command_helper = False
    for observation in referenced:
        if (
            "get_cmd" in observation.content
            or "build_cmd" in observation.content
            or any("command_helper:" in eid for eid in observation.evidence_ids)
        ):
            observed_command_helper = True
        if observation.tool == "inspect_command_construction" and not observation.metadata.get("observation_truncated"):
            observed_command_inspection = True
            status = _command_status(observation, subject)
            if output.label == "VULNERABLE" and status == "UNSANITIZED":
                cites_command_inspection = True
            elif output.label == "VULNERABLE" and status == "NOT_ESTABLISHED" and _has_candidate_command_flow(referenced, subject):
                # No shell established does not refute tainted interpreter argv.
                cites_command_inspection = True
            elif output.label == "SAFE" and status == "SANITIZED":
                cites_command_inspection = True
        content = _json_object(observation.content)
        if content is None:
            continue
        if observation.tool == "run_static_check":
            if subject is not None and content.get("path") not in {None, subject.entry_path}:
                continue
            if content.get("callee") in {"get_cmd", "build_cmd"}:
                observed_command_helper = True
    return observed_static_command and (observed_command_helper or observed_command_inspection) and not cites_command_inspection


def _has_candidate_command_flow(observations: list[ToolObservation], subject: ValidationSubject | None) -> bool:
    if subject is None or subject.entry_line is None:
        return False
    for observation in observations:
        if observation.tool != "trace_dataflow" or observation.metadata.get("observation_truncated"):
            continue
        if observation.subject is not None and observation.subject != subject:
            continue
        content = _json_object(observation.content)
        if content is None or content.get("flow_status") != "MAY_REACH":
            continue
        for entry in content.get("trace", []):
            if not isinstance(entry, dict) or entry.get("path") != subject.entry_path:
                continue
            if any(isinstance(sink, dict) and sink.get("category") == "command-execution"
                   and sink.get("line") == _candidate_local_line(subject) and sink.get("tainted") is True
                   for sink in entry.get("sinks", [])):
                return True
    return False
