"""Evidence admissibility and prediction/validation consistency policy."""
from __future__ import annotations

import json
import re
from collections import Counter

from cv_agent.domain.evidence import (
    FixtureProofScope,
    ReActStep,
    ToolObservation,
    ValidationStatus,
    ValidationSubject,
)
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.tools.identity import local_source_line


class InsufficientEvidenceError(ValueError):
    """Raised when a material prediction lacks the required affirmative evidence chain."""
    def __init__(self, message: str, *, reason_code: str, required_evidence: str):
        super().__init__(message)
        self.reason_code = reason_code
        self.required_evidence = required_evidence


class IncompleteValidationTaskError(ValueError):
    """Raised when assigned validation tools did not complete before finalization."""
    def __init__(self, message: str, *, missing_validators: tuple[str, ...] = ()):
        super().__init__(message)
        self.missing_validators = tuple(missing_validators)


def validator_observation_completed(observation: ToolObservation) -> bool:
    """A manifest-preparation reply is not an executed witness validator."""
    return (observation.status == "ok"
            and not observation.metadata.get("observation_truncated")
            and not observation.metadata.get("model_payload_suppressed")
            and (observation.tool != "run_bounded_execution_witness"
                 or observation.metadata.get("witness_attempted") is True))


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
    except (InsufficientEvidenceError, IncompleteValidationTaskError) as error:
        if errors:
            raise ValueError(" ".join(errors) + " " + str(error))
        raise
    except ValueError as error:
        errors.append(str(error))
    if errors:
        raise ValueError(" ".join(errors))


def _has_successful_observation(
    trace: list[ReActStep], current_trace: list[ReActStep] | None,
) -> bool:
    """Whether the expert task delivered one successful typed observation (C6).

    Blocked/error calls, truncated payloads, suppressed (undelivered) results
    and retrieval snippets are not successful observations. An unrelated
    successful call satisfies this floor only; candidate-bound proof is still
    enforced by the gates below, so one irrelevant success cannot substitute
    for the required evidence.
    """
    steps = current_trace if current_trace is not None else trace
    return any(
        step.observation.status == "ok"
        and not step.observation.metadata.get("observation_truncated")
        and not step.observation.metadata.get("model_payload_suppressed")
        for step in steps
    )


def _validate_prediction(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
    trace: list[ReActStep],
    required_validators: tuple[str, ...],
    current_trace: list[ReActStep] | None,
    subject: ValidationSubject | None,
) -> None:
    if output.label != "ABSTAIN" and not _has_successful_observation(trace, current_trace):
        raise InsufficientEvidenceError(
            "A material prediction requires at least one successful typed tool "
            "observation; blocked, truncated, suppressed or retrieval-only "
            "evidence cannot support it.",
            reason_code="no_successful_observation",
            required_evidence="successful tool observation",
        )
    if output.label != "ABSTAIN" and not output.evidence_ids:
        raise InsufficientEvidenceError(
            "A material prediction must cite observed evidence.",
            reason_code="missing_evidence",
            required_evidence="observed evidence",
        )
    if output.label != "ABSTAIN" and subject is not None and subject.entry_line is not None:
        line = _candidate_local_line(subject)
        for observation in observations:
            content = _json_object(observation.content)
            if (observation.tool == "inspect_command_construction" and content is not None
                    and content.get("source_path") == subject.entry_path
                    and type(content.get("source_line_count")) is int
                    and not 1 <= line <= content["source_line_count"]):
                raise ValueError("Evidence subject location is outside the inspected source slice")
    executed = Counter(
        step.observation.tool for step in (current_trace if current_trace is not None else trace)
        if validator_observation_completed(step.observation)
    )
    if Counter(required_validators) - executed:
        missing = tuple(sorted(Counter(required_validators) - executed))
        raise IncompleteValidationTaskError(
            f"Assigned validation tools must complete before finalizing the expert tasks. Missing: {', '.join(missing)}",
            missing_validators=missing,
        )
    command_proofs = {_command_status(item, subject) for item in observations}
    if output.label != "ABSTAIN" and subject is not None and {"SANITIZED", "UNSANITIZED"} <= command_proofs:
        # A single inspection may contain safe and unsafe paths (overall
        # UNSANITIZED). Two whole-scope inspections claiming both overall
        # safety and a complete dangerous path instead require reconciliation.
        raise InsufficientEvidenceError(
            "Candidate has conflicting command proofs for the same scope; reconcile them or abstain.",
            reason_code="conflicting_command_proofs",
            required_evidence="reconciled command proof scope",
        )
    concrete_labels = {
        'VULNERABLE' if item.validation_status == ValidationStatus.CONFIRMED else 'SAFE'
        for item in observations
        if _matches_validator_subject(item, subject)
        and not item.metadata.get('observation_truncated')
        and item.validation_status in {ValidationStatus.CONFIRMED, ValidationStatus.REFUTED}
    }
    if output.label != 'ABSTAIN' and concrete_labels - {output.label}:
        raise InsufficientEvidenceError(
            'Prediction contradicts concrete validator evidence for this candidate and scope; resolve the conflict or abstain.',
            reason_code="contradicts_concrete_validator",
            required_evidence="reconciled validator evidence",
        )
    expected_proof = {"VULNERABLE": ValidationStatus.CONFIRMED, "SAFE": ValidationStatus.REFUTED}.get(output.label)
    cited_proof = any(
        _matches_validator_subject(item, subject)
        and item.validation_status == expected_proof
        and not item.metadata.get("observation_truncated")
        and set(output.evidence_ids) & {*item.evidence_ids, item.citation_id}
        for item in _supporting_observations(output, observations)
    )
    missing_bibliography = [
        item.citation_id for item in _supporting_observations(output, observations)
        if item.citation_id and _matches_validator_subject(item, subject)
        and not item.metadata.get("observation_truncated")
        and item.validation_status == output.validation_status
        and not set(output.evidence_ids) & {*item.evidence_ids, item.citation_id}
    ]
    if (output.validation_status in {ValidationStatus.CONFIRMED, ValidationStatus.REFUTED}
            and not cited_proof and missing_bibliography):
        raise ValueError(
            "CONFIRMED/REFUTED requires matching cited validator output in evidence_ids. "
            "These matching validator citations appear in supporting_observation_ids "
            "but are missing from evidence_ids: " + ", ".join(missing_bibliography)
            + ". Include the supporting validator citation in evidence_ids too; "
            "a local source reference alone is not a validator citation."
        )
    if output.label != "ABSTAIN" and subject is not None and any(
        (item.tool in {"validate_permission_mode", "probe_python_eval"}
         and item.validation_status in {ValidationStatus.CONFIRMED, ValidationStatus.REFUTED}
         and not _matches_validator_subject(item, subject))
        or (item.tool == "inspect_command_construction" and subject.property_id != "command-execution")
        for item in _supporting_observations(output, observations)
    ):
        raise InsufficientEvidenceError(
            "A local validator fact outside the candidate property or location cannot "
            "support this prediction; cite evidence for the declared subject or abstain.",
            reason_code="local_fact_outside_candidate",
            required_evidence="candidate-bound property proof",
        )
    if (output.label != "ABSTAIN" and subject is not None
            and subject.property_id not in {None, "command-execution", "chmod-mode-others-write"}
            and not cited_proof):
        raise InsufficientEvidenceError(
            "The declared candidate property requires a matching cited proof; "
            "a local fact about a different property cannot supply it.",
            reason_code="unproved_candidate_property",
            required_evidence="candidate-bound property proof",
        )
    if not cited_proof and output.label == "VULNERABLE" and _contradicts_observed_command_evidence(
        output, observations, subject
    ):
        raise InsufficientEvidenceError(
            "Prediction contradicts observed command-construction counter-evidence; "
            "cite supporting command construction evidence, resolve the conflict, or abstain.",
            reason_code="contradicts_command_counter_evidence",
            required_evidence="supporting command construction evidence",
        )
    if not cited_proof and output.label == "VULNERABLE" and _relies_on_unestablished_taint_without_command_support(
        output, observations, subject
    ):
        raise InsufficientEvidenceError(
            "A NOT_ESTABLISHED taint trace and sink listings do not support a "
            "VULNERABLE prediction; inspect command construction evidence or abstain.",
            reason_code="unestablished_taint_without_command_support",
            required_evidence="inspect_command_construction",
        )
    if output.label != "ABSTAIN" and _relies_on_static_permission_without_validator(
        output, observations, subject
    ):
        raise InsufficientEvidenceError(
            "Static chmod mode matching or an inconclusive permission check does not "
            "support a material permission prediction; cite complete candidate-bound "
            "validate_permission_mode evidence or abstain. Changing citation roles or "
            "omitting the check cannot bypass this requirement.",
            reason_code="static_permission_without_validator",
            required_evidence="validate_permission_mode",
        )
    if not cited_proof and output.label != "ABSTAIN" and _relies_on_static_command_without_inspection(
        output, observations, subject
    ):
        raise InsufficientEvidenceError(
            "Static command-execution sink matching does not support a material "
            "prediction; cite inspect_command_construction evidence or abstain. "
            "If no shell was established, trace_dataflow with sink_category='command-execution' "
            "can supply candidate-bound flow evidence for non-shell execution. "
            "SAFE requires affirmative counter-evidence for this command property "
            "in supporting_observation_ids; counter_observation_ids and "
            "unresolved_observation_ids do not supply affirmative support.",
            reason_code="static_command_without_inspection",
            required_evidence="inspect_command_construction",
        )
    if (
        output.label == "SAFE"
        and output.validation_status == ValidationStatus.UNRESOLVED
        and _safe_prediction_lacks_affirmative_evidence(output, observations, subject)
    ):
        raise InsufficientEvidenceError(
            "SAFE/UNRESOLVED requires affirmative counter-evidence; empty searches, "
            "missing graph neighbors, static no-finding results, or source reads alone "
            "must be reported as ABSTAIN/UNRESOLVED. "
            "Evidence supporting SAFE belongs in supporting_observation_ids, not "
            "counter_observation_ids or unresolved_observation_ids. Counter means "
            "against your predicted label, not against the vulnerability hypothesis.",
            reason_code="safe_lacks_affirmative_evidence",
            required_evidence="affirmative counter-evidence",
        )
    if output.validation_status == ValidationStatus.UNRESOLVED:
        return
    expected = {
        ValidationStatus.CONFIRMED: "VULNERABLE", ValidationStatus.REFUTED: "SAFE",
    }[output.validation_status]
    if output.label != expected:
        raise ValueError("Validation status contradicts the prediction label.")
    referenced = [
        item for item in _supporting_observations(output, observations)
        if not item.metadata.get("observation_truncated")
        and set(output.evidence_ids) & {*item.evidence_ids, item.citation_id}
        and item.validation_status not in {None, ValidationStatus.UNRESOLVED}
    ]
    if not referenced or any(item.validation_status != output.validation_status for item in referenced):
        raise ValueError(
            "CONFIRMED/REFUTED requires matching cited validator output; "
            "reading code alone only supports validation_status=UNRESOLVED."
        )
    if any(not _matches_validator_subject(item, subject) for item in referenced):
        raise ValueError("Confirmed/refuted evidence subject must match this candidate and source snapshot")


def fixture_can_support_candidate(
    proof: FixtureProofScope | None,
    subject: ValidationSubject | None,
    status: ValidationStatus | None,
) -> bool:
    return (
        proof is not None
        and subject is not None
        and proof.coverage == "candidate"
        and proof.method != "source_pattern"
        and proof.property_id == subject.property_id
        and status in proof.supported_statuses
        and status in {ValidationStatus.CONFIRMED, ValidationStatus.REFUTED}
    )


def _matches_validator_subject(observation: ToolObservation, subject: ValidationSubject | None) -> bool:
    if subject is None or observation.subject != subject:
        return False
    if observation.tool == "run_bounded_execution_witness":
        proof = observation.fixture_proof
        return (subject.property_id == "command-execution"
                and observation.validation_status == ValidationStatus.CONFIRMED
                and proof is not None
                and proof.contract_id == "bounded-execution-witness-v1"
                and proof.method == "bounded_execution"
                and proof.supported_statuses == (ValidationStatus.CONFIRMED,)
                and fixture_can_support_candidate(proof, subject, observation.validation_status))
    if observation.tool == "run_fixture_test":
        return fixture_can_support_candidate(
            observation.fixture_proof,
            subject,
            observation.validation_status,
        )
    if observation.tool == "run_loopback_http_case":
        # This tool observes one authorized and one unauthorized HTTP
        # response. Even a registrant-supplied proof contract cannot turn
        # those status codes into command, permission, or other proof.
        return (
            subject.property_id == "authorization-boundary"
            and observation.fixture_proof is not None
            and observation.fixture_proof.method == "bounded_execution"
            and fixture_can_support_candidate(
                observation.fixture_proof,
                subject,
                observation.validation_status,
            )
        )
    if observation.tool == "validate_permission_mode":
        return subject.property_id == "chmod-mode-others-write"
    if observation.tool == "probe_python_eval":
        return subject.property_id == "dynamic-evaluation"
    return False


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
    if observation.tool == "inspect_command_construction":
        return _command_status(observation, subject) == "SANITIZED"
    if observation.subject is not None and observation.subject != subject:
        return False
    if observation.validation_status == ValidationStatus.REFUTED:
        return _matches_validator_subject(observation, subject)
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
    return local_source_line(subject.entry_path, subject.entry_line)


def _function_scope(content: dict, subject: ValidationSubject) -> bool:
    line = _candidate_local_line(subject)
    if line is None:
        return True
    if "function_header_lines" in content:
        return line in content["function_header_lines"]
    # Legacy synthetic observations lack parsed source coordinates. Current
    # tools always provide them; this fallback is not used for indexed source.
    return line == 1


def _command_status(observation: ToolObservation, subject: ValidationSubject | None = None) -> str | None:
    if subject is not None and subject.property_id != "command-execution":
        return None
    if observation.metadata.get("observation_truncated"):
        return None
    if observation.tool != "inspect_command_construction":
        return None
    if subject is not None:
        if observation.subject is None:
            return None
        # The tool analyzes the complete source function; line selection is
        # applied to its facts below. Candidate, snapshot, inputs and scope
        # must still match, even when a narrower line is selected afterward.
        if observation.subject.model_copy(update={"entry_line": subject.entry_line}) != subject:
            return None
    content = _json_object(observation.content)
    if content is None:
        return None
    if subject is not None and content.get("source_path") not in {None, subject.entry_path}:
        return None
    facts = [fact for fact in content.get("sink_facts", []) if isinstance(fact, dict)]
    if subject is not None and subject.entry_line is not None and isinstance(content.get("sink_facts"), list):
        local_line = _candidate_local_line(subject)
        if local_line is not None and local_line < 1:
            return None
        if not _function_scope(content, subject):
            facts = [
                fact for fact in facts
                if fact.get("path") == subject.entry_path and fact.get("line") == local_line
            ]
        elif subject.entry_path:
            # Whole-function scope must retain reachable helper sinks: a helper
            # that executes attacker-controlled input stays fatal even when the
            # caller's own sinks are sanitized. Helper facts are reachable by
            # construction (admitted callees inlined on actual calls); the
            # helper path set below only re-admits them after scoping.
            helper_paths = {
                helper.get("path")
                for helper in content.get("helpers", [])
                if isinstance(helper, dict)
            } | {
                evidence_id.split("command_helper:", 1)[1]
                for evidence_id in observation.evidence_ids
                if "command_helper:" in evidence_id
            }
            facts = [
                fact for fact in facts
                if fact.get("path") == subject.entry_path or fact.get("path") in helper_paths
            ]
    statuses = {
        "SANITIZED" if fact.get("status") == "NOT_ESTABLISHED" and fact.get("numeric_argv") is True
        else fact.get("status") for fact in facts
    }
    if content.get("issues"):
        # One unsafe path remains evidence even when a later path is unsupported.
        # Safety still requires complete interpretation of every candidate path.
        if "UNSANITIZED" in statuses:
            return "UNSANITIZED"
        # A visited non-shell sink also survives a later effect gap. It is
        # never safety proof: VULNERABLE still requires its candidate-bound
        # command flow, and a numeric-argv safety fact cannot bypass the gap.
        if statuses == {"NOT_ESTABLISHED"}:
            return "NOT_ESTABLISHED"
        return "AMBIGUOUS"
    if subject is not None and subject.entry_line is not None and isinstance(content.get("sink_facts"), list):
        # Safety must cover every sink on the candidate line. An unresolved
        # non-shell sink cannot inherit a neighboring sink's protection.
        return next((status for status in ("UNSANITIZED", "AMBIGUOUS", "NOT_ESTABLISHED", "SANITIZED") if status in statuses), None)
    if facts:
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
    # Full-trace gate: candidate-bound SANITIZED observed anywhere still
    # contradicts VULNERABLE, even when omitted from supporting citations or
    # placed in a counter role. _command_status already enforces candidate /
    # path / line binding, so helper-local safety (different source_path)
    # returns None and does not block; a caller with its own cited UNSANITIZED
    # evidence returns False above via referenced UNSANITIZED. Subject is
    # required here: without a candidate identity, an incidental SANITIZED
    # (e.g. helper-local minimal payload) must not veto an unrelated claim.
    if subject is not None and any(
        _command_status(observation, subject) == "SANITIZED"
        for observation in observations
    ):
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
    if subject is not None and subject.property_id not in {None, "chmod-mode-others-write"}:
        return False
    referenced = _supporting_observations(output, observations)
    permission_observed = subject is not None and subject.property_id == "chmod-mode-others-write"
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
            and _matches_validator_subject(observation, subject)
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
        local_line = _candidate_local_line(subject)
        matching = [item for item in findings if item.get("line") == local_line]
        if matching:
            return matching
        if local_line == 1:
            return findings
        return matching
    return findings


def _candidate_is_command_weakness(
    observations: list[ToolObservation], subject: ValidationSubject | None,
) -> bool:
    if subject is not None and subject.property_id is not None:
        return subject.property_id == "command-execution"
    if subject is not None and subject.entry_line is not None:
        local_line = _candidate_local_line(subject)
        whole_function = any(
            obs.tool == "inspect_command_construction"
            and not obs.metadata.get("observation_truncated")
            and obs.subject is not None
            and obs.subject.model_copy(update={"entry_line": subject.entry_line}) == subject
            and (content := _json_object(obs.content)) is not None
            and content.get("source_path") == subject.entry_path
            and _function_scope(content, subject)
            for obs in observations
        )
        if local_line is not None and local_line > 1 and not whole_function:
            has_line_static = any(
                f.get("category") == "command-execution"
                for obs in observations
                for f in _candidate_static_findings(obs, subject)
            )
            has_line_sink = any(
                obs.tool == "inspect_command_construction"
                and any(
                    f.get("line") == local_line and f.get("path") in {None, subject.entry_path}
                    for f in (_json_object(obs.content) or {}).get("sink_facts", [])
                )
                for obs in observations
            )
            return has_line_static or has_line_sink

    if any(
        f.get("category") == "command-execution"
        for obs in observations
        for f in _candidate_static_findings(obs, subject)
    ):
        return True
    if any(
        obs.tool == "inspect_command_construction"
        and not obs.metadata.get("observation_truncated")
        for obs in observations
    ):
        return True
    if subject is None:
        return False
    if subject.analysis_scope and any(kw in subject.analysis_scope for kw in ("command", "subprocess", "Popen", "os.system", "os.popen", "shell")):
        return True
    return False


def _relies_on_static_command_without_inspection(
    output: AgentExpertConclusion,
    observations: list[ToolObservation],
    subject: ValidationSubject | None,
) -> bool:
    if not _candidate_is_command_weakness(observations, subject):
        return False
    referenced = _supporting_observations(output, observations)
    for observation in referenced:
        status = _command_status(observation, subject)
        if output.label == "SAFE" and status == "SANITIZED":
            return False
        if output.label == "VULNERABLE":
            if status == "UNSANITIZED":
                return False
            if status == "NOT_ESTABLISHED" and _has_candidate_command_flow(referenced, subject):
                return False
    # The property determines the proof obligation. Static matches, guard
    # patterns, helper names and citation choices cannot replace that proof.
    # A separate, matching concrete validator is handled by the caller.
    return True


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
