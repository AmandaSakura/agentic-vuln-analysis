"""HTTP response measurements cannot impersonate arbitrary candidate proofs."""

import json

import pytest

from cv_agent.agents.evidence_policy import validate_conclusion
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import (
    FixtureProofScope,
    ReActStep,
    ToolObservation,
    ValidationStatus,
    ValidationSubject,
)
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.validation.fixtures import loopback
from cv_agent.tools.validation.models import CaseInput, LoopbackCase, LoopbackRequest, LoopbackResponse


def _subject(property_id: str) -> ValidationSubject:
    return ValidationSubject(
        candidate_id="loopback-candidate",
        repository_id="r",
        property_id=property_id,
        entry_path="entry.py",
        source_digest="d" * 64,
    )


def _proof(property_id: str, *, method: str = "bounded_execution") -> FixtureProofScope:
    return FixtureProofScope(
        contract_id="two-request-authorization-case",
        property_id=property_id,
        coverage="candidate",
        method=method,
        supported_statuses=(ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
    )


def _all_open(request: LoopbackRequest) -> LoopbackResponse:
    del request
    return LoopbackResponse(status=200, body=b"action completed")


def _guarded(request: LoopbackRequest) -> LoopbackResponse:
    if request.headers.get("Authorization"):
        return LoopbackResponse(status=200, body=b"action completed")
    return LoopbackResponse(status=403, body=b"forbidden")


def _observe(subject, application, proof_scope):
    case = LoopbackCase(
        case_id="case",
        application=application,
        subject=subject,
        proof_scope=proof_scope,
    )
    observation = loopback(
        {case.case_id: case},
        CaseInput(case_id=case.case_id),
        ToolExecutionScope(
            admitted_paths=frozenset({subject.entry_path}),
            candidate_path=subject.entry_path,
            subject=subject,
            max_observation_tokens=10_000,
        ),
    )
    return observation.model_copy(update={"citation_id": "loopback:case"})


def _admit(observation, subject, label):
    status = ValidationStatus.CONFIRMED if label == "VULNERABLE" else ValidationStatus.REFUTED
    conclusion = AgentExpertConclusion(
        expert="scan",
        label=label,
        confidence=0.9,
        validation_status=status,
        evidence_ids=(observation.citation_id,),
        supporting_observation_ids=(observation.citation_id,),
        rationale="Use the registered bounded HTTP case.",
    )
    trace = [ReActStep(
        step=1,
        model_id="offline",
        tool_call=ModelToolCall(call_id="loopback", name=observation.tool, arguments={"case_id": "case"}),
        observation=observation,
    )]
    validate_conclusion(conclusion, trace, initial_evidence_ids=frozenset(), subject=subject)


@pytest.mark.parametrize("property_id,application,raw_status,label", [
    ("command-execution", _all_open, "CONFIRMED", "VULNERABLE"),
    ("authorization-boundary", _guarded, "REFUTED", "SAFE"),
])
def test_loopback_without_proof_scope_keeps_only_local_http_measurement(property_id, application, raw_status, label):
    subject = _subject(property_id)
    observation = _observe(subject, application, None)
    payload = json.loads(observation.content)
    assert observation.status == "ok"
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert payload["status"] == "UNRESOLVED"
    assert payload["raw_status"] == raw_status
    assert payload["proof_scope_error"] == "missing_proof_scope"
    assert payload["details"]["bind_host"] == "127.0.0.1"
    with pytest.raises(ValueError):
        _admit(observation, subject, label)


def test_loopback_contract_cannot_claim_command_execution_from_http_codes():
    subject = _subject("command-execution")
    observation = _observe(subject, _all_open, _proof("command-execution"))
    payload = json.loads(observation.content)
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert payload["raw_status"] == "CONFIRMED"
    assert payload["proof_scope_error"] == "unsupported_property:command-execution"
    with pytest.raises(ValueError):
        _admit(observation, subject, "VULNERABLE")

    # Consumer also rejects a hand-built strong observation that bypasses the
    # producer's downgrade, including a matching but semantically false scope.
    forged = observation.model_copy(update={
        "validation_status": ValidationStatus.CONFIRMED,
        "content": json.dumps({"status": "CONFIRMED"}),
    })
    with pytest.raises(ValueError):
        _admit(forged, subject, "VULNERABLE")


@pytest.mark.parametrize("application,raw_status,label", [
    (_all_open, ValidationStatus.CONFIRMED, "VULNERABLE"),
    (_guarded, ValidationStatus.REFUTED, "SAFE"),
])
def test_registered_authorization_loopback_preserves_candidate_proof(application, raw_status, label):
    subject = _subject("authorization-boundary")
    observation = _observe(subject, application, _proof("authorization-boundary"))
    payload = json.loads(observation.content)
    assert observation.validation_status == raw_status
    assert payload["status"] == raw_status.value
    assert "raw_status" not in payload
    assert observation.fixture_proof is not None
    _admit(observation, subject, label)


def test_unknown_tool_name_with_matching_subject_cannot_mint_typed_proof():
    subject = _subject("authorization-boundary")
    observation = ToolObservation(
        tool="unregistered_test_validator",
        status="ok",
        content="locally constructed answer",
        citation_id="loopback:case",
        validation_status=ValidationStatus.CONFIRMED,
        subject=subject,
    )
    with pytest.raises(ValueError):
        _admit(observation, subject, "VULNERABLE")
