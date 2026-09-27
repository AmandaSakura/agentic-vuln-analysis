"""Fixture output distinguishes a raw measurement from candidate proof."""

import json

import pytest

from cv_agent.agents.evidence_policy import validate_conclusion
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import FixtureProofScope, ReActStep, ValidationStatus, ValidationSubject
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.validation.fixtures import fixture
from cv_agent.tools.validation.models import CaseInput, FixtureCase, FixtureOutcome


SUBJECT = ValidationSubject(
    property_id="command-execution",
    candidate_id="fixture-candidate",
    repository_id="r",
    entry_path="entry.py",
    source_digest="fixture-source-digest",
)

PROOF = FixtureProofScope(
    contract_id="closed-candidate-test",
    property_id="command-execution",
    coverage="candidate",
    method="bounded_execution",
    supported_statuses=(ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
)


def _observe(raw_status, *, proof_scope, scoped_subject):
    case = FixtureCase(
        case_id="offline",
        runner=lambda: FixtureOutcome(
            status=raw_status,
            summary="bounded local measurement",
            details={"observed": True},
        ),
        subject=SUBJECT,
        proof_scope=proof_scope,
    )
    observation = fixture(
        {case.case_id: case},
        CaseInput(case_id=case.case_id),
        ToolExecutionScope(
            admitted_paths=frozenset({SUBJECT.entry_path}),
            candidate_path=SUBJECT.entry_path if scoped_subject is not None else None,
            subject=scoped_subject,
            max_observation_tokens=10_000,
        ),
    )
    return observation.model_copy(update={"citation_id": "fixture:offline"})


def _conclude(observation, label):
    conclusion = AgentExpertConclusion(
        expert="scan",
        label=label,
        confidence=0.9,
        validation_status=ValidationStatus.CONFIRMED if label == "VULNERABLE" else ValidationStatus.REFUTED,
        evidence_ids=(observation.citation_id,),
        supporting_observation_ids=(observation.citation_id,),
        rationale="Use the candidate-scoped fixture result.",
    )
    trace = [ReActStep(
        step=1,
        model_id="offline",
        tool_call=ModelToolCall(call_id="fixture", name="run_fixture_test", arguments={"case_id": "offline"}),
        observation=observation,
    )]
    validate_conclusion(conclusion, trace, initial_evidence_ids=frozenset(), subject=SUBJECT)


@pytest.mark.parametrize("raw_status,label", [
    (ValidationStatus.CONFIRMED, "VULNERABLE"),
    (ValidationStatus.REFUTED, "SAFE"),
])
def test_missing_proof_scope_downgrades_both_statuses_and_rejects_vote(raw_status, label):
    observation = _observe(raw_status, proof_scope=None, scoped_subject=SUBJECT)
    payload = json.loads(observation.content)
    assert observation.status == "ok"
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert payload["status"] == "UNRESOLVED"
    assert payload["raw_status"] == raw_status.value
    assert payload["proof_scope_error"] == "missing_proof_scope"
    assert payload["details"] == {"observed": True}
    with pytest.raises(ValueError):
        _conclude(observation, label)


def test_candidate_proof_contract_without_scope_subject_is_diagnostic_only():
    observation = _observe(ValidationStatus.CONFIRMED, proof_scope=PROOF, scoped_subject=None)
    payload = json.loads(observation.content)
    assert observation.status == "ok"
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert payload["status"] == "UNRESOLVED"
    assert payload["raw_status"] == "CONFIRMED"
    assert payload["proof_scope_error"] == "missing_validation_subject"
    with pytest.raises(ValueError):
        _conclude(observation, "VULNERABLE")


@pytest.mark.parametrize("raw_status,label", [
    (ValidationStatus.CONFIRMED, "VULNERABLE"),
    (ValidationStatus.REFUTED, "SAFE"),
])
def test_matching_candidate_proof_still_emits_and_admits_status(raw_status, label):
    observation = _observe(raw_status, proof_scope=PROOF, scoped_subject=SUBJECT)
    payload = json.loads(observation.content)
    assert observation.status == "ok"
    assert observation.validation_status == raw_status
    assert payload["status"] == raw_status.value
    assert "raw_status" not in payload
    _conclude(observation, label)
