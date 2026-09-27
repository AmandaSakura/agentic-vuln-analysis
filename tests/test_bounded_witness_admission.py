"""A bounded witness must not turn one literal observation into candidate SAFE."""

from __future__ import annotations

import json

import pytest

from cv_agent.agents.evidence_policy import fixture_can_support_candidate, validate_conclusion
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import FixtureProofScope, ReActStep, ValidationStatus, ValidationSubject
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.harness import FULL_SYSTEM_HARNESS
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation import FixtureCase, FixtureOutcome, full_agent_tools


SUBJECT = ValidationSubject(
    property_id="command-execution",
    candidate_id="synthetic-command-entry",
    repository_id="synthetic-repository",
    entry_path="synthetic/entry.py",
    entry_line=10,
    source_digest="synthetic-index-digest",
)
POSITIVE_ONLY_PROOF = FixtureProofScope(
    contract_id="bounded-execution-witness-v1",
    property_id="command-execution",
    coverage="candidate",
    method="bounded_execution",
    supported_statuses=(ValidationStatus.CONFIRMED,),
)


def _observe(status: ValidationStatus, raw_status: str):
    case = FixtureCase(
        case_id="synthetic-witness",
        runner=lambda: FixtureOutcome(
            status=status,
            summary="synthetic bounded execution witness",
            details={"raw_status": raw_status},
        ),
        subject=SUBJECT,
        proof_scope=POSITIVE_ONLY_PROOF,
    )
    registry = ToolRegistry(
        full_agent_tools(RepositoryIndex(), fixture_cases=(case,)),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )
    call = ModelToolCall(
        call_id="synthetic-witness-call",
        name="run_fixture_test",
        arguments={"case_id": case.case_id},
    )
    observation = registry.invoke(
        call,
        allowed=("run_fixture_test",),
        scope=ToolExecutionScope(
            admitted_paths=frozenset({SUBJECT.entry_path}),
            candidate_path=SUBJECT.entry_path,
            subject=SUBJECT,
            max_observation_tokens=FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens,
        ),
    )
    return call, observation.model_copy(update={"citation_id": "fixture:synthetic-witness"})


def _conclude(call: ModelToolCall, observation, *, label: str) -> None:
    status = ValidationStatus.CONFIRMED if label == "VULNERABLE" else ValidationStatus.REFUTED
    conclusion = AgentExpertConclusion(
        expert="scan",
        label=label,
        confidence=0.9,
        validation_status=status,
        evidence_ids=(observation.citation_id,),
        supporting_observation_ids=(observation.citation_id,),
        rationale="Use the bounded execution witness.",
    )
    validate_conclusion(
        conclusion,
        [ReActStep(step=1, model_id="offline", tool_call=call, observation=observation)],
        initial_evidence_ids=frozenset(),
        required_validators=(),
        subject=SUBJECT,
    )


@pytest.mark.parametrize("label", ["SAFE", "VULNERABLE"])
def test_literal_witness_is_diagnostic_only_through_real_fixture_tool(label):
    call, observation = _observe(ValidationStatus.UNRESOLVED, "LITERAL_OBSERVED")
    assert observation.status == "ok"
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert json.loads(observation.content)["details"]["raw_status"] == "LITERAL_OBSERVED"
    assert not fixture_can_support_candidate(
        observation.fixture_proof, observation.subject, observation.validation_status,
    )
    with pytest.raises(ValueError):
        _conclude(call, observation, label=label)


def test_refuted_output_is_rejected_by_positive_only_proof_scope():
    call, observation = _observe(ValidationStatus.REFUTED, "LITERAL_OBSERVED")
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert json.loads(observation.content)["proof_scope_error"] == "unsupported_status:REFUTED"
    with pytest.raises(ValueError):
        _conclude(call, observation, label="SAFE")


def test_positive_witness_still_supports_candidate_vulnerable_vote():
    call, observation = _observe(ValidationStatus.CONFIRMED, "EXPANDED_OBSERVED")
    assert observation.validation_status == ValidationStatus.CONFIRMED
    assert fixture_can_support_candidate(
        observation.fixture_proof, observation.subject, observation.validation_status,
    )
    _conclude(call, observation, label="VULNERABLE")
