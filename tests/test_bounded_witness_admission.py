"""A bounded witness must not turn one literal observation into candidate SAFE."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from cv_agent.agents.evidence_policy import fixture_can_support_candidate, validate_conclusion
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import FixtureProofScope, ReActStep, ValidationStatus, ValidationSubject
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.harness import FULL_SYSTEM_HARNESS
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation import FixtureCase, FixtureOutcome, full_agent_tools
from cv_agent.domain.types import Candidate, CodeDocument
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.validation.witness_scenario import WitnessScenarioHypothesis
from test_witness_scope_notes import reported_scenario, scenario_projection
from cv_agent.runtime.witness.kernel import SourceFileBinding, WitnessManifest
from cv_agent.runtime.witness.contract import bounded_witness_fixture_case


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


@pytest.mark.parametrize("quoted", [False, True])
def test_classified_real_fixture_adapter_measures_inputs_and_preserves_control(tmp_path, quoted):
    expression = "shlex.quote(model_uri)" if quoted else "model_uri"
    source = ("import subprocess\nimport shlex\nclass Entry:\n"
              "    def serve(self, model_uri):\n"
              f'        subprocess.Popen(["bash", "-c", f"record {{{expression}}}"])\n')
    source_file = tmp_path / "entry.py"
    source_file.write_text(source)
    digest = hashlib.sha256(source.encode()).hexdigest()
    span = "entry.py::Entry.serve@4-5"
    index = RepositoryIndex((CodeDocument(repository_id="neutral", path=span,
        text="".join(source.splitlines(keepends=True)[3:5]), language="python", source_sha256=digest),))
    candidate = Candidate(candidate_id="neutral", case_id="neutral", repository_id="neutral", path=span,
                          line=4, query="entry", property_id="command-execution", input_parameters=("model_uri",))
    subject = candidate_subject(index, candidate)
    scenario = WitnessScenarioHypothesis.model_validate({
        "input_parameter": {"value": "model_uri", "classification": "attacker_controlled_input",
                            "rationale": "The fixture caller supplies an existing local directory."},
    })
    manifest = WitnessManifest(subject=subject, original_subject=subject, scenario_hypothesis=scenario,
        scenario_origin="dataset_provided", checkout_root=tmp_path, module_name="entry", class_name="Entry",
        method_name="serve", entry_relative_path="entry.py", entry_file_sha256=digest, entry_first_line=4,
        source_modules=(SourceFileBinding(module_name="entry", relative_path="entry.py", sha256=digest),),
        probe_argument="model_uri", recorder_command="record")
    fixture = bounded_witness_fixture_case(index, candidate, manifest)
    registry = ToolRegistry(full_agent_tools(index, fixture_cases=(fixture,)),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)
    call = ModelToolCall(call_id="actual-fixture", name="run_fixture_test", arguments={"case_id": fixture.case_id})
    observation = registry.invoke(call, allowed=("run_fixture_test",), scope=ToolExecutionScope(
        admitted_paths=frozenset({span}), candidate_path=span, subject=subject,
        max_observation_tokens=FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens), citation_id="fixture:actual")
    expected = ValidationStatus.UNRESOLVED if quoted else ValidationStatus.CONFIRMED
    assert observation.status == "ok", observation.content
    assert observation.validation_status == expected, observation.content
    payload = json.loads(observation.content)
    details = payload["details"]
    assert scenario_projection(details) == reported_scenario(scenario.model_dump(mode="json"))
    assert details["remote_authority_established"] is False
    artifact = json.loads(Path(details["artifact_path"]).read_text())
    worker = artifact["result"]["details"]["probe_event"]
    assert worker["assumption_verification"]["scenario_data"]["input_parameter"]["matched"] is True
    conclusion = AgentExpertConclusion(expert="scan", label="VULNERABLE", confidence=.9,
        validation_status=ValidationStatus.CONFIRMED, evidence_ids=(observation.citation_id,),
        supporting_observation_ids=(observation.citation_id,), rationale="Use the conditional measured witness.")
    trace = [ReActStep(step=1, model_id="offline", tool_call=call, observation=observation)]
    if quoted:
        with pytest.raises(ValueError):
            validate_conclusion(conclusion, trace, initial_evidence_ids=frozenset(), subject=subject)
    else:
        validate_conclusion(conclusion, trace, initial_evidence_ids=frozenset(), subject=subject)
