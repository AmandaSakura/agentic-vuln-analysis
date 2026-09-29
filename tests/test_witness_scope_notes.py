"""Conditional witness scope reports declarations separately from measurements."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from cv_agent.domain.evidence import ValidationStatus
from cv_agent.tools.validation.bounded_witness import _visible_provenance
from cv_agent.tools.validation.witness_scenario import WitnessScenarioHypothesis


SCENARIO_MAPS = (
    "entry_boolean_arguments", "entry_condition_assumptions", "entry_value_assumptions",
    "constructor_parameters", "precondition_files",
)


def scenario_projection(payload):
    """Reverse the transport projection, including escaped names and empty maps."""
    scenario = {field: {} for field in SCENARIO_MAPS}
    seen = set()
    for premise in payload["premises"]:
        pointer = premise["name"]
        assert pointer.startswith("/") and pointer not in seen
        seen.add(pointer)
        parts = [part.replace("~1", "/").replace("~0", "~")
                 for part in pointer[1:].split("/")]
        item = {key: value for key, value in premise.items() if key != "name"}
        if parts == ["input_parameter"]:
            scenario["input_parameter"] = item
        else:
            assert len(parts) == 2 and parts[0] in SCENARIO_MAPS
            scenario[parts[0]][parts[1]] = item
    assert "input_parameter" in scenario
    return scenario


def reported_scenario(proposal):
    """Expected old nested projection, independently derived from the raw proposal."""
    scenario = WitnessScenarioHypothesis.model_validate(proposal).model_dump(mode="json")
    for field, values in scenario.items():
        items = [values] if field == "input_parameter" else values.values()
        for premise in items:
            premise.pop("rationale")
            encoded = json.dumps(premise["value"], sort_keys=True, separators=(",", ":"),
                                 allow_nan=False).encode("utf-8")
            if len(encoded) > 512:
                premise["value"] = {"sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded)}
                premise["value_representation"] = "canonical_json_sha256"
    return scenario


@pytest.mark.parametrize("renamed", [False, True])
def test_each_executed_scope_has_one_complete_classified_premise_projection(tmp_path, renamed):
    if renamed:
        from test_witness_scenario_generalization import _inputs, _proposal, _run
        index, candidate, context = _inputs(tmp_path / "repo")
        proposal = _proposal()
        verdict, _ = _run(index, candidate, context, proposal)
        observation = verdict.votes[0].trace[0].observation
    else:
        from test_witness_scenario import inputs, execute, scenario
        index, candidate, _, registry = inputs(tmp_path)
        proposal = scenario()
        _, observation, _ = execute(index, candidate, registry, proposal)
    assert observation.validation_status == ValidationStatus.CONFIRMED, observation.content
    payload = json.loads(observation.content)
    assert "scenario" not in payload
    assert scenario_projection(payload) == reported_scenario(proposal)
    assert payload["scope_note"] == (
        "This observation covers only the executed concrete input under the listed premises; "
        "remote reachability is not established."
    )
    assert payload["scenario_verification"]["remote_authority_established"] is False
    artifact = json.loads(Path(payload["artifact_path"]).read_text())
    assert artifact["scenario"] == WitnessScenarioHypothesis.model_validate(proposal).model_dump(mode="json")
    assert artifact["scenario_sha256"] == payload["scenario_sha256"]
    assert "premises" not in artifact


@pytest.mark.parametrize("length", [510, 511])
def test_value_summary_keeps_exact_existing_512_byte_boundary(length):
    from test_witness_scenario import scenario
    proposal = scenario()
    proposal["constructor_parameters"]["options"]["value"] = "x" * length
    normalized = WitnessScenarioHypothesis.model_validate(proposal).model_dump(mode="json")
    displayed = _visible_provenance({"scenario": normalized, "scenario_sha256": "bound-digest"})
    assert "scenario" not in displayed
    assert scenario_projection(displayed) == reported_scenario(proposal)
    item = scenario_projection(displayed)["constructor_parameters"]["options"]
    assert ("value_representation" in item) is (length == 511)
    assert displayed["scenario_sha256"] == "bound-digest"


def test_projection_roundtrip_keeps_every_field_and_escaped_premise_name():
    from test_witness_scenario import classified, scenario
    proposal = scenario()
    proposal["entry_condition_assumptions"]["location == 'a/b~c'"] = classified(False, "environment_condition")
    proposal["precondition_files"]["nested/data~v1.json"] = classified("literal file", "attacker_controlled_input")
    normalized = WitnessScenarioHypothesis.model_validate(proposal).model_dump(mode="json")
    displayed = _visible_provenance({"scenario": normalized})
    assert scenario_projection(displayed) == reported_scenario(proposal)
    assert any("~1" in item["name"] and "~0" in item["name"] for item in displayed["premises"])


def test_preparation_has_no_executed_scope_or_visible_premises(tmp_path):
    from test_witness_protocol_continuation import _inputs, _partial, _registry, _call, _arguments
    index, candidate, context = _inputs(tmp_path)
    _, observation = _call(_registry(index, candidate, context), index, candidate, _arguments(_partial()))
    payload = json.loads(observation.content)
    assert observation.metadata["witness_attempted"] is False
    assert payload["premises"] == []
    assert payload["scope_note"].startswith("No witness has executed.")
    assert "scenario" not in payload
    assert observation.metadata["preparation_provenance"]["scenario"] == (
        WitnessScenarioHypothesis.model_validate(_partial()).model_dump(mode="json")
    )
    assert not context.runtime_root.exists()


def test_unobserved_candidate_retains_declarations_without_claiming_execution(tmp_path):
    from test_witness_scenario import inputs, execute, scenario
    index, candidate, _, registry = inputs(tmp_path)
    proposal = scenario()
    proposal["entry_boolean_arguments"]["enabled"]["value"] = False
    _, observation, _ = execute(index, candidate, registry, proposal)
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    payload = json.loads(observation.content)
    assert scenario_projection(payload) == reported_scenario(proposal)
    assert payload["scope_note"] == (
        "A bounded execution was attempted; candidate execution and the listed premises were not established. "
        "Remote reachability is not established."
    )
    assert payload["scenario_verification"]["probe"]["ok"] is False
    assert payload["scenario_verification"]["remote_authority_established"] is False


def test_observed_candidate_with_failed_premise_does_not_claim_all_premises_verified(tmp_path):
    from test_witness_scenario import inputs, execute, scenario
    index, candidate, _, registry = inputs(tmp_path)
    proposal = scenario()
    proposal["entry_condition_assumptions"]["os.path.exists(location)"]["value"] = False
    _, observation, _ = execute(index, candidate, registry, proposal)
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    payload = json.loads(observation.content)
    assert scenario_projection(payload) == reported_scenario(proposal)
    assert payload["probe"]["candidate_frame"] is not None
    assert "declared requirements" in payload["scope_note"]
    assert "unmet or unverified" in payload["scope_note"]
    assert payload["scenario_verification"]["probe"]["ok"] is False
    assert payload["scenario_verification"]["remote_authority_established"] is False


@pytest.mark.parametrize("quoted", [False, True])
def test_standard_budget_still_delivers_preparation_then_conditional_result(tmp_path, quoted):
    from test_witness_protocol_continuation import _inputs, _complete
    from cv_agent.evaluation.diagnostics.scripted_witness_acceptance import run_scripted_candidate
    from cv_agent.harness import FULL_SYSTEM_HARNESS
    index, candidate, context = _inputs(tmp_path, quoted=quoted)
    result = run_scripted_candidate(index, candidate, context, constructor_parameters={}, precondition_files={},
                                    nonce="SCOPECONTROL12345678", scenario_hypothesis=_complete())
    assert result["verdict"]["label"] == ("ABSTAIN" if quoted else "VULNERABLE"), result
    vote = result["verdict"]["votes"][0]
    assert vote["tool_observation_token_count"] <= FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens
    observed = vote["trace"][-1]["observation"]
    assert observed["status"] == "ok" and not observed["metadata"]["observation_truncated"]
    payload = json.loads(observed["content"])
    assert payload["raw_status"] == ("LITERAL_OBSERVED" if quoted else "EXPANDED_OBSERVED")
    assert scenario_projection(payload) == reported_scenario(_complete())
    assert result["witness_attempts"][-1]["premises"] == payload["premises"]


def test_validation_source_has_no_fixed_probe_domain_prose():
    from cv_agent.tools.validation import bounded_witness
    root = Path(bounded_witness.__file__).parent
    for source in root.glob("*.py"):
        text = source.read_text()
        assert "local directory" not in text
        assert "shell metacharacters" not in text
