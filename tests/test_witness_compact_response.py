"""Offline compact transport controls; full server proof remains authoritative."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest


from cv_agent.tools.validation import witness_response as response


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def prototype():
    return {
        "status": "CONFIRMED", "raw_status": "EXPANDED_OBSERVED", "gaps": [],
        "scenario_origin": "model_proposed", "classification_status": "complete",
        "manifest_sha256": "a" * 64, "subject_source_digest": "b" * 64, "scenario_sha256": "c" * 64,
        "scope_note": "This observation covers only the executed concrete input under the listed premises; remote reachability is not established.",
        "premises": [{"name": "/input_parameter", "value": "incoming", "classification": "attacker_controlled_input"}],
        "scenario_verification": {"remote_authority_established": False, "probe": {"ok": True, "gaps": []},
                                  "control": {"ok": True, "gaps": []}},
    }


def measured():
    event = {"argv": ["bash", "-c", "relay emit concrete-long-input"], "phase": "invoke",
             "emitter_frame": {"qualname": "Relay.launch"}, "candidate_frame": {"qualname": "Relay.launch"},
             "authentic_subprocess_popen": True, "loaded_source_gaps": []}
    return {"probe_event": event, "control_event": deepcopy(event)}


def test_exact_projection_retains_all_server_bindings_and_measured_facts():
    full = prototype()
    event = measured()
    before = deepcopy(full), deepcopy(event)
    compact = response.compact_witness_response(full, details=event)
    assert compact == {
        "raw_status": "EXPANDED_OBSERVED", "gaps": [], "scenario_origin": "model_proposed",
        "classified_scenario_ref": {"arguments": "/scenario_hypothesis", "sha256": "c" * 64},
        "manifest_sha256": "a" * 64, "remote_authority_established": False,
        "premises_verified": True, "emitter": "Relay.launch",
        "command_sha256": hashlib.sha256(canonical(event["probe_event"]["argv"]).encode()).hexdigest(),
        "command_prefix": "relay emit concrete-",
        "scope_note": "Concrete input observed; premises verified.",
    }
    assert (full, event) == before
    assert full["subject_source_digest"] == "b" * 64  # retained in the private complete response
    assert "premises" not in compact and "subject_source_digest" not in compact


@pytest.mark.parametrize("change", ["dataset", "classification", "remote_authority", "binding"])
def test_projection_cannot_hide_invalid_classification_or_source_binding(change):
    full = prototype()
    if change == "dataset":
        full["scenario_origin"] = "dataset_provided"
    elif change == "classification":
        full["classification_status"] = "not_supplied"
    elif change == "remote_authority":
        full["scenario_verification"]["remote_authority_established"] = True
    else:
        full.pop("subject_source_digest")
    with pytest.raises(ValueError):
        response.compact_witness_response(full, details=measured())


def test_unresolved_attempt_keeps_every_gap_and_does_not_claim_candidate_execution():
    full = prototype()
    full.update(status="UNRESOLVED", raw_status="UNRESOLVED", gaps=["command_boundary_not_reached", "another_gap"])
    full["scenario_verification"]["probe"]["ok"] = False
    full["scenario_verification"]["control"]["ok"] = False
    full["scope_note"] = "A bounded execution was attempted; candidate execution and the listed premises were not established. Remote reachability is not established."
    compact = response.compact_witness_response(full, details={"probe_event": {"kind": "no_event"}})
    assert compact["gaps"] == full["gaps"]
    assert compact["premises_verified"] is False
    assert compact["command_sha256"] is None and compact["command_prefix"] is None and compact["emitter"] is None
    assert compact["scope_note"] == "Attempted; candidate and premises unestablished."
    assert compact["remote_authority_established"] is False


def test_observed_candidate_with_unverified_premises_retains_the_distinction():
    full = prototype()
    full.update(status="UNRESOLVED", raw_status="UNRESOLVED", gaps=["condition_assumption_unverified:gate"])
    full["scenario_verification"]["probe"]["ok"] = False
    full["scope_note"] = "A concrete candidate input was observed. Listed premises are declared requirements; consult runtime verification for unmet or unverified premises. Remote reachability is not established."
    compact = response.compact_witness_response(full, details=measured())
    assert compact["premises_verified"] is False
    assert compact["scope_note"] == "Candidate observed; premises not all verified."
    assert compact["remote_authority_established"] is False
    assert compact["gaps"] == full["gaps"]


def test_direct_callback_compact_scope_preserves_parser_boundary_and_private_bindings():
    full = prototype()
    full["entry_adapter"] = {"invocation": "click_callback", "scope": "direct_click_callback",
                             "public_parser_executed": False}
    before = deepcopy(full)
    compact = response.compact_witness_response(full, details=measured())
    assert compact["scope_note"].startswith("Direct callback; CLI parser not executed.")
    assert compact["public_parser_executed"] is False
    assert "manifest_sha256" not in compact
    assert full == before and full["manifest_sha256"] == "a" * 64


def test_direct_callback_projection_cannot_claim_public_parser_was_executed():
    full = prototype()
    full["entry_adapter"] = {"invocation": "click_callback", "scope": "direct_click_callback",
                             "public_parser_executed": True}
    with pytest.raises(ValueError, match="public CLI parser"):
        response.compact_witness_response(full, details=measured())


def test_wrong_branch_prefix_gap_keeps_all_facts_under_serialized_wrapper_limit():
    from cv_agent.domain.evidence import ToolObservation, ValidationStatus
    from cv_agent.tools.registry import ToolRegistry
    from cv_agent.runtime.witness.contract import PositiveOnlyWitnessProofScope
    full = prototype()
    full.update(status="UNRESOLVED", raw_status="UNRESOLVED", gaps=["recorder_prefix_not_established"])
    full["scenario_verification"]["control"]["ok"] = False
    event = measured()
    event["probe_event"]["emitter_frame"]["qualname"] = "DispatcherWithConfiguredBackend.launch"
    event["probe_event"]["argv"][2] = "exec worker-service start " + "captured-input" * 30
    compact = response.compact_witness_response(full, details=event)
    observation = ToolObservation(tool="run_bounded_execution_witness", status="ok", content=canonical(compact),
        citation_id="scan/tool:1", validation_status=ValidationStatus.UNRESOLVED,
        fixture_proof=PositiveOnlyWitnessProofScope())
    rendered = ToolRegistry._render_prompt_payload(observation, content=observation.content)
    assert len(rendered.encode()) <= 1000
    assert compact["gaps"] == full["gaps"]
    assert compact["command_prefix"] == event["probe_event"]["argv"][2][:20]
    assert compact["emitter"] == event["probe_event"]["emitter_frame"]["qualname"]
    assert compact["remote_authority_established"] is False
    assert compact["manifest_sha256"] == full["manifest_sha256"]


def _physical_inputs(tmp_path, *, quoted=False):
    from test_witness_protocol_continuation import _inputs
    return _inputs(tmp_path, quoted=quoted)


def _registry(index, candidate, context):
    from cv_agent.harness import FULL_SYSTEM_HARNESS
    from cv_agent.tools.registry import ToolRegistry
    from cv_agent.tools.validation.registry import full_agent_tools
    tools = full_agent_tools(index, witness_contexts={candidate.repository_id: context})
    return ToolRegistry(tools, max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)


def _run(tmp_path, *, quoted=False, scenes=2, compact=True):
    from dataclasses import replace
    from cv_agent.agents.workflow import AgenticPipeline
    from cv_agent.domain.chat import ModelReply, ModelToolCall
    from cv_agent.harness import AgentSystemVersion
    from cv_agent.runtime.model import ScriptedChatModel
    from test_witness_protocol_continuation import _complete, _finish
    index, candidate, context = _physical_inputs(tmp_path, quoted=quoted)
    context = replace(context, response_mode="compact" if compact else "full")
    hypotheses = []
    for variant in range(scenes - 1):
        wrong = _complete()
        wrong["entry_boolean_arguments"]["gate"]["value"] = False
        wrong["constructor_parameters"]["options"]["value"] = {"route": variant}
        hypotheses.append(wrong)
    hypotheses.append(_complete())
    replies = [ModelReply(model_id="offline-compact", tool_calls=(ModelToolCall(call_id=f"scene-{i}",
        name="run_bounded_execution_witness", arguments={"constructor_parameters": {}, "precondition_files": {},
                                                       "scenario_hypothesis": hypothesis}),))
               for i, hypothesis in enumerate(hypotheses)]
    model = ScriptedChatModel([*replies, _finish])
    registry = _registry(index, candidate, context)
    verdict = AgenticPipeline(index=index, system=AgentSystemVersion.E1_LOCAL_SINGLE, models={"scan": model},
                             tools=registry).run(candidate)
    return verdict, model, registry


@pytest.mark.parametrize("quoted", [False, True])
@pytest.mark.parametrize("scenes", [2, 3])
def test_multiple_distinct_physical_scenes_fit_original_steps_and_byte_budget(tmp_path, quoted, scenes):
    from cv_agent.harness import FULL_SYSTEM_HARNESS
    verdict, model, registry = _run(tmp_path, quoted=quoted, scenes=scenes)
    assert verdict.label == ("ABSTAIN" if quoted else "VULNERABLE"), verdict.model_dump(mode="json")
    assert len(model.requests) == scenes + 1 <= FULL_SYSTEM_HARNESS.react_loop.max_steps
    vote = verdict.votes[0]
    assert vote.tool_observation_token_count < FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens
    for step in vote.trace:
        observation = step.observation
        assert observation.status == "ok" and not observation.metadata["observation_truncated"]
        assert len(registry.prompt_payload(observation).encode()) <= 1000
        payload = json.loads(observation.content)
        full = observation.metadata["witness_full_response"]
        assert payload["gaps"] == full["gaps"]
        assert payload["classified_scenario_ref"]["sha256"] == full["scenario_sha256"]
        assert payload["manifest_sha256"] == full["manifest_sha256"]
        artifact = json.loads(Path(full["artifact_path"]).read_text())
        assert full["premises"]
        assert artifact["scenario"] == artifact["manifest"]["scenario_hypothesis"]
        assert observation.fixture_proof is not None
    final = vote.trace[-1].observation
    assert final.validation_status.value == ("UNRESOLVED" if quoted else "CONFIRMED")
    assert json.loads(final.content)["raw_status"] == ("LITERAL_OBSERVED" if quoted else "EXPANDED_OBSERVED")


def test_default_full_positive_control_keeps_complete_premises_and_original_proof(tmp_path):
    verdict, _, _ = _run(tmp_path, scenes=2, compact=False)
    assert verdict.label == "VULNERABLE"
    observation = verdict.votes[0].trace[-1].observation
    payload = json.loads(observation.content)
    assert payload["premises"] and payload["probe"]["candidate_frame"]
    assert "classified_scenario_ref" not in payload
    assert observation.fixture_proof.supported_statuses[0].value == "CONFIRMED"


@pytest.mark.parametrize("proposed_status", ["UNRESOLVED", "REFUTED"])
def test_compact_literal_observation_cannot_support_safe(tmp_path, proposed_status):
    from cv_agent.agents.evidence_policy import validate_conclusion
    from cv_agent.domain.review import AgentExpertConclusion
    verdict, _, _ = _run(tmp_path, quoted=True, scenes=2)
    trace = verdict.votes[0].trace
    observed = trace[-1].observation
    assert observed.validation_status.value == "UNRESOLVED"
    assert json.loads(observed.content)["raw_status"] == "LITERAL_OBSERVED"
    conclusion = AgentExpertConclusion(expert="scan", label="SAFE", confidence=.9,
        validation_status=proposed_status, evidence_ids=(observed.citation_id,),
        supporting_observation_ids=(observed.citation_id,), rationale="Attempt to turn a literal result into safety.")
    with pytest.raises(ValueError):
        validate_conclusion(conclusion, trace, initial_evidence_ids=frozenset(), subject=observed.subject)


def test_missing_classification_refuses_before_any_worker(tmp_path):
    from dataclasses import replace
    from cv_agent.domain.chat import ModelToolCall
    from test_witness_protocol_continuation import _complete, _scope
    index, candidate, context = _physical_inputs(tmp_path)
    context = replace(context, response_mode="compact")
    registry = _registry(index, candidate, context)
    hypothesis = _complete()
    hypothesis["input_parameter"].pop("classification")
    observation = registry.invoke(ModelToolCall(call_id="unclassified", name="run_bounded_execution_witness",
        arguments={"constructor_parameters": {}, "precondition_files": {}, "scenario_hypothesis": hypothesis}),
        allowed=("run_bounded_execution_witness",), scope=_scope(index, candidate), citation_id="test:bad")
    assert observation.status == "error" and observation.fixture_proof is None
    assert not context.runtime_root.exists()


def test_compact_preparation_groups_six_fields_and_drives_real_protocol_completion(tmp_path):
    from dataclasses import replace
    from cv_agent.agents.workflow import AgenticPipeline
    from cv_agent.domain.chat import ModelReply, ModelToolCall
    from cv_agent.harness import AgentSystemVersion, FULL_SYSTEM_HARNESS
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.runtime.model import ScriptedChatModel
    from test_witness_protocol_continuation import _classified, _complete, _finish
    index, candidate, context = _physical_inputs(tmp_path)
    file = context.checkout_root / "relay.py"
    before = "incoming, address, gate"
    after = "incoming, address, gate, region, deadline"
    source = file.read_text().replace(before, after)
    file.write_text(source)
    digest = hashlib.sha256(source.encode()).hexdigest()
    index = RepositoryIndex(tuple(document.model_copy(update={
        "text": document.text.replace(before, after), "source_sha256": digest,
    }) for document in index.documents.values()))
    context = replace(context, response_mode="compact")
    partial = {"input_parameter": _classified("incoming", "attacker_controlled_input")}
    full = _complete()
    full["entry_value_assumptions"].update(region=_classified("fixture-region"), deadline=_classified(None))
    first = ModelReply(model_id="offline-compact", tool_calls=(ModelToolCall(call_id="partial", name="run_bounded_execution_witness",
        arguments={"constructor_parameters": {}, "precondition_files": {}, "scenario_hypothesis": partial}),))
    def complete(messages, tools):
        assert messages[-1].content.startswith("Preparation continuation for required validator")
        for name in ("address", "gate", "region", "deadline", "options", "mode"):
            assert name in messages[-1].content
        return ModelReply(model_id="offline-compact", tool_calls=(ModelToolCall(call_id="completed",
            name="run_bounded_execution_witness", arguments={"constructor_parameters": {}, "precondition_files": {},
                                                            "scenario_hypothesis": full}),))
    registry = _registry(index, candidate, context)
    model = ScriptedChatModel([first, complete, _finish])
    verdict = AgenticPipeline(index=index, system=AgentSystemVersion.E1_LOCAL_SINGLE, models={"scan": model},
                             tools=registry).run(candidate)
    assert verdict.label == "VULNERABLE", verdict.model_dump(mode="json")
    vote = verdict.votes[0]
    assert len(model.requests) == 3 <= FULL_SYSTEM_HARNESS.react_loop.max_steps
    assert vote.tool_observation_token_count < FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens
    preparation = vote.trace[0].observation
    assert preparation.status == "ok" and preparation.fixture_proof is None
    assert len(registry.prompt_payload(preparation).encode()) <= 1000
    visible = json.loads(preparation.content)
    trusted = preparation.metadata["validation_preparation"]
    assert trusted == preparation.metadata["witness_full_response"]["preparation"]
    reconstructed = [dict(name=name, destination=group["destination"], classified=group["classified"])
                     for group in visible["preparation"]["missing_inputs"] for name in group["names"]]
    assert reconstructed == trusted["missing_inputs"]
    assert len(reconstructed) == 6
    assert visible["gaps"] == preparation.metadata["witness_full_response"]["gaps"]
    assert visible["missing_constructor_parameters"] == ["options", "mode"]
    assert visible["scope_note"] == "No witness has executed."
    assert visible["premises"] == []
    assert vote.trace[1].observation.validation_status.value == "CONFIRMED"


def test_scripted_report_resolves_same_call_ref_without_using_it_as_proof(tmp_path):
    from dataclasses import replace
    from cv_agent.evaluation.diagnostics.scripted_witness_acceptance import run_scripted_candidate
    from test_witness_protocol_continuation import _complete
    index, candidate, context = _physical_inputs(tmp_path)
    context = replace(context, response_mode="compact")
    result = run_scripted_candidate(index, candidate, context, constructor_parameters={}, precondition_files={},
                                    nonce="COMPACTREPORT12345678", scenario_hypothesis=_complete())
    assert result["verdict"]["label"] == "VULNERABLE", result
    report = result["witness_attempts"][-1]
    assert report["classified_scenario_ref_matches_call"] is True
    assert report["classification_status"] == "complete" and report["premises"]
    assert report["artifact_path"]
    assert "artifact_path" not in report["delivered_payload"]
    assert "premises" not in report["delivered_payload"]
    assert report["observation_token_count"] <= 1000 and not report["observation_truncated"]


@pytest.mark.parametrize("quoted", [False, True])
def test_generic_scripted_sequence_uses_only_explicit_distinct_scenes(tmp_path, quoted):
    from dataclasses import replace
    from cv_agent.evaluation.diagnostics.scripted_witness_acceptance import run_scripted_candidate
    from cv_agent.harness import FULL_SYSTEM_HARNESS
    from test_witness_protocol_continuation import _complete
    index, candidate, context = _physical_inputs(tmp_path, quoted=quoted)
    context = replace(context, response_mode="compact")
    wrong = _complete()
    wrong["entry_boolean_arguments"]["gate"]["value"] = False
    final = _complete()
    additional = deepcopy(final)
    additional["entry_value_assumptions"]["address"]["value"] = "another-address"
    result = run_scripted_candidate(index, candidate, context, constructor_parameters={}, precondition_files={},
        nonce="SEQUENCECONTROL12345678", hypothesis_sequence=[wrong, final, additional])
    assert result["verdict"]["label"] == ("ABSTAIN" if quoted else "VULNERABLE")
    assert result["semantic_hypothesis_count"] == 3
    assert result["scripted_model_calls"] == (4 if quoted else 3)
    attempts = result["witness_attempts"]
    assert len(attempts) == (3 if quoted else 2)
    assert all(attempt["witness_attempted"] and attempt["observation_token_count"] <= 1000 for attempt in attempts)
    assert all(attempt["classified_scenario_ref_matches_call"] for attempt in attempts)
    assert result["verdict"]["votes"][0]["tool_observation_token_count"] < FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens
    assert attempts[-1]["raw_status"] == ("LITERAL_OBSERVED" if quoted else "EXPANDED_OBSERVED")


@pytest.mark.parametrize("invalid", ["rationale_only", "classification_missing", "too_many", "mutually_exclusive", "outer_data"])
def test_scripted_sequence_rejects_invalid_whole_plan_before_worker(tmp_path, invalid):
    from cv_agent.evaluation.diagnostics.scripted_witness_acceptance import run_scripted_candidate
    from test_witness_protocol_continuation import _complete
    index, candidate, context = _physical_inputs(tmp_path)
    first = _complete()
    second = deepcopy(first)
    kwargs = {}
    constructor = {}
    if invalid == "rationale_only":
        second["input_parameter"]["rationale"] = "A different explanation does not change execution values."
        sequence = [first, second]
    elif invalid == "classification_missing":
        second["input_parameter"].pop("classification")
        sequence = [first, second]
    elif invalid == "too_many":
        sequence = [first] * 7
    elif invalid == "mutually_exclusive":
        sequence = [first]
        kwargs["scenario_hypothesis"] = first
    else:
        sequence = [first]
        constructor = {"options": {}}
    with pytest.raises(ValueError):
        run_scripted_candidate(index, candidate, context, constructor_parameters=constructor, precondition_files={},
            nonce="BADSEQUENCE12345678", hypothesis_sequence=sequence, **kwargs)
    assert not context.runtime_root.exists()


@pytest.mark.parametrize("failure", [ValueError, TypeError, KeyError])
def test_projection_error_keeps_physical_receipt_and_does_not_authorize_repeat(tmp_path, monkeypatch, failure):
    from dataclasses import replace
    from cv_agent.domain.chat import ModelToolCall
    from cv_agent.runtime.witness import kernel
    from cv_agent.tools.validation import bounded_witness
    from test_witness_protocol_continuation import _complete, _scope
    index, candidate, context = _physical_inputs(tmp_path)
    context = replace(context, response_mode="compact")
    executions = []
    original = kernel.run_witness
    def measure(*args, **kwargs):
        result = original(*args, **kwargs)
        executions.append(result.status.value)
        return result
    def fail_projection(*args, **kwargs):
        raise failure("forced response projection failure")
    monkeypatch.setattr(kernel, "run_witness", measure)
    monkeypatch.setattr(bounded_witness, "compact_witness_response", fail_projection)
    registry = _registry(index, candidate, context)
    scope = _scope(index, candidate)
    call = ModelToolCall(call_id="positive", name="run_bounded_execution_witness",
        arguments={"constructor_parameters": {}, "precondition_files": {}, "scenario_hypothesis": _complete()})
    first = registry.invoke(call, allowed=(call.name,), scope=scope, citation_id="receipt:1")
    assert first.status == "error" and first.validation_status is None and first.fixture_proof is None
    assert first.metadata["producer_completed"] is True
    assert first.metadata["witness_result_status"] == "CONFIRMED"
    assert first.metadata["witness_full_response"]["raw_status"] == "EXPANDED_OBSERVED"
    artifact = json.loads(Path(first.metadata["artifact_path"]).read_text())
    assert artifact["result"]["status"] == "CONFIRMED"
    second = registry.invoke(call, allowed=(call.name,), scope=scope, citation_id="receipt:2")
    assert second.status == "blocked" and "already executed" in second.content
    assert executions == ["CONFIRMED"]
    wrong = _complete()
    wrong["entry_boolean_arguments"]["gate"]["value"] = False
    changed = call.model_copy(update={"call_id": "different", "arguments": {
        "constructor_parameters": {}, "precondition_files": {}, "scenario_hypothesis": wrong}})
    third = registry.invoke(changed, allowed=(call.name,), scope=scope, citation_id="receipt:3")
    assert third.status == "error" and third.metadata["witness_result_status"] == "UNRESOLVED"
    assert executions == ["CONFIRMED", "UNRESOLVED"]
