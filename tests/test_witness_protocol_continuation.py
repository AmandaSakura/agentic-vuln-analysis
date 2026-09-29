"""Preparation asks for call data and never supplies evidence or input choices."""
from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import json
import sys
from pathlib import Path

import pytest

from cv_agent.agents.evidence_policy import validate_conclusion, validator_observation_completed
from cv_agent.agents.react import ReActEngine, run_expert
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.domain.chat import ModelReply, ModelToolCall
from cv_agent.domain.evidence import ReActStep, ToolObservation, ValidationStatus
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.domain.types import Candidate, CodeDocument, FrozenModel
from cv_agent.harness import AgentSystemVersion, FULL_SYSTEM_HARNESS
from cv_agent.retrieval import RepositoryIndex
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import AgentTool, ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation.registry import full_agent_tools
from cv_agent.tools.validation.witness_manifest import WitnessExecutionContext
from cv_agent.tools.validation.witness_scenario import WitnessScenarioHypothesis


TOOL = "run_bounded_execution_witness"
CONTINUATION = "Preparation continuation for required validator"


def _classified(value, classification="deployment_configuration"):
    return {"value": value, "classification": classification, "rationale": "A concrete fixture premise."}


def _inputs(tmp_path: Path, *, quoted=False):
    root = tmp_path / "checkout"
    root.mkdir()
    expression = "shlex.quote(incoming)" if quoted else "incoming"
    source = ("import subprocess\nimport shlex\nclass Relay:\n"
              "    def __init__(self, options, mode):\n        self.options = options\n        self.mode = mode\n"
              "    def launch(self, incoming, address, gate):\n"
              "        if not gate:\n            return\n"
              f'        subprocess.Popen(["bash", "-c", f"relay emit {{{expression}}}"])\n')
    file = root / "relay.py"
    file.write_text(source)
    node = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef) and n.name == "launch")
    span = f"relay.py::Relay.launch@{node.lineno}-{node.end_lineno}"
    digest = hashlib.sha256(source.encode()).hexdigest()
    index = RepositoryIndex((
        CodeDocument(repository_id="neutral", path=f"relay.py::<module>@1-{len(source.splitlines())}",
                     text=source, language="python", adapter_tier="ast", source_sha256=digest),
        CodeDocument(repository_id="neutral", path=span,
                     text="".join(source.splitlines(keepends=True)[node.lineno-1:node.end_lineno]),
                     language="python", adapter_tier="ast", source_sha256=digest),
    ))
    candidate = Candidate(candidate_id="neutral", case_id="neutral", repository_id="neutral", path=span,
                          line=node.lineno, query="entry", property_id="command-execution")
    context = WitnessExecutionContext(checkout_root=root, python_executable=Path(sys.executable),
                                      runtime_root=tmp_path / "runtime")
    return index, candidate, context


def _partial():
    return {"input_parameter": _classified("incoming", "attacker_controlled_input"),
            "entry_boolean_arguments": {"gate": _classified(True)}}


def _complete():
    return {**_partial(), "entry_value_assumptions": {"address": _classified("fixture-address")},
            "constructor_parameters": {"options": _classified({}), "mode": _classified("fixture-mode")}}


def _arguments(scenario):
    return {"constructor_parameters": {}, "precondition_files": {}, "scenario_hypothesis": scenario}


def _registry(index, candidate, context):
    return ToolRegistry(full_agent_tools(index, witness_contexts={candidate.repository_id: context}),
                        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)


def _scope(index, candidate):
    return ToolExecutionScope(admitted_paths=frozenset({candidate.path}), candidate_path=candidate.path,
        subject=candidate_subject(index, candidate), max_observation_tokens=FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens)


def _call(registry, index, candidate, arguments):
    call = ModelToolCall(call_id="prepare", name=TOOL, arguments=arguments)
    observation = registry.invoke(call, allowed=(TOOL,), scope=_scope(index, candidate), citation_id="tool:prepare")
    return call, observation


def _finish(messages, tools):
    observed = json.loads(next(m.content for m in reversed(messages) if m.role == "tool"))
    confirmed = observed.get("validation_status") == "CONFIRMED"
    citation = observed.get("citation_id") if observed["status"] == "ok" else None
    return ModelReply(model_id="offline", content=json.dumps({
        "expert": "scan", "label": "VULNERABLE" if confirmed else "ABSTAIN", "confidence": .9 if confirmed else 0.,
        "validation_status": "CONFIRMED" if confirmed else "UNRESOLVED",
        "evidence_ids": [citation] if citation else [],
        "supporting_observation_ids": [citation] if confirmed and citation else [],
        "rationale": "Use only the complete measured witness.",
    }))


def test_model_preparation_has_all_missing_destinations_and_cannot_supply_proof(tmp_path):
    index, candidate, context = _inputs(tmp_path)
    call, observation = _call(_registry(index, candidate, context), index, candidate, _arguments(_partial()))
    state = observation.metadata["validation_preparation"]
    assert state["state"] == "preparation"
    assert state["mode"] == "model_proposed"
    assert state["action"] == "complete_call_data"
    assert {(item["name"], item["destination"]) for item in state["missing_inputs"]} == {
        ("address", "scenario_hypothesis.entry_value_assumptions"),
        ("options", "scenario_hypothesis.constructor_parameters"),
        ("mode", "scenario_hypothesis.constructor_parameters"),
    }
    assert all(item["classified"] for item in state["missing_inputs"])
    assert all("value" not in item and "default" not in item for item in state["missing_inputs"])
    payload = json.loads(observation.content)
    assert payload["preparation"] == state
    assert payload["scenario_origin"] == "model_proposed" and payload["scenario_sha256"]
    assert "scenario" not in payload
    assert observation.metadata["preparation_provenance"]["scenario"]["input_parameter"]["value"] == "incoming"
    assert observation.metadata["preparation_generated"]["call_parameters"] == ["incoming", "address", "gate"]
    assert observation.fixture_proof is None
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert not validator_observation_completed(observation)
    assert not context.runtime_root.exists()
    conclusion = AgentExpertConclusion(expert="scan", label="VULNERABLE", confidence=.9,
        validation_status=ValidationStatus.CONFIRMED, evidence_ids=(observation.citation_id,), rationale="Unsupported proposal.")
    with pytest.raises(ValueError):
        validate_conclusion(conclusion, [ReActStep(step=1, model_id="offline", tool_call=call, observation=observation)],
                            initial_evidence_ids=frozenset(), subject=candidate_subject(index, candidate))


@pytest.mark.parametrize("quoted", [False, True])
def test_immediate_continuation_can_complete_call_and_terminal_result_never_requests_retry(tmp_path, quoted):
    index, candidate, context = _inputs(tmp_path, quoted=quoted)
    first = ModelReply(model_id="offline", tool_calls=(ModelToolCall(call_id="partial", name=TOOL,
        arguments=_arguments(_partial())),))
    def complete(messages, tools):
        assert CONTINUATION in messages[-1].content
        assert "scenario_hypothesis.entry_value_assumptions.address" in messages[-1].content
        assert "scenario_hypothesis.constructor_parameters.options" in messages[-1].content
        assert "Choose values" in messages[-1].content
        return ModelReply(model_id="offline", tool_calls=(ModelToolCall(call_id="complete", name=TOOL,
            arguments=_arguments(_complete())),))
    def finish(messages, tools):
        assert messages[-1].role == "tool"
        assert sum(CONTINUATION in (m.content or "") for m in messages) == 1
        return _finish(messages, tools)
    model = ScriptedChatModel((first, complete, finish))
    result = AgenticPipeline(index=index, system=AgentSystemVersion.E1_LOCAL_SINGLE, models={"scan": model},
                            tools=_registry(index, candidate, context)).run(candidate)
    assert result.label == ("ABSTAIN" if quoted else "VULNERABLE")
    assert result.model_calls == 3 and result.tool_calls == 2
    assert result.tool_observation_token_count <= FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens
    trace = result.votes[0].trace
    assert trace[0].observation.metadata["witness_attempted"] is False
    assert trace[1].observation.metadata["witness_attempted"] is True
    assert "validation_preparation" not in trace[1].observation.metadata
    assert result.task_executions[0].validator_completed is True
    assert trace[1].observation.validation_status == (ValidationStatus.UNRESOLVED if quoted else ValidationStatus.CONFIRMED)


def test_dataset_mode_requests_outer_constructor_and_rejects_replacement_without_executing(tmp_path):
    index, candidate, context = _inputs(tmp_path)
    scene = WitnessScenarioHypothesis.model_validate(_complete())
    candidate = candidate.model_copy(update={"input_parameters": ("incoming",), "entry_boolean_arguments": {"gate": True},
                                             "entry_value_assumptions": {"address": "fixture-address"}})
    context = replace(context, dataset_scenario=scene)
    registry = _registry(index, candidate, context)
    _, preparation = _call(registry, index, candidate, _arguments(None))
    state = preparation.metadata["validation_preparation"]
    assert state["mode"] == "dataset_provided"
    assert {item["destination"] for item in state["missing_inputs"]} == {"constructor_parameters"}
    assert not any(item["classified"] for item in state["missing_inputs"])
    _, replacement = _call(registry, index, candidate, _arguments(_partial()))
    assert replacement.metadata["validation_preparation"]["action"] == "use_dataset_scenario"
    assert replacement.metadata["witness_attempted"] is False
    _, executed = _call(registry, index, candidate, {"constructor_parameters": {"options": {}, "mode": "fixture-mode"},
                                                   "precondition_files": {}})
    assert executed.validation_status == ValidationStatus.CONFIRMED, executed.content
    assert not validator_observation_completed(preparation)
    assert validator_observation_completed(executed)


def test_unknown_source_binding_gap_carries_no_actionable_continuation(tmp_path):
    index, candidate, context = _inputs(tmp_path)
    registry = _registry(index, candidate, context)
    (context.checkout_root / "relay.py").write_text("raise AssertionError('stale source')\n")
    _, observation = _call(registry, index, candidate, _arguments(_partial()))
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert "validation_preparation" not in observation.metadata
    assert "preparation" not in json.loads(observation.content)
    assert observation.metadata["witness_attempted"] is False
    assert not context.runtime_root.exists()


class _NeutralInput(FrozenModel):
    scenario_hypothesis: dict[str, dict[str, dict]] = {}


def _neutral_state():
    return {"state": "preparation", "mode": "model_proposed", "action": "complete_call_data",
            "missing_inputs": [{"name": "address", "destination": "scenario_hypothesis.call_data",
                                "classified": True}]}


@pytest.mark.parametrize("required", [True, False])
def test_continuation_uses_trusted_preparation_for_any_registered_required_validator(required):
    def handler(arguments, scope):
        complete = "address" in arguments.scenario_hypothesis.get("call_data", {})
        return ToolObservation(tool="measure_request", status="ok", validation_status=ValidationStatus.UNRESOLVED,
            content="Measured terminal result." if complete else "Prepared call only.",
            metadata={} if complete else {"validation_preparation": _neutral_state()})
    registry = ToolRegistry((AgentTool(name="measure_request", description="Measure a neutral request.",
        input_model=_NeutralInput, handler=handler, validation_statuses=(ValidationStatus.UNRESOLVED,)),), max_output_bytes=10000)
    def next_step(messages, tools):
        assert (CONTINUATION in (messages[-1].content or "")) is required
        return ModelReply(model_id="offline", tool_calls=(ModelToolCall(call_id="done", name="measure_request",
            arguments={"scenario_hypothesis": {"call_data": {"address": _classified("fixture-address")}}}),))
    model = ScriptedChatModel((ModelReply(model_id="offline", tool_calls=(ModelToolCall(call_id="prepare",
        name="measure_request", arguments={}),)), next_step, _finish))
    engine = ReActEngine(model=model, tools=registry,
        scope=ToolExecutionScope(admitted_paths=frozenset(), max_observation_tokens=8192),
        harness=FULL_SYSTEM_HARNESS.react_loop)
    result = run_expert(engine, expert="scan", system_prompt="Measure", task_prompt="Review",
        allowed_tools=("measure_request",), required_validators=("measure_request",) if required else ())
    assert result.label == "ABSTAIN" and result.model_calls == 3
    assert not validator_observation_completed(result.trace[0].observation)
    assert validator_observation_completed(result.trace[1].observation)


def test_arbitrary_payload_text_does_not_become_preparation_metadata():
    observation = ToolObservation(tool="measure_request", status="ok", validation_status=ValidationStatus.UNRESOLVED,
                                  content=json.dumps({"validation_preparation": _neutral_state()}))
    assert validator_observation_completed(observation)


@pytest.mark.parametrize("delivery", ["error", "blocked", "truncated", "suppressed"])
def test_preparation_feedback_requires_complete_successful_delivery(delivery):
    metadata = {"validation_preparation": _neutral_state()}
    if delivery == "truncated":
        metadata["observation_truncated"] = True
    if delivery == "suppressed":
        metadata["model_payload_suppressed"] = True
    status = delivery if delivery in {"error", "blocked"} else "ok"
    observation = ToolObservation(tool="measure_request", status=status, content="Incomplete delivery.", metadata=metadata)
    assert not validator_observation_completed(observation)


def test_malformed_trusted_preparation_is_explicit_protocol_error():
    observation = ToolObservation(tool="measure_request", status="ok", content="Prepared.",
                                  metadata={"validation_preparation": {"state": "preparation"}})
    with pytest.raises(ValueError):
        validator_observation_completed(observation)


def test_schema_advertises_strict_boolean_and_text_premise_types_without_choices():
    from cv_agent.tools.validation.witness_manifest import WitnessSupplement
    schema = WitnessSupplement.model_json_schema()
    fields = schema["$defs"]["WitnessScenarioHypothesis"]["properties"]
    for field in ("entry_boolean_arguments", "entry_condition_assumptions"):
        name = fields[field]["additionalProperties"]["$ref"].rsplit("/", 1)[1]
        value = schema["$defs"][name]["properties"]["value"]
        assert value["type"] == "boolean"
        assert not {"default", "const", "enum", "examples"} & value.keys()
    for field in ("input_parameter", "precondition_files"):
        reference = fields[field] if field == "input_parameter" else fields[field]["additionalProperties"]
        name = reference["$ref"].rsplit("/", 1)[1]
        assert schema["$defs"][name]["properties"]["value"]["type"] == "string"


def test_generic_preparation_cannot_complete_required_task_or_claim_a_strong_status():
    from cv_agent.agents.evidence_policy import IncompleteValidationTaskError
    call = ModelToolCall(call_id="prepare", name="measure_request", arguments={})
    preparation = ToolObservation(tool="measure_request", status="ok", content="Prepared only.", citation_id="tool:1",
        validation_status=ValidationStatus.UNRESOLVED, metadata={"validation_preparation": _neutral_state()})
    final = AgentExpertConclusion(expert="scan", label="ABSTAIN", confidence=0,
        validation_status=ValidationStatus.UNRESOLVED, evidence_ids=("tool:1",), rationale="No execution yet.")
    with pytest.raises(IncompleteValidationTaskError):
        validate_conclusion(final, [ReActStep(step=1, model_id="offline", tool_call=call, observation=preparation)],
                            initial_evidence_ids=frozenset(), required_validators=("measure_request",))
    with pytest.raises(ValueError, match="preparation cannot claim"):
        validator_observation_completed(preparation.model_copy(update={"validation_status": ValidationStatus.CONFIRMED}))


def test_terminal_result_in_same_batch_cancels_stale_preparation_feedback():
    def handler(arguments, scope):
        complete = "address" in arguments.scenario_hypothesis.get("call_data", {})
        return ToolObservation(tool="measure_request", status="ok", validation_status=ValidationStatus.UNRESOLVED,
            content="Terminal result." if complete else "Prepare first.",
            metadata={} if complete else {"validation_preparation": _neutral_state()})
    registry = ToolRegistry((AgentTool(name="measure_request", description="Measure request.", input_model=_NeutralInput,
        handler=handler, validation_statuses=(ValidationStatus.UNRESOLVED,)),), max_output_bytes=10000)
    first = ModelReply(model_id="offline", tool_calls=(
        ModelToolCall(call_id="prepare", name="measure_request", arguments={}),
        ModelToolCall(call_id="execute", name="measure_request",
            arguments={"scenario_hypothesis": {"call_data": {"address": _classified("fixture-address")}}}),
    ))
    def finish(messages, tools):
        assert not any(CONTINUATION in (message.content or "") for message in messages)
        return _finish(messages, tools)
    model = ScriptedChatModel((first, finish))
    engine = ReActEngine(model=model, tools=registry,
        scope=ToolExecutionScope(admitted_paths=frozenset(), max_observation_tokens=8192),
        harness=FULL_SYSTEM_HARNESS.react_loop)
    result = run_expert(engine, expert="scan", system_prompt="Measure", task_prompt="Review",
                        allowed_tools=("measure_request",), required_validators=("measure_request",))
    assert result.label == "ABSTAIN" and result.model_calls == 2 and result.tool_calls == 2
