"""Model scenarios are explicit conditional hypotheses, never candidate identity."""
from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from cv_agent.agents.evidence_policy import validate_conclusion
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import ReActStep, ValidationStatus
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.domain.types import Candidate, CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation.registry import full_agent_tools
from cv_agent.tools.validation.witness_manifest import WitnessExecutionContext, WitnessSupplement
from cv_agent.tools.validation.witness_scenario import WitnessScenarioHypothesis


TOOL = "run_bounded_execution_witness"


def classified(value, classification="deployment_configuration"):
    return {"value": value, "classification": classification,
            "rationale": "A concrete premise to measure in this bounded execution."}


def scenario():
    return {
        "input_parameter": classified("location", "attacker_controlled_input"),
        "entry_boolean_arguments": {"enabled": classified(True)},
        "entry_condition_assumptions": {
            "os.path.exists(location)": classified(True, "environment_condition"),
            'self.kind != "local"': classified(False),
        },
        "entry_value_assumptions": {"self.kind": classified("local")},
        "constructor_parameters": {"options": classified({})},
        "precondition_files": {
            "data.json": classified('{"ready": true}', "environment_condition"),
        },
    }


def inputs(tmp_path: Path):
    root = tmp_path / "checkout"
    root.mkdir()
    source = (
        "import subprocess\nimport os\nimport json\nfrom pathlib import Path\n"
        "class Worker:\n"
        "    def __init__(self, options, kind='local'):\n"
        "        self.options = options\n        self.kind = kind\n"
        "    def run(self, location, enabled=False):\n"
        "        if not enabled:\n            return\n"
        "        if not os.path.exists(location):\n            return\n"
        "        if self.kind != 'local':\n            return\n"
        "        metadata = json.loads(Path(location, 'data.json').read_text())\n"
        "        if metadata.get('ready') is not True:\n            return\n"
        '        subprocess.Popen(["bash", "-c", f"ls {location}"])\n'
    )
    source_file = root / "example.py"
    source_file.write_text(source)
    method = next(node for node in ast.walk(ast.parse(source))
                  if isinstance(node, ast.FunctionDef) and node.name == "run")
    span = f"example.py::Worker.run@{method.lineno}-{method.end_lineno}"
    digest = hashlib.sha256(source.encode()).hexdigest()
    index = RepositoryIndex((
        CodeDocument(repository_id="neutral", path=f"example.py::<module>@1-{len(source.splitlines())}",
                     text=source, language="python", adapter_tier="ast", source_sha256=digest),
        CodeDocument(repository_id="neutral", path=span,
                     text="".join(source.splitlines(keepends=True)[method.lineno-1:method.end_lineno]),
                     language="python", adapter_tier="ast", source_sha256=digest),
    ))
    candidate = Candidate(candidate_id="neutral", case_id="neutral", repository_id="neutral",
                          path=span, line=method.lineno, query="entry", property_id="command-execution",
                          analysis_scope="whole declared entry")
    context = WitnessExecutionContext(checkout_root=root, python_executable=Path(sys.executable),
                                      runtime_root=tmp_path / "runtime")
    registry = ToolRegistry(full_agent_tools(index, witness_contexts={"neutral": context}),
                            max_output_bytes=100000)
    return index, candidate, context, registry


def execute(index, candidate, registry, hypothesis, **outer):
    subject = candidate_subject(index, candidate)
    call = ModelToolCall(call_id="scenario", name=TOOL, arguments={
        "constructor_parameters": {}, "precondition_files": {},
        "scenario_hypothesis": hypothesis, **outer,
    })
    observation = registry.invoke(call, allowed=(TOOL,), scope=ToolExecutionScope(
        admitted_paths=frozenset({candidate.path}), candidate_path=candidate.path,
        subject=subject, max_observation_tokens=20000), citation_id="tool:scenario")
    return call, observation, subject


def test_empty_subject_can_execute_model_scenario_without_identity_drift(tmp_path):
    index, candidate, _, registry = inputs(tmp_path)
    original = candidate_subject(index, candidate)
    assert registry.candidate_witness_available(original)
    call, observation, subject = execute(index, candidate, registry, scenario())
    assert observation.status == "ok", observation.content
    assert observation.validation_status == ValidationStatus.CONFIRMED, observation.content
    assert observation.subject == original == subject
    assert original.input_parameters == ()
    payload = json.loads(observation.content)
    assert payload["scenario_origin"] == "model_proposed"
    assert payload["scenario"]["input_parameter"]["classification"] == "attacker_controlled_input"
    assert payload["scenario_verification"]["probe"]["ok"] is True
    assert payload["scenario_verification"]["control"]["ok"] is True
    assert payload["scenario_verification"]["remote_authority_established"] is False
    artifact = json.loads(Path(payload["artifact_path"]).read_text())
    assert artifact["scenario_sha256"] == payload["scenario_sha256"]
    assert artifact["manifest"]["subject"] == artifact["execution_subject"]
    assert artifact["execution_subject"]["input_parameters"] == ["location"]
    assert artifact["original_subject"]["input_parameters"] == []
    assert artifact["original_subject"] == original.model_dump(mode="json")
    assert artifact["scenario_verification"]["probe"]["precondition_files"]["data.json"]["matched"] is True
    conclusion = AgentExpertConclusion(expert="scan", label="VULNERABLE", confidence=.9,
        validation_status=ValidationStatus.CONFIRMED, evidence_ids=(observation.citation_id,),
        supporting_observation_ids=(observation.citation_id,), rationale="Conditional witness under reported premises.")
    validate_conclusion(conclusion, [ReActStep(step=1, model_id="offline", tool_call=call,
        observation=observation)], initial_evidence_ids=frozenset(), subject=original)


@pytest.mark.parametrize("wrong", ["boolean", "condition", "value", "file", "parameter"])
def test_wrong_model_scenario_is_unresolved_and_never_safe(tmp_path, wrong):
    index, candidate, _, registry = inputs(tmp_path)
    hypothesis = scenario()
    if wrong == "boolean":
        hypothesis["entry_boolean_arguments"]["enabled"]["value"] = False
    elif wrong == "condition":
        hypothesis["entry_condition_assumptions"]["os.path.exists(location)"]["value"] = False
    elif wrong == "value":
        hypothesis["entry_value_assumptions"]["self.kind"]["value"] = "other"
    elif wrong == "file":
        hypothesis["precondition_files"]["data.json"]["value"] = '{"ready": false}'
    else:
        hypothesis["input_parameter"]["value"] = "absent"
    _, observation, _ = execute(index, candidate, registry, hypothesis)
    assert observation.status == "ok", observation.content
    assert observation.validation_status == ValidationStatus.UNRESOLVED, observation.content
    assert '"REFUTED"' not in observation.content


@pytest.mark.parametrize("field", ["input_parameter", "entry_boolean_arguments", "entry_condition_assumptions",
                                  "entry_value_assumptions", "constructor_parameters", "precondition_files"])
def test_missing_classification_refuses_execution(tmp_path, field):
    index, candidate, context, registry = inputs(tmp_path)
    hypothesis = scenario()
    premise = hypothesis[field] if field == "input_parameter" else next(iter(hypothesis[field].values()))
    premise.pop("classification")
    _, observation, _ = execute(index, candidate, registry, hypothesis)
    assert observation.status == "error"
    assert observation.validation_status is None
    assert not context.runtime_root.exists()


@pytest.mark.parametrize("outer", [{"constructor_parameters": {"options": {}}},
                                   {"precondition_files": {"data.json": "{}"}}])
def test_model_hypothesis_cannot_mix_unclassified_outer_data(tmp_path, outer):
    index, candidate, context, registry = inputs(tmp_path)
    _, observation, _ = execute(index, candidate, registry, scenario(), **outer)
    assert observation.status == "error"
    assert not context.runtime_root.exists()


def test_model_hypothesis_cannot_replace_dataset_premises(tmp_path):
    index, candidate, context, registry = inputs(tmp_path)
    candidate = candidate.model_copy(update={"input_parameters": ("location",),
                                             "entry_boolean_arguments": {"enabled": False}})
    _, observation, _ = execute(index, candidate, registry, scenario())
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert "dataset_scenario_cannot_be_replaced" in observation.content
    assert not context.runtime_root.exists()


def test_dataset_classification_reports_original_premises_without_filling_missing_data(tmp_path):
    index, candidate, context, _ = inputs(tmp_path)
    declaration = WitnessScenarioHypothesis.model_validate(scenario())
    candidate = candidate.model_copy(update={
        "input_parameters": (declaration.input_parameter.value,),
        "entry_boolean_arguments": declaration.values("entry_boolean_arguments"),
        "entry_condition_assumptions": declaration.values("entry_condition_assumptions"),
        "entry_value_assumptions": declaration.values("entry_value_assumptions"),
    })
    context = replace(context, dataset_scenario=declaration)
    registry = ToolRegistry(full_agent_tools(index, witness_contexts={"neutral": context}), max_output_bytes=100000)
    _, preparation, _ = execute(index, candidate, registry, None)
    assert preparation.validation_status == ValidationStatus.UNRESOLVED
    assert json.loads(preparation.content)["missing_constructor_parameters"] == ["options"]
    assert not context.runtime_root.exists()
    _, observed, original = execute(index, candidate, registry, None,
        constructor_parameters={"options": {}}, precondition_files={"data.json": '{"ready": true}'})
    assert observed.validation_status == ValidationStatus.CONFIRMED, observed.content
    payload = json.loads(observed.content)
    assert payload["scenario_origin"] == "dataset_provided"
    assert payload["classification_status"] == "complete"
    artifact = json.loads(Path(payload["artifact_path"]).read_text())
    assert artifact["original_subject"] == artifact["execution_subject"] == original.model_dump(mode="json")
    assert artifact["scenario_verification"]["control"]["constructor_parameters"]["options"]["matched"] is True


def test_unclassified_dataset_scenario_is_rejected_before_execution(tmp_path):
    index, candidate, context, registry = inputs(tmp_path)
    declaration = WitnessScenarioHypothesis.model_validate(scenario())
    candidate = candidate.model_copy(update={
        "input_parameters": (declaration.input_parameter.value,),
        "entry_boolean_arguments": declaration.values("entry_boolean_arguments"),
        "entry_condition_assumptions": declaration.values("entry_condition_assumptions"),
        "entry_value_assumptions": declaration.values("entry_value_assumptions"),
    })
    _, observation, _ = execute(index, candidate, registry, None,
        constructor_parameters={"options": {}}, precondition_files={"data.json": '{"ready": true}'})
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert "scenario_classification_missing" in observation.content
    assert observation.metadata["witness_attempted"] is False
    assert not context.runtime_root.exists()


@pytest.mark.parametrize("change", ["subject", "constructor", "files"])
def test_dataset_classification_binding_cannot_be_forged_or_supplemented(tmp_path, change):
    index, candidate, context, _ = inputs(tmp_path)
    declaration = WitnessScenarioHypothesis.model_validate(scenario())
    candidate = candidate.model_copy(update={
        "input_parameters": (declaration.input_parameter.value,),
        "entry_boolean_arguments": declaration.values("entry_boolean_arguments"),
        "entry_condition_assumptions": declaration.values("entry_condition_assumptions"),
        "entry_value_assumptions": declaration.values("entry_value_assumptions"),
    })
    if change == "subject":
        candidate = candidate.model_copy(update={"entry_boolean_arguments": {"enabled": False}})
    context = replace(context, dataset_scenario=declaration)
    registry = ToolRegistry(full_agent_tools(index, witness_contexts={"neutral": context}), max_output_bytes=100000)
    _, observation, _ = execute(index, candidate, registry, None,
        constructor_parameters={"options": {"extra": 1}} if change == "constructor" else {"options": {}},
        precondition_files={"data.json": "{}"} if change == "files" else {"data.json": '{"ready": true}'})
    assert observation.validation_status == ValidationStatus.UNRESOLVED, observation.content
    assert not context.runtime_root.exists()


@pytest.mark.parametrize("mutation", ["unsafe_file", "runtime_field", "wrong_input_class", "nonboolean"])
def test_scenario_remains_strict_data_only(mutation):
    hypothesis = scenario()
    if mutation == "unsafe_file":
        hypothesis["precondition_files"] = {"../escape": classified("x")}
    elif mutation == "runtime_field":
        hypothesis["python_executable"] = classified("/tmp/model-python")
    elif mutation == "wrong_input_class":
        hypothesis["input_parameter"]["classification"] = "environment_condition"
    else:
        hypothesis["entry_boolean_arguments"]["enabled"]["value"] = 1
    with pytest.raises((ValidationError, ValueError)):
        WitnessSupplement.model_validate({"constructor_parameters": {}, "precondition_files": {},
                                          "scenario_hypothesis": hypothesis})
