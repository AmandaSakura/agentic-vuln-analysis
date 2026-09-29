"""Classified model scenarios reach actual witnesses through neutral source names.

These scripted proposals are offline protocol controls, not a claim that a model
discovered their premises. Repository code, command capture and the benign
control are executed by the ordinary source-bound validator.
"""

from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import pytest

from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.domain.chat import ModelReply, ModelToolCall
from cv_agent.domain.evidence import ValidationStatus
from cv_agent.domain.types import Candidate, CodeDocument
from cv_agent.harness import AgentSystemVersion, FULL_SYSTEM_HARNESS
from cv_agent.retrieval import RepositoryIndex
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation.registry import full_agent_tools
from cv_agent.tools.validation.witness_manifest import WitnessExecutionContext
from test_witness_scope_notes import scenario_projection


TOOL = "run_bounded_execution_witness"
NONCE = "SCENARIOGENERAL12345678"


def _requirement(value, classification, rationale):
    return {"value": value, "classification": classification, "rationale": rationale}


def _proposal():
    deployment = "deployment_configuration"
    environment = "environment_condition"
    return {
        "input_parameter": _requirement(
            "location", "attacker_controlled_input", "Caller supplies the directory argument."
        ),
        "entry_boolean_arguments": {
            "activated": _requirement(True, deployment, "Deployment activates this dispatch path.")
        },
        "entry_condition_assumptions": {
            "self.engine != policy.EMBEDDED": _requirement(
                False, deployment, "Deployment uses the embedded engine constant."
            ),
            "os.path.exists(location)": _requirement(
                True, environment, "The supplied local directory exists before dispatch."
            ),
            "os.path.exists(os.path.join(location, 'metadata.json'))": _requirement(
                True, environment, "Dispatch requires a metadata file in that directory."
            ),
        },
        "entry_value_assumptions": {
            "self.workers": _requirement(3, deployment, "Use the default worker configuration.")
        },
        "constructor_parameters": {
            "options": _requirement({}, deployment, "Construct the dispatcher with empty options.")
        },
        "precondition_files": {
            "metadata.json": _requirement(
                "{}", "attacker_controlled_input", "Caller prepares metadata in the supplied directory."
            )
        },
    }


def _inputs(root: Path, *, quoted=False):
    root.mkdir()
    expression = "shlex.quote(location)" if quoted else "location"
    source = (
        "import os\nimport shlex\nimport subprocess\nimport settings as policy\n\n"
        "class LaunchPad:\n"
        "    def __init__(self, options, engine, concurrency=3):\n"
        "        self.options = options\n"
        "        self.engine = engine\n"
        "        self.workers = concurrency\n\n"
        "    def dispatch(self, location, activated=False):\n"
        "        if self.engine != policy.EMBEDDED:\n"
        "            return None\n"
        "        if not activated:\n"
        "            return None\n"
        "        if not os.path.exists(location):\n"
        "            return None\n"
        "        if not os.path.exists(os.path.join(location, 'metadata.json')):\n"
        "            return None\n"
        f'        subprocess.Popen(["bash", "-c", f"widget launch {{{expression}}}"])\n'
    )
    sources = {"relay.py": source, "settings.py": 'EMBEDDED = "embedded"\n'}
    documents = []
    for relative, text in sources.items():
        path = root / relative
        path.write_text(text)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        documents.append(CodeDocument(
            repository_id="neutral-repository", path=f"{relative}::<module>@1-{len(text.splitlines())}",
            text=text, language="python", adapter_tier="ast", source_sha256=digest,
        ))
    method = next(node for node in ast.walk(ast.parse(source))
                  if isinstance(node, ast.FunctionDef) and node.name == "dispatch")
    span = f"relay.py::LaunchPad.dispatch@{method.lineno}-{method.end_lineno}"
    documents.append(CodeDocument(
        repository_id="neutral-repository", path=span,
        text="".join(source.splitlines(keepends=True)[method.lineno - 1:method.end_lineno]),
        language="python", adapter_tier="ast", source_sha256=hashlib.sha256(source.encode()).hexdigest(),
        defines=("LaunchPad.dispatch",),
    ))
    index = RepositoryIndex(documents)
    candidate = Candidate(
        candidate_id="neutral-candidate", case_id="neutral-case", repository_id="neutral-repository",
        path=span, line=method.lineno, query="Assess the dispatch entry.",
        property_id="command-execution", analysis_scope="Whole dispatch call in this exact source snapshot.",
    )
    context = WitnessExecutionContext(
        checkout_root=root, python_executable=Path(sys.executable), runtime_root=root.parent / "runtime",
    )
    return index, candidate, context


def _registry(index, candidate, context):
    return ToolRegistry(full_agent_tools(
        index, witness_contexts={candidate.repository_id: context}, witness_nonce_factory=lambda: NONCE,
    ), max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)


def _arguments(proposal):
    arguments = {"constructor_parameters": {}, "precondition_files": {}}
    if proposal is not None:
        arguments["scenario_hypothesis"] = proposal
    return arguments


def _run(index, candidate, context, proposal):
    first = ModelReply(model_id="offline-scenario", tool_calls=(ModelToolCall(
        call_id="propose-scenario", name=TOOL, arguments=_arguments(proposal),
    ),))

    def conclude(messages, tools):
        delivered = json.loads(next(message.content for message in reversed(messages) if message.role == "tool"))
        confirmed = delivered["status"] == "ok" and delivered.get("validation_status") == "CONFIRMED"
        citation = delivered["citation_id"] if delivered["status"] == "ok" else None
        return ModelReply(model_id="offline-scenario", content=json.dumps({
            "expert": "scan", "label": "VULNERABLE" if confirmed else "ABSTAIN",
            "confidence": 0.9 if confirmed else 0.0,
            "validation_status": "CONFIRMED" if confirmed else "UNRESOLVED",
            "evidence_ids": [citation] if citation else [],
            "supporting_observation_ids": [citation] if citation and confirmed else [],
            "rationale": "Use the delivered witness status and its explicitly conditional scope.",
        }))

    model = ScriptedChatModel([first, *([conclude] * (FULL_SYSTEM_HARNESS.react_loop.max_steps - 1))])
    verdict = AgenticPipeline(
        index=index, system=AgentSystemVersion.E1_LOCAL_SINGLE, models={"scan": model},
        tools=_registry(index, candidate, context),
    ).run(candidate)
    return verdict, model


def _observation(verdict):
    return verdict.votes[0].trace[0].observation


def test_renamed_entry_with_model_scenario_executes_and_admits_concrete_witness(tmp_path):
    index, candidate, context = _inputs(tmp_path / "repo")
    original_subject = candidate_subject(index, candidate)
    assert not original_subject.input_parameters
    assert not original_subject.entry_boolean_arguments
    assert not original_subject.entry_condition_assumptions
    assert not original_subject.entry_value_assumptions
    verdict, model = _run(index, candidate, context, _proposal())
    assert verdict.label == "VULNERABLE", verdict.model_dump(mode="json")
    assert len(model.requests) == 2
    observation = _observation(verdict)
    assert observation.validation_status == ValidationStatus.CONFIRMED
    assert observation.fixture_proof.supported_statuses == (ValidationStatus.CONFIRMED,)
    assert observation.subject == original_subject
    assert candidate_subject(index, candidate) == original_subject
    payload = json.loads(observation.content)
    assert payload["raw_status"] == "EXPANDED_OBSERVED"
    artifact = json.loads(Path(payload["artifact_path"]).read_text())
    assert payload["scenario_origin"] == artifact["scenario_origin"] == "model_proposed"
    reported_proposal = _proposal()
    reported_proposal["input_parameter"].pop("rationale")
    for field, premises in reported_proposal.items():
        if field != "input_parameter":
            for premise in premises.values():
                premise.pop("rationale")
    assert scenario_projection(payload) == reported_proposal
    assert artifact["scenario"] == _proposal()
    assert payload["scenario_sha256"] == artifact["scenario_sha256"]
    assert artifact["original_subject"] == original_subject.model_dump(mode="json")
    assert artifact["execution_subject"]["input_parameters"] == ["location"]
    assert artifact["execution_subject"]["entry_boolean_arguments"] == {"activated": True}
    assert payload["scenario_verification"]["remote_authority_established"] is False
    assert artifact["manifest"]["probe_argument"] == "location"
    assert artifact["manifest"]["class_name"] == "LaunchPad"
    assert artifact["manifest"]["method_name"] == "dispatch"
    assert artifact["manifest"]["constructor_kwargs"] == {"options": {}, "engine": "embedded"}
    assert artifact["manifest"]["precondition_files"] == {"metadata.json": "{}"}
    assert artifact["result"]["gaps"] == []
    assert artifact["result"]["details"]["derived_recorder"] == {"command": "widget", "arguments": ["launch"]}
    for phase in ("probe", "control"):
        assert payload[phase]["candidate_frame"]["file"] == "relay.py"
        assert not Path(payload[phase]["candidate_frame"]["file"]).is_absolute()
        assert payload[phase]["emitter_frame"] == {"same_as_candidate": True}
        event = artifact["result"]["details"][phase + "_event"]
        assert event["candidate_frame"] == event["emitter_frame"]
    assert str(context.checkout_root) not in json.dumps(payload)


@pytest.mark.parametrize("mistake", ["inactive", "wrong_condition", "unknown_input", "missing_file"])
def test_incorrect_model_scenario_cannot_supply_confirmation(tmp_path, mistake):
    index, candidate, context = _inputs(tmp_path / "repo")
    proposal = _proposal()
    if mistake == "inactive":
        proposal["entry_boolean_arguments"]["activated"]["value"] = False
    elif mistake == "wrong_condition":
        proposal["entry_condition_assumptions"]["os.path.exists(location)"]["value"] = False
    elif mistake == "unknown_input":
        proposal["input_parameter"]["value"] = "absent"
    else:
        proposal["precondition_files"] = {}
    verdict, _ = _run(index, candidate, context, proposal)
    assert verdict.label == "ABSTAIN"
    observation = _observation(verdict)
    assert observation.status == "ok", observation.content
    assert observation.validation_status == ValidationStatus.UNRESOLVED, observation.content
    if mistake == "wrong_condition":
        assert "entry_condition_assumption_mismatch:os.path.exists(location)" in observation.content
    if mistake == "unknown_input":
        assert not context.runtime_root.exists()


def test_quoted_entry_with_same_model_scenario_preserves_positive_only_contract(tmp_path):
    index, candidate, context = _inputs(tmp_path / "repo", quoted=True)
    verdict, _ = _run(index, candidate, context, _proposal())
    assert verdict.label == "ABSTAIN"
    observation = _observation(verdict)
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert json.loads(observation.content)["raw_status"] == "LITERAL_OBSERVED"
    assert "REFUTED" not in observation.content


def test_absent_scenario_never_fills_empty_candidate_assumptions_from_entry_names(tmp_path):
    index, candidate, context = _inputs(tmp_path / "repo")
    verdict, _ = _run(index, candidate, context, None)
    assert verdict.label == "ABSTAIN"
    assert _observation(verdict).validation_status == ValidationStatus.UNRESOLVED
    assert not context.runtime_root.exists()


@pytest.mark.parametrize("field,name", [
    ("input_parameter", None),
    ("entry_boolean_arguments", "activated"),
    ("entry_condition_assumptions", "os.path.exists(location)"),
    ("entry_value_assumptions", "self.workers"),
    ("constructor_parameters", "options"),
    ("precondition_files", "metadata.json"),
])
def test_every_model_premise_requires_classification_before_execution(tmp_path, field, name):
    index, candidate, context = _inputs(tmp_path / "repo")
    proposal = _proposal()
    requirement = proposal[field] if name is None else proposal[field][name]
    requirement.pop("classification")
    scope = ToolExecutionScope(
        admitted_paths=frozenset({candidate.path}), candidate_path=candidate.path,
        subject=candidate_subject(index, candidate),
        max_observation_tokens=FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens,
    )
    observation = _registry(index, candidate, context).invoke(
        ModelToolCall(call_id="unclassified", name=TOOL, arguments=_arguments(proposal)),
        allowed=(TOOL,), scope=scope, citation_id="tool:unclassified",
    )
    assert observation.status == "error"
    assert observation.validation_status is None
    assert observation.fixture_proof is None
    assert "classification" in observation.content
    assert not context.runtime_root.exists()


@pytest.mark.parametrize("rationale", [None, "", "   "])
def test_model_premise_requires_its_rationale_before_execution(tmp_path, rationale):
    index, candidate, context = _inputs(tmp_path / "repo")
    proposal = _proposal()
    if rationale is None:
        proposal["precondition_files"]["metadata.json"].pop("rationale")
    else:
        proposal["precondition_files"]["metadata.json"]["rationale"] = rationale
    scope = ToolExecutionScope(
        admitted_paths=frozenset({candidate.path}), candidate_path=candidate.path,
        subject=candidate_subject(index, candidate),
        max_observation_tokens=FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens,
    )
    observation = _registry(index, candidate, context).invoke(
        ModelToolCall(call_id="unexplained", name=TOOL, arguments=_arguments(proposal)),
        allowed=(TOOL,), scope=scope, citation_id="tool:unexplained",
    )
    assert observation.status == "error"
    assert observation.validation_status is None
    assert observation.fixture_proof is None
    assert "rationale" in observation.content
    assert not context.runtime_root.exists()


def test_label_metadata_cannot_change_model_scenario_or_generated_manifest(tmp_path):
    index, candidate, context = _inputs(tmp_path / "repo")
    proposal = _proposal()
    left, left_model = _run(index, candidate.model_copy(update={"metadata": {"expected_label": "SAFE"}}),
                            context, deepcopy(proposal))
    right, right_model = _run(index, candidate.model_copy(update={"metadata": {"expected_label": "VULNERABLE"}}),
                              context, deepcopy(proposal))
    assert left.label == right.label == "VULNERABLE"
    assert [step.tool_call for step in left.votes[0].trace] == [step.tool_call for step in right.votes[0].trace]
    assert _observation(left).metadata["manifest_sha256"] == _observation(right).metadata["manifest_sha256"]
    assert left_model.requests[0] == right_model.requests[0]
