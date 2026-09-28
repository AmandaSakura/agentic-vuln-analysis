"""The ordinary agent tool owns its manifest, runtime policy and positive proof."""

from __future__ import annotations

import ast
from dataclasses import replace
import hashlib
import json
import sys
from pathlib import Path

import pytest

from cv_agent.agents.evidence_policy import validate_conclusion
from cv_agent.agents.plan_policy import required_tasks, validate_plan_policy
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.domain.chat import ModelReply, ModelToolCall
from cv_agent.domain.evidence import ReActStep, ValidationStatus
from cv_agent.domain.review import AgentExpertConclusion, ValidationPlan
from cv_agent.domain.types import Candidate, CodeDocument
from cv_agent.tools.validation.witness_manifest import WitnessExecutionContext
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentSystemVersion
from cv_agent.retrieval import RepositoryIndex
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation.registry import full_agent_tools


TOOL = "run_bounded_execution_witness"


def _inputs(root: Path, *, quoted: bool = False, missing_constructor: bool = False):
    root.mkdir()
    expression = "shlex.quote(model_uri)" if quoted else "model_uri"
    constructor = "    def __init__(self, token):\n        self.token = token\n" if missing_constructor else ""
    source = (
        "import subprocess\nimport shlex\n\nclass Service:\n" + constructor
        + "    def serve(self, model_uri):\n"
        + f'        subprocess.Popen(["bash", "-c", f"ls {{{expression}}}"])\n'
    )
    path = root / "sample.py"
    path.write_text(source)
    method = next(node for node in ast.walk(ast.parse(source))
                  if isinstance(node, ast.FunctionDef) and node.name == "serve")
    span = f"sample.py::Service.serve@{method.lineno}-{method.end_lineno}"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    index = RepositoryIndex((
        CodeDocument(repository_id="neutral-repo", path=f"sample.py::<module>@1-{len(source.splitlines())}",
                     text=source, language="python", adapter_tier="ast", source_sha256=digest),
        CodeDocument(repository_id="neutral-repo", path=span,
                     text="".join(source.splitlines(keepends=True)[method.lineno - 1:method.end_lineno]),
                     language="python", adapter_tier="ast", source_sha256=digest,
                     defines=("Service.serve",)),
    ))
    candidate = Candidate(candidate_id="neutral-candidate", case_id="neutral-case", repository_id="neutral-repo",
                          path=span, line=method.lineno, query="entry", property_id="command-execution",
                          input_parameters=("model_uri",), analysis_scope="whole Service.serve call")
    context = WitnessExecutionContext(checkout_root=root, python_executable=Path(sys.executable),
                                      runtime_root=root.parent / "runtime")
    tools = ToolRegistry(full_agent_tools(index, witness_contexts={candidate.repository_id: context}),
                         max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)
    return index, candidate, context, tools


def _call(tools, index, candidate, arguments=None, *, admitted=True):
    subject = candidate_subject(index, candidate)
    call = ModelToolCall(call_id="call-witness", name=TOOL, arguments=(arguments or {
        "constructor_parameters": {}, "precondition_files": {},
    }))
    scope = ToolExecutionScope(admitted_paths=frozenset({candidate.path}) if admitted else frozenset(),
                               max_observation_tokens=FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens,
                               candidate_path=candidate.path, subject=subject)
    observation = tools.invoke(call, allowed=(TOOL,), scope=scope, citation_id="tool:witness")
    return call, observation, scope


def _conclude(call, observation, subject, *, label="VULNERABLE", status=ValidationStatus.CONFIRMED):
    conclusion = AgentExpertConclusion(expert="scan", label=label, confidence=.9,
        validation_status=status, evidence_ids=(observation.citation_id,),
        supporting_observation_ids=(observation.citation_id,), rationale="Use the measured candidate witness.")
    validate_conclusion(conclusion, [ReActStep(step=1, model_id="offline", tool_call=call,
                        observation=observation)], initial_evidence_ids=frozenset(), subject=subject)


def test_standard_factory_registers_tool_and_exact_positive_channel(tmp_path: Path) -> None:
    index, candidate, _, tools = _inputs(tmp_path / "checkout")
    assert TOOL in FULL_SYSTEM_HARNESS.validation.validators
    assert TOOL in next(expert for expert in FULL_SYSTEM_HARNESS.experts if expert.expert == "scan").tools
    assert tools.candidate_witness_available(candidate_subject(index, candidate))
    call, observation, scope = _call(tools, index, candidate)
    assert observation.status == "ok", observation.content
    assert observation.validation_status == ValidationStatus.CONFIRMED, observation.content
    assert observation.subject == scope.subject
    assert observation.fixture_proof.coverage == "candidate"
    assert observation.fixture_proof.method == "bounded_execution"
    assert observation.fixture_proof.supported_statuses == (ValidationStatus.CONFIRMED,)
    result = json.loads(observation.content)
    assert result["raw_status"] == "EXPANDED_OBSERVED"
    assert Path(result["artifact_path"]).is_file()
    _conclude(call, observation, scope.subject)


def test_literal_never_supports_safe_or_refuted(tmp_path: Path) -> None:
    index, candidate, _, tools = _inputs(tmp_path / "checkout", quoted=True)
    call, observation, scope = _call(tools, index, candidate)
    assert observation.validation_status == ValidationStatus.UNRESOLVED, observation.content
    assert json.loads(observation.content)["raw_status"] == "LITERAL_OBSERVED"
    assert "REFUTED" not in observation.content
    with pytest.raises(ValueError):
        _conclude(call, observation, scope.subject, label="SAFE", status=ValidationStatus.REFUTED)


def test_missing_constructor_is_structured_gap_then_only_missing_field_can_complete(tmp_path: Path) -> None:
    index, candidate, _, tools = _inputs(tmp_path / "checkout", missing_constructor=True)
    assert tools.candidate_witness_available(candidate_subject(index, candidate))
    _, missing, _ = _call(tools, index, candidate)
    payload = json.loads(missing.content)
    assert missing.validation_status == ValidationStatus.UNRESOLVED
    assert "token" in payload["missing_constructor_parameters"]
    assert "probe_nonce" not in payload and "probe_path" not in payload
    _, completed, _ = _call(tools, index, candidate, {
        "constructor_parameters": {"token": 7}, "precondition_files": {},
    })
    assert completed.validation_status == ValidationStatus.CONFIRMED, completed.content


@pytest.mark.parametrize("forbidden", ["manifest", "nonce", "label", "recorder_command", "python_executable",
                                        "resource_profile", "stub", "call_kwargs"])
def test_model_cannot_supply_runtime_manifest_or_proof_fields(tmp_path: Path, forbidden: str) -> None:
    index, candidate, _, tools = _inputs(tmp_path / "checkout")
    _, observation, _ = _call(tools, index, candidate, {
        "constructor_parameters": {}, "precondition_files": {}, forbidden: "not allowed",
    })
    assert observation.status == "error"
    assert observation.validation_status is None
    assert observation.fixture_proof is None


def test_candidate_outside_scope_and_stale_source_never_execute(tmp_path: Path) -> None:
    index, candidate, context, tools = _inputs(tmp_path / "checkout")
    _, outside, _ = _call(tools, index, candidate, admitted=False)
    assert outside.validation_status == ValidationStatus.UNRESOLVED
    assert "candidate_not_admitted" in outside.content
    assert not context.runtime_root.exists()
    (context.checkout_root / "sample.py").write_text("raise AssertionError('stale code must not execute')\n")
    _, stale, _ = _call(tools, index, candidate)
    assert stale.validation_status == ValidationStatus.UNRESOLVED
    assert not context.runtime_root.exists()


def test_default_registry_exposes_name_but_has_no_execution_context() -> None:
    tools = ToolRegistry(full_agent_tools(RepositoryIndex()), max_output_bytes=10000)
    assert TOOL in tools.names
    assert TOOL not in tools.available_names


def test_witness_task_retains_command_inspections_and_orders_taint_after_witness(tmp_path: Path) -> None:
    index, candidate, _, tools = _inputs(tmp_path / "checkout")
    candidate = candidate.model_copy(update={"analysis_scope": "get_cmd subprocess.Popen bash shell-command"})
    subject = candidate_subject(index, candidate)
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E4_GRAPH_MULTI)
    tasks = required_tasks(candidate, None, tools, spec, subject=subject)
    assert {task.allowed_validator for task in tasks} == {TOOL, "inspect_command_construction"}
    witness = next(task for task in tasks if task.allowed_validator == TOOL)
    assert witness.expert == "scan"
    for task in tasks:
        if task.allowed_validator == "inspect_command_construction":
            assert witness.task_id in task.dependencies
    plan = ValidationPlan(candidate_id=candidate.candidate_id, subtasks=tasks,
                          vulnerability_hypotheses=("bounded shell interpolation",),
                          rationale="typed independent checks")
    validate_plan_policy(plan, harness=FULL_SYSTEM_HARNESS, system_spec=spec,
                         tools=tools, candidate=candidate, subject=subject)
    omitted = plan.model_copy(update={"subtasks": tuple(task for task in tasks
        if task.allowed_validator != "inspect_command_construction")})
    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_plan_policy(omitted, harness=FULL_SYSTEM_HARNESS, system_spec=spec,
                             tools=tools, candidate=candidate, subject=subject)


def test_trusted_src_layout_keeps_repo_relative_source_binding(tmp_path: Path) -> None:
    index, candidate, context, _ = _inputs(tmp_path / "checkout")
    source_root = context.checkout_root / "src"
    source_root.mkdir()
    (context.checkout_root / "sample.py").rename(source_root / "sample.py")
    index = RepositoryIndex(doc.model_copy(update={"path": "src/" + doc.path})
                            for doc in index.documents.values())
    candidate = candidate.model_copy(update={"path": "src/" + candidate.path})
    context = replace(context, import_root="src")
    tools = ToolRegistry(full_agent_tools(index, witness_contexts={candidate.repository_id: context}),
                         max_output_bytes=100000)
    _, observation, _ = _call(tools, index, candidate)
    assert observation.validation_status == ValidationStatus.CONFIRMED, observation.content
    payload = json.loads(observation.content)
    artifact = json.loads(Path(payload["artifact_path"]).read_text())
    assert artifact["manifest"]["import_root"] == "src"
    assert artifact["manifest"]["entry_relative_path"] == "src/sample.py"
    assert artifact["result"]["details"]["probe_event"]["candidate_frame"]["sha256"] == artifact["manifest"]["entry_file_sha256"]


def test_trusted_import_root_cannot_escape_checkout(tmp_path: Path) -> None:
    index, candidate, context, _ = _inputs(tmp_path / "checkout")
    context = replace(context, import_root="../outside")
    tools = ToolRegistry(full_agent_tools(index, witness_contexts={candidate.repository_id: context}),
                         max_output_bytes=100000)
    assert not tools.candidate_witness_available(candidate_subject(index, candidate))
    _, observation, _ = _call(tools, index, candidate)
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert not context.runtime_root.exists()


def test_later_line_candidate_cannot_borrow_first_command_expansion(tmp_path: Path) -> None:
    index, candidate, context, _ = _inputs(tmp_path / "checkout")
    source_file = context.checkout_root / "sample.py"
    source = source_file.read_text() + '        subprocess.Popen(["bash", "-c", f"ls {shlex.quote(model_uri)}"])\n'
    source_file.write_text(source)
    method = next(node for node in ast.walk(ast.parse(source))
                  if isinstance(node, ast.FunctionDef) and node.name == "serve")
    digest = hashlib.sha256(source_file.read_bytes()).hexdigest()
    span = f"sample.py::Service.serve@{method.lineno}-{method.end_lineno}"
    documents = []
    for document in index.documents.values():
        module = "::<module>" in document.path
        documents.append(document.model_copy(update={
            "path": f"sample.py::<module>@1-{len(source.splitlines())}" if module else span,
            "text": source if module else "".join(source.splitlines(keepends=True)[method.lineno - 1:method.end_lineno]),
            "source_sha256": digest,
        }))
    index = RepositoryIndex(documents)
    candidate = candidate.model_copy(update={"path": span, "line": method.end_lineno,
        "analysis_scope": "selected final Popen invocation and the data affecting that invocation"})
    tools = ToolRegistry(full_agent_tools(index, witness_contexts={candidate.repository_id: context}),
                         max_output_bytes=100000)
    _, observation, _ = _call(tools, index, candidate)
    assert observation.validation_status == ValidationStatus.UNRESOLVED, observation.content
    assert not tools.candidate_witness_available(candidate_subject(index, candidate))


def test_preparation_response_does_not_complete_implicit_witness_task(tmp_path: Path) -> None:
    index, candidate, context, tools = _inputs(tmp_path / "checkout", missing_constructor=True)
    final = ModelReply(model_id="offline", content=json.dumps({
        "expert": "scan", "label": "ABSTAIN", "confidence": 0.0,
        "validation_status": "UNRESOLVED", "evidence_ids": ["scan/tool:1"],
        "supporting_observation_ids": [], "counter_observation_ids": [],
        "unresolved_observation_ids": ["scan/tool:1"],
        "rationale": "Constructor data is missing.",
    }))
    model = ScriptedChatModel([
        ModelReply(model_id="offline", tool_calls=(ModelToolCall(call_id="prepare", name=TOOL,
            arguments={"constructor_parameters": {}, "precondition_files": {}}),)),
        *([final] * (FULL_SYSTEM_HARNESS.react_loop.max_steps - 1)),
    ])
    result = AgenticPipeline(index=index, system=AgentSystemVersion.E1_LOCAL_SINGLE,
        models={"scan": model}, tools=tools).run(candidate)
    assert result.label == "ABSTAIN"
    assert result.task_executions[0].validator_completed is False
    assert result.votes[0].trace[0].observation.metadata["witness_attempted"] is False
    assert not context.runtime_root.exists()
