"""Real source-bound function and Click callback controls in the project env."""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
from types import FunctionType, SimpleNamespace

import pytest

from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.domain.chat import ModelReply, ModelToolCall
from cv_agent.domain.evidence import ValidationStatus
from cv_agent.domain.types import Candidate, CodeDocument
from cv_agent.evaluation.diagnostics.bounded_execution_witness import _capture_event
from cv_agent.evaluation.diagnostics.bounded_execution_witness import SourceFileBinding, run_witness
from cv_agent.harness import AgentSystemVersion, FULL_SYSTEM_HARNESS
from cv_agent.retrieval import RepositoryIndex
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation.registry import full_agent_tools
from cv_agent.tools.validation.witness_manifest import WitnessExecutionContext
from test_bounded_execution_witness import DIRECT, NONCE, _manifest


TOOL = "run_bounded_execution_witness"


def _premise(value, classification="deployment_configuration"):
    return {"value": value, "classification": classification,
            "rationale": "Concrete caller requirement for this synthetic entry."}


def _proposal():
    return {
        "input_parameter": _premise("location", "attacker_controlled_input"),
        "entry_boolean_arguments": {"activated": _premise(True)},
        "entry_condition_assumptions": {
            "os.path.exists(location)": _premise(True, "environment_condition"),
        },
        "entry_value_assumptions": {}, "constructor_parameters": {},
        "precondition_files": {"metadata.json": _premise("{}", "attacker_controlled_input")},
    }


def _source(kind="click_callback", *, quoted=False, suffix="", preempt=False):
    imports = "import os\nimport shlex\nimport subprocess\n"
    decorators = ""
    if kind == "click_callback":
        imports += "import click\n"
        decorators = ('@click.command()\n'
                      '@click.option("--location", required=True)\n'
                      '@click.option("--activated", is_flag=True)\n')
    expression = "shlex.quote(location)" if quoted else "location"
    body = (
        "    if not activated:\n        return None\n"
        "    if not os.path.exists(location):\n        return None\n"
        "    if not os.path.exists(os.path.join(location, 'metadata.json')):\n        return None\n"
    )
    if preempt:
        body += '    subprocess.Popen(["echo", "setup"])\n'
    body += f'    subprocess.Popen(["bash", "-c", f"widget launch {{{expression}}}"])\n'
    if kind == "instance_method":
        definition = "class LaunchNode:\n    def dispatch(self, location, activated=False):\n"
        body = "".join("    " + line for line in body.splitlines(keepends=True))
    else:
        definition = decorators + "def dispatch(location, activated=False):\n"
    return imports + "\n" + definition + body + suffix


def _inputs(tmp_path, *, kind="click_callback", quoted=False, suffix="", preempt=False,
            extra_sources=None, line_offset=0):
    root = tmp_path / "checkout"
    root.mkdir()
    source = _source(kind, quoted=quoted, suffix=suffix, preempt=preempt)
    sources = {"dispatch_unit.py": source, **(extra_sources or {})}
    documents = []
    for relative, text in sources.items():
        (root / relative).write_text(text)
        documents.append(CodeDocument(repository_id="entry-repo", language="python", adapter_tier="ast",
            path=f"{relative}::<module>@1-{len(text.splitlines())}", text=text,
            source_sha256=hashlib.sha256(text.encode()).hexdigest()))
    tree = ast.parse(source)
    node = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "dispatch")
    first = min((item.lineno for item in node.decorator_list), default=node.lineno)
    symbol = "LaunchNode.dispatch" if kind == "instance_method" else "dispatch"
    span = f"dispatch_unit.py::{symbol}@{first}-{node.end_lineno}"
    documents.append(CodeDocument(repository_id="entry-repo", language="python", adapter_tier="ast",
        path=span, text="".join(source.splitlines(keepends=True)[first - 1:node.end_lineno]),
        source_sha256=hashlib.sha256(source.encode()).hexdigest(), defines=(symbol,)))
    index = RepositoryIndex(documents)
    candidate = Candidate(candidate_id="entry-candidate", case_id="entry-case", repository_id="entry-repo",
        path=span, line=first + line_offset, property_id="command-execution",
        query="Assess this entry.", analysis_scope="Whole entry in this fixed source snapshot.")
    context = WitnessExecutionContext(checkout_root=root, python_executable=Path(sys.executable),
        runtime_root=tmp_path / "runtime")
    registry = ToolRegistry(full_agent_tools(index, witness_contexts={candidate.repository_id: context},
        witness_nonce_factory=lambda: "ENTRYADAPTER123456789"),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)
    return index, candidate, context, registry


def _arguments(proposal=None):
    return {"constructor_parameters": {}, "precondition_files": {},
            "scenario_hypothesis": _proposal() if proposal is None else proposal}


def _observe(inputs, proposal=None):
    index, candidate, _, registry = inputs
    scope = ToolExecutionScope(admitted_paths=frozenset({candidate.path}), candidate_path=candidate.path,
        subject=candidate_subject(index, candidate),
        max_observation_tokens=FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens)
    return registry.invoke(ModelToolCall(call_id="entry", name=TOOL, arguments=_arguments(proposal)),
        allowed=(TOOL,), scope=scope, citation_id="tool:entry")


@pytest.mark.parametrize("kind", ["instance_method", "function", "click_callback"])
def test_real_entry_adapter_confirms_and_retains_exact_bound_frame(tmp_path, kind):
    inputs = _inputs(tmp_path, kind=kind)
    observation = _observe(inputs)
    assert observation.status == "ok", observation.content
    assert observation.validation_status == ValidationStatus.CONFIRMED, observation.content
    payload = json.loads(observation.content)
    artifact = json.loads(Path(payload["artifact_path"]).read_text())
    assert artifact["manifest"]["entry_invocation"] == kind
    for phase in ("probe", "control"):
        event = artifact["result"]["details"][phase + "_event"]
        frame = event["candidate_frame"]
        assert frame["qualname"] == ("LaunchNode.dispatch" if kind == "instance_method" else "dispatch")
        assert frame["file"] == str(inputs[2].checkout_root / "dispatch_unit.py")
        assert frame["first_line"] == inputs[1].line
        assert frame == event["emitter_frame"]
        assert event["assumption_verification"]["gaps"] == []
        assert event["entry_adapter"]["invocation"] == kind
        assert event["entry_adapter"]["public_parser_executed"] is False
    assert artifact["original_subject"]["input_parameters"] == []


@pytest.mark.parametrize("kind", ["function", "click_callback"])
def test_quoted_real_entry_remains_unresolved_literal(tmp_path, kind):
    observation = _observe(_inputs(tmp_path, kind=kind, quoted=True))
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert json.loads(observation.content)["raw_status"] == "LITERAL_OBSERVED"


def test_authentic_click_tool_observation_admitted_through_scripted_pipeline(tmp_path):
    index, candidate, _, registry = _inputs(tmp_path)
    first = ModelReply(model_id="offline-entry", tool_calls=(ModelToolCall(
        call_id="entry", name=TOOL, arguments=_arguments()),))
    def finish(messages, tools):
        delivered = json.loads(next(message.content for message in reversed(messages) if message.role == "tool"))
        citation = delivered["citation_id"]
        return ModelReply(model_id="offline-entry", content=json.dumps({
            "expert": "scan", "label": "VULNERABLE", "confidence": 0.9,
            "validation_status": "CONFIRMED", "evidence_ids": [citation],
            "supporting_observation_ids": [citation], "rationale": "Use this concrete source-bound witness.",
        }))
    model = ScriptedChatModel([first, *([finish] * (FULL_SYSTEM_HARNESS.react_loop.max_steps - 1))])
    verdict = AgenticPipeline(index=index, system=AgentSystemVersion.E1_LOCAL_SINGLE,
        models={"scan": model}, tools=registry).run(candidate)
    assert verdict.label == "VULNERABLE", verdict.model_dump(mode="json")
    assert len(model.requests) == 2


@pytest.mark.parametrize("kind", ["instance_method", "function", "click_callback"])
def test_identical_code_with_foreign_globals_cannot_borrow_candidate(tmp_path, kind):
    target = "LaunchNode.dispatch" if kind == "instance_method" else ("dispatch.callback" if kind == "click_callback" else "dispatch")
    suffix = f'\nfrom types import FunctionType\n{target} = FunctionType({target}.__code__, dict(globals()))\n'
    observation = _observe(_inputs(tmp_path, kind=kind, suffix=suffix))
    assert observation.validation_status == ValidationStatus.UNRESOLVED, observation.content
    assert "entry_function_globals_mismatch" in observation.content


@pytest.mark.parametrize("suffix,gap", [
    ('\ndef alternate(location, activated=False):\n    return None\ndispatch.callback = alternate\n', "entry_function_code_mismatch"),
    ('\nsaved = dispatch.callback\nclass Substitute:\n    def __init__(self):\n        self.callback = saved\nclick.core.Command = Substitute\ndispatch = Substitute()\n', "entry_click_command_type_mismatch"),
    ('\nsaved = dispatch.callback\nclass Substitute:\n    def __init__(self):\n        self.__wrapped__ = saved\ndispatch = Substitute()\n', "entry_click_command_type_mismatch"),
    ('\nclass Alternative(click.Command):\n    pass\ndispatch = Alternative("dispatch", callback=dispatch.callback)\n', "entry_click_command_type_mismatch"),
    ('\ndispatch.callback = object()\n', "entry_function_binding_unsupported"),
    ('\ndispatch.callback.__code__ = dispatch.callback.__code__.replace(co_name="impostor")\n', "entry_function_code_mismatch"),
])
def test_click_impostors_and_swapped_callbacks_remain_unresolved(tmp_path, suffix, gap):
    observation = _observe(_inputs(tmp_path, suffix=suffix))
    assert observation.validation_status == ValidationStatus.UNRESOLVED, observation.content
    assert gap in observation.content


def test_trusted_command_identity_survives_target_export_rebinding(tmp_path):
    observation = _observe(_inputs(tmp_path, suffix="\nclick.core.Command = object\nclick.Command = object\n"))
    assert observation.validation_status == ValidationStatus.CONFIRMED, observation.content


def test_target_framework_shadow_cannot_replace_captured_command_type(tmp_path):
    fake = ('class Command:\n    def __init__(self, callback):\n        self.callback = callback\n'
            'def command():\n    return Command\n'
            'def option(*args, **kwargs):\n    return lambda function: function\n')
    observation = _observe(_inputs(tmp_path, extra_sources={"click.py": fake}))
    assert observation.validation_status == ValidationStatus.UNRESOLVED, observation.content
    assert "source_mismatch" in observation.content or "entry_click_command_type_mismatch" in observation.content


def test_decorator_start_is_the_only_admitted_candidate_header(tmp_path):
    observation = _observe(_inputs(tmp_path, line_offset=3))
    assert observation.validation_status == ValidationStatus.UNRESOLVED, observation.content
    assert "candidate_scope_unbound" in observation.content


def test_click_context_wrapper_is_not_arbitrarily_unwrapped(tmp_path):
    suffix = "\ndispatch.callback = click.pass_context(dispatch.callback)\n"
    observation = _observe(_inputs(tmp_path, suffix=suffix))
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert "entry_function_globals_mismatch" in observation.content


def test_first_unrelated_process_is_never_skipped(tmp_path):
    observation = _observe(_inputs(tmp_path, preempt=True))
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    payload = json.loads(observation.content)
    artifact = json.loads(Path(payload["artifact_path"]).read_text())
    assert artifact["result"]["details"]["probe_event"]["argv"] == ["echo", "setup"]
    assert artifact["result"]["gaps"] == ["recorder_prefix_not_established"]


def test_candidate_frame_is_exact_code_object_among_same_key_impostors(tmp_path):
    source = ("class LaunchNode:\n"
              "    def dispatch(self, callback):\n"
              "        return callback()\n"
              "def impostor():\n"
              "    pass\n"
              "    return trampoline()\n")
    file = tmp_path / "dispatch_unit.py"
    file.write_text(source)
    dictionary = {"__name__": "dispatch_unit"}
    exec(compile(source, str(file), "exec"), dictionary)
    function = dictionary["LaunchNode"].dispatch
    manifest = SimpleNamespace(entry_relative_path=file.name, entry_first_line=2,
        class_name="LaunchNode", method_name="dispatch", entry_qualified_name="LaunchNode.dispatch",
        entry_file_sha256=hashlib.sha256(source.encode()).hexdigest())
    def trampoline():
        return _capture_event("os.system", ("echo harmless",), tmp_path, manifest,
            function.__code__, (), expected_globals=dictionary)
    dictionary["trampoline"] = trampoline
    impostor = FunctionType(dictionary["impostor"].__code__.replace(
        co_qualname=function.__code__.co_qualname, co_firstlineno=function.__code__.co_firstlineno), dictionary)
    event = dictionary["LaunchNode"]().dispatch(impostor)
    assert event["candidate_frame"]["line"] == 3
    assert event["emitter_frame"]["line"] == 4
    assert event["candidate_frame"]["qualname"] == event["emitter_frame"]["qualname"]


@pytest.mark.parametrize("mistake", ["boolean", "condition", "input", "file", "classification", "constructor"])
def test_wrong_or_unclassified_callback_premises_cannot_confirm(tmp_path, mistake):
    proposal = deepcopy(_proposal())
    if mistake == "boolean":
        proposal["entry_boolean_arguments"]["activated"]["value"] = False
    elif mistake == "condition":
        proposal["entry_condition_assumptions"]["os.path.exists(location)"]["value"] = False
    elif mistake == "input":
        proposal["input_parameter"]["value"] = "absent"
    elif mistake == "file":
        proposal["precondition_files"] = {}
    elif mistake == "classification":
        proposal["input_parameter"].pop("classification")
    else:
        proposal["constructor_parameters"]["unused"] = _premise({})
    observation = _observe(_inputs(tmp_path), proposal)
    assert observation.validation_status in {None, ValidationStatus.UNRESOLVED}, observation.content
    if mistake == "classification":
        assert observation.status == "error"


def test_response_mode_is_a_strict_trusted_context_choice(tmp_path):
    context = WitnessExecutionContext(checkout_root=tmp_path)
    assert context.response_mode == "full"
    assert replace(context, response_mode="compact").response_mode == "compact"
    with pytest.raises(ValueError, match="response_mode"):
        replace(context, response_mode="unknown")


def test_dead_entry_after_import_error_preserves_actual_import_diagnostic(tmp_path):
    manifest = _manifest(tmp_path, 'raise ImportError("actual import failure")\n' + DIRECT)
    result = run_witness(manifest, nonce=NONCE, diagnostic_only=True)
    assert result.status == ValidationStatus.UNRESOLVED
    assert result.details["probe_event"]["gap"] == "target_or_isolation_error"
    assert "ImportError: actual import failure" in result.details["probe_event"]["error"]
    assert "candidate_frame" not in result.details["probe_event"]


def test_successful_import_with_compiler_removed_entry_cannot_invoke(tmp_path):
    manifest = _manifest(tmp_path, DIRECT)
    source = ("import subprocess\n"
              "if False:\n"
              "    class Service:\n"
              "        def serve(self, model_uri):\n"
              "            subprocess.Popen(['bash', '-c', f'record {model_uri}'])\n")
    path = tmp_path / "sample.py"
    path.write_text(source)
    digest = hashlib.sha256(source.encode()).hexdigest()
    manifest = manifest.model_copy(update={
        "entry_first_line": 4, "entry_file_sha256": digest,
        "subject": manifest.subject.model_copy(update={"entry_path": "sample.py::Service.serve@4-5", "entry_line": 4}),
        "source_modules": (SourceFileBinding(module_name="sample", relative_path="sample.py", sha256=digest),),
    })
    result = run_witness(manifest, nonce=NONCE, diagnostic_only=True)
    assert result.status == ValidationStatus.UNRESOLVED
    assert result.details["probe_event"]["gap"] == "entry_source_code_nonunique"
    assert "candidate_frame" not in result.details["probe_event"]
    assert "probe_replay" not in result.details


def test_reachable_source_entry_still_confirms_with_all_obligations(tmp_path):
    result = run_witness(_manifest(tmp_path, DIRECT), nonce=NONCE, verify_obligations=True)
    assert result.status == ValidationStatus.CONFIRMED, result.model_dump()
    assert result.details["probe_event"]["assumption_verification"]["gaps"] == []
