"""Rendered-request preflight verifies source provenance before masking it."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from cv_agent.domain.chat import ChatMessage, ModelToolCall
from cv_agent.domain.types import Candidate, CodeDocument
from cv_agent.evaluation.diagnostics.witness_scenario_preflight import (
    CapturedInitialRequest, WitnessPreflightError, capture_initial_request,
    inspect_initial_request, preflight_cells,
)
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation.registry import full_agent_tools
from cv_agent.tools.validation.witness_manifest import WitnessExecutionContext
from cv_agent.tools.validation.witness_scenario import WitnessScenarioHypothesis


def _premise(value, category="deployment_configuration"):
    return {"value": value, "classification": category, "rationale": "Concrete offline fixture premise."}


def _inputs(tmp_path):
    root = tmp_path / "checkout"
    root.mkdir()
    source = ("import os\nclass Entry:\n"
              "    def call(self, location, engaged=False):\n"
              "        if engaged and os.path.exists(location):\n            return location\n")
    (root / "entry.py").write_text(source)
    span = "entry.py::Entry.call@3-5"
    digest = hashlib.sha256(source.encode()).hexdigest()
    index = RepositoryIndex((
        CodeDocument(repository_id="neutral-entry", path=span, language="python", adapter_tier="ast",
                     text="".join(source.splitlines(keepends=True)[2:]), source_sha256=digest),
        CodeDocument(repository_id="neutral-entry", path="entry.py::<module>@1-5", language="python",
                     adapter_tier="ast", text=source, source_sha256=digest),
    ))
    candidate = Candidate(candidate_id="neutral-entry", case_id="neutral-entry", repository_id="neutral-entry",
                          path=span, line=3, query="A disclosed command advisory.", property_id="command-execution",
                          analysis_scope="Assess the exact entry and disclosed advisory.")
    context = WitnessExecutionContext(checkout_root=root, runtime_root=tmp_path / "unused-runtime")
    tools = tuple(full_agent_tools(index, witness_contexts={candidate.repository_id: context}))
    scenario = WitnessScenarioHypothesis.model_validate({
        "input_parameter": _premise("location", "attacker_controlled_input"),
        "entry_boolean_arguments": {"engaged": _premise(True)},
        "entry_condition_assumptions": {"os.path.exists(location)": _premise(True, "environment_condition")},
    })
    return index, candidate, context, tools, scenario


def test_actual_initial_capture_uses_no_credentials_transport_workers_or_tools(tmp_path, monkeypatch):
    index, candidate, context, tools, scenario = _inputs(tmp_path)
    def forbidden(*args, **kwargs):
        raise AssertionError("preflight must not invoke credentials, model transport, tool or worker")
    from cv_agent.runtime import provider, model
    from cv_agent.evaluation.diagnostics import bounded_execution_witness
    monkeypatch.setattr(provider, "load_experiment_model", forbidden)
    monkeypatch.setattr(model.OpenAICompatibleChatModel, "complete", forbidden)
    monkeypatch.setattr(bounded_execution_witness, "run_witness", forbidden)
    monkeypatch.setattr(ToolRegistry, "invoke", forbidden)
    request = capture_initial_request(index, candidate, tools)
    report = inspect_initial_request(request, index, candidate, scenario=scenario, scenario_empty=True,
                                     private_markers=("private-case-99", "/private/interpreter"))
    assert report["passed"] is True
    assert report["live_model_requests"] == report["tool_calls"] == report["worker_executions"] == 0
    assert report["outside_source_marker_counts"]["engaged"] == 0
    assert report["outside_source_marker_counts"]["os.path.exists(location)"] == 0
    assert "engaged" in report["request"]["messages"][1]["content"]
    assert not context.runtime_root.exists()


@pytest.mark.parametrize("where", ["metadata", "tool_description", "tool_schema", "advisory", "source"])
def test_foreign_premises_or_forged_source_are_rejected(tmp_path, where):
    index, candidate, _, tools, scenario = _inputs(tmp_path)
    request = capture_initial_request(index, candidate, tools)
    messages = list(request.messages)
    definitions = deepcopy(request.tools)
    if where in {"metadata", "advisory"}:
        content = messages[1].content
        data, endpoint = json.JSONDecoder().raw_decode(content)
        data["candidate"]["analysis_scope"] += (
            " Scenario assumes engaged=True." if where == "metadata" else " Advisory summary: engaged=True.")
        messages[1] = messages[1].model_copy(update={"content": json.dumps(data) + content[endpoint:]})
    elif where == "tool_description":
        definitions[0]["function"]["description"] += " Set engaged=True."
    elif where == "tool_schema":
        definitions[0]["function"]["parameters"]["properties"]["engaged"] = {"type": "boolean"}
    else:
        content = messages[1].content
        data, endpoint = json.JSONDecoder().raw_decode(content)
        data["retrieved_code"][0]["text"] += "\n# forged fixture instruction\n"
        messages[1] = messages[1].model_copy(update={"content": json.dumps(data) + content[endpoint:]})
    changed = CapturedInitialRequest(tuple(messages), definitions)
    with pytest.raises(WitnessPreflightError, match="source|outside"):
        inspect_initial_request(changed, index, candidate, scenario=scenario, scenario_empty=True)


def test_rendered_candidate_cannot_change_location_while_reusing_bound_source(tmp_path):
    index, candidate, _, tools, scenario = _inputs(tmp_path)
    request = capture_initial_request(index, candidate, tools)
    messages = list(request.messages)
    content = messages[1].content
    data, endpoint = json.JSONDecoder().raw_decode(content)
    data["candidate"]["path"] = "unrelated.py::Entry.call@3-5"
    messages[1] = messages[1].model_copy(update={"content": json.dumps(data) + content[endpoint:]})
    with pytest.raises(WitnessPreflightError, match="identity"):
        inspect_initial_request(CapturedInitialRequest(tuple(messages), request.tools), index, candidate,
                                scenario=scenario, scenario_empty=True)


@pytest.mark.parametrize("private", ["private-case-99", "bca832ab", "/private/venv/bin/python"])
def test_private_case_commit_and_interpreter_aliases_are_rejected(tmp_path, private):
    index, candidate, _, tools, scenario = _inputs(tmp_path)
    request = capture_initial_request(index, candidate, tools)
    messages = list(request.messages)
    messages[0] = messages[0].model_copy(update={"content": messages[0].content + " " + private})
    with pytest.raises(WitnessPreflightError, match="private"):
        inspect_initial_request(CapturedInitialRequest(tuple(messages), request.tools), index, candidate,
                                scenario=scenario, scenario_empty=True, private_markers=(private,))


def test_source_derived_entry_marker_is_verified_before_being_allowed(tmp_path):
    index, candidate, _, tools, scenario = _inputs(tmp_path)
    candidate = candidate.model_copy(update={"analysis_scope":
        "Declared entry code marker:     def call(self, location, engaged=False):. Inspect the disclosed advisory."})
    request = capture_initial_request(index, candidate, tools)
    report = inspect_initial_request(request, index, candidate, scenario=scenario, scenario_empty=True)
    assert report["outside_source_marker_counts"]["engaged"] == 0
    candidate = candidate.model_copy(update={"analysis_scope":
        "Declared entry code marker: def invented(engaged=True):. Inspect the disclosed advisory."})
    with pytest.raises(WitnessPreflightError, match="entry marker"):
        inspect_initial_request(capture_initial_request(index, candidate, tools), index, candidate,
                                scenario=scenario, scenario_empty=True)
    candidate = candidate.model_copy(update={"analysis_scope":
        "Declared entry code marker: engaged. Inspect the disclosed advisory."})
    with pytest.raises(WitnessPreflightError, match="entry marker"):
        inspect_initial_request(capture_initial_request(index, candidate, tools), index, candidate,
                                scenario=scenario, scenario_empty=True)


def test_preflight_reports_paired_input_controls_without_demanding_identical_source(tmp_path):
    index, base, context, _, scenario = _inputs(tmp_path)
    supplied = base.model_copy(update={
        "input_parameters": ("location",), "entry_boolean_arguments": {"engaged": True},
        "entry_condition_assumptions": {"os.path.exists(location)": True},
        "analysis_scope": "Declared supplied scenario engaged=True and os.path.exists(location)=True.",
    })
    cells = []
    for origin, candidate in (("dataset_provided", supplied), ("model_proposed", base)):
        for case in ("private-first", "private-second"):
            supplied_context = replace(context, dataset_scenario=scenario if origin == "dataset_provided" else None)
            tools = tuple(full_agent_tools(index, witness_contexts={candidate.repository_id: supplied_context}))
            cells.append(SimpleNamespace(evaluation_case_id=case, scenario_origin=origin, index=index,
                candidate=candidate, context=supplied_context, registered_tools=tools,
                identity={"case_id": case, "commit": "12345678abcdef", "configured_commit": "12345678abcdef"}))
    config = SimpleNamespace(dataset_scenario=scenario, origins=("dataset_provided", "model_proposed"))
    report = preflight_cells(tuple(cells), config)
    assert len(report["cells"]) == 4
    assert all(control["same_supplied_inputs"] for control in report["controls"].values())
    assert all(control["same_initial_request"] for control in report["controls"].values())
    assert not context.runtime_root.exists()
    changed = tuple(cells[:-1]) + (SimpleNamespace(**{**vars(cells[-1]), "candidate":
        base.model_copy(update={"query": "A different advisory input."})}),)
    with pytest.raises(WitnessPreflightError, match="paired snapshots"):
        preflight_cells(changed, config)


def test_b_only_preflight_requires_no_reference_scene_and_runs_only_declared_cells(tmp_path):
    index, candidate, context, tools, _ = _inputs(tmp_path)
    cells = tuple(SimpleNamespace(evaluation_case_id=case, scenario_origin="model_proposed", index=index,
        candidate=candidate, context=context, registered_tools=tools, identity={"case_id": case})
        for case in ("private-first", "private-second"))
    report = preflight_cells(cells, SimpleNamespace(origins=("model_proposed",), dataset_scenario=None))
    assert report["origins"] == ("model_proposed",)
    assert len(report["cells"]) == 2
    assert all(cell["scenario_reference_provided"] is False for cell in report["cells"])
    assert all(cell["outside_source_marker_counts"] == {} for cell in report["cells"])
    assert set(report["controls"]) == {"model_proposed"}
    assert report["controls"]["model_proposed"]["same_supplied_inputs"] is True
    assert report["live_model_requests"] == report["worker_executions"] == report["tool_calls"] == 0
    assert not context.runtime_root.exists()


@pytest.mark.parametrize("declaration", ["Declared externally supplied entry parameters:",
                                        "Scenario entry boolean arguments:",
                                        "Scenario condition assumptions:", "Scenario value assumptions:"])
def test_no_reference_preflight_still_refuses_supplied_scene_declarations(tmp_path, declaration):
    index, candidate, _, tools, _ = _inputs(tmp_path)
    candidate = candidate.model_copy(update={"analysis_scope": candidate.analysis_scope + " " + declaration + " {}"})
    with pytest.raises(WitnessPreflightError, match="supplied scenario declarations"):
        inspect_initial_request(capture_initial_request(index, candidate, tools), index, candidate,
                                scenario_empty=True)


def test_no_reference_preflight_still_refuses_nonempty_original_scene(tmp_path):
    index, candidate, _, tools, _ = _inputs(tmp_path)
    candidate = candidate.model_copy(update={"entry_boolean_arguments": {"engaged": True}})
    with pytest.raises(WitnessPreflightError, match="B candidate contains"):
        inspect_initial_request(capture_initial_request(index, candidate, tools), index, candidate,
                                scenario_empty=True)


def test_advance_tool_description_and_unexecuted_reply_do_not_choose_input_profile(tmp_path):
    index, candidate, context, tools, _ = _inputs(tmp_path)
    request = capture_initial_request(index, candidate, tools)
    witness = next(t["function"] for t in request.tools if t["function"]["name"] == "run_bounded_execution_witness")
    assert "local directory" not in witness["description"]
    assert "metacharacters" not in witness["description"]
    registry = ToolRegistry(tools, max_output_bytes=100000)
    observation = registry.invoke(ModelToolCall(call_id="prepare", name="run_bounded_execution_witness",
        arguments={"constructor_parameters": {}, "precondition_files": {}}),
        allowed=("run_bounded_execution_witness",), scope=ToolExecutionScope(
            admitted_paths=frozenset({candidate.path}), candidate_path=candidate.path,
            subject=candidate_subject(index, candidate), max_observation_tokens=8192))
    assert observation.metadata["witness_attempted"] is False
    assert "input_profile" not in observation.content
    assert "local directory" not in observation.content
    assert "metacharacters" not in observation.content
    assert not context.runtime_root.exists()
