"""Inspect actual initial requests without running tools, transports or workers."""
from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import json
import re
import textwrap
from typing import Any, Iterable, Sequence

from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.domain.chat import ChatMessage
from cv_agent.domain.types import Candidate
from cv_agent.harness import AgentSystemVersion, FULL_SYSTEM_HARNESS
from cv_agent.retrieval import RepositoryIndex
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.tools.registry import AgentTool, ToolRegistry
from cv_agent.tools.validation.witness_scenario import WitnessScenarioHypothesis


class WitnessPreflightError(ValueError):
    """The rendered request differs from its declared source/input boundary."""


_SUPPLIED_SCENARIO_DECLARATIONS = (
    "Declared externally supplied entry parameters:", "Scenario entry boolean arguments:",
    "Scenario condition assumptions:", "Scenario value assumptions:",
)


class _RequestCaptured(Exception):
    pass


class _CaptureOnlyTools(ToolRegistry):
    def invoke(self, *args, **kwargs):
        raise AssertionError("initial-request preflight cannot execute a tool")


@dataclass(frozen=True)
class CapturedInitialRequest:
    messages: tuple[ChatMessage, ...]
    tools: tuple[dict[str, Any], ...]


def _digest(value: Any) -> str:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(serialized.encode()).hexdigest()


def capture_initial_request(
    index: RepositoryIndex, candidate: Candidate, registered_tools: Iterable[AgentTool], *,
    system: AgentSystemVersion = AgentSystemVersion.E1_LOCAL_SINGLE,
) -> CapturedInitialRequest:
    """Render through the ordinary pipeline and abort its first scripted request."""
    def capture(messages, definitions):
        raise _RequestCaptured()
    spec = FULL_SYSTEM_HARNESS.system_spec(system)
    roles = set(spec.expert_order) | ({"planner"} if spec.planner_enabled else set())
    models = {role: ScriptedChatModel((capture,)) for role in roles}
    registry = _CaptureOnlyTools(tuple(registered_tools),
                                max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes)
    pipeline = AgenticPipeline(index=index, system=system, models=models, tools=registry)
    try:
        pipeline.run(candidate)
    except _RequestCaptured:
        pass
    requests = [request for model in models.values() for request in model.requests]
    if len(requests) != 1:
        raise WitnessPreflightError("preflight must capture exactly one initial scripted request")
    messages, definitions = requests[0]
    return CapturedInitialRequest(messages, definitions)


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _scenario_markers(scenario: WitnessScenarioHypothesis) -> tuple[str, ...]:
    markers = set(scenario.entry_boolean_arguments)
    for expression in scenario.entry_condition_assumptions:
        markers.add(expression)
        tree = ast.parse(expression, mode="eval")
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                markers.add(node.func.id)
            elif isinstance(node, ast.Attribute):
                markers.add(ast.unparse(node))
    return tuple(sorted(markers))


def _occurrences(text: str, marker: str) -> int:
    if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", marker):
        return len(re.findall(r"(?<![A-Za-z_0-9])" + re.escape(marker) + r"(?![A-Za-z_0-9])", text))
    return text.count(marker)


def _entry_marker_matches(text: str, marker: str) -> bool:
    tree = ast.parse(textwrap.dedent(text))
    definitions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if len(definitions) != 1:
        return False
    header = "".join(text.splitlines(keepends=True)[definitions[0].lineno - 1:])
    return bool(marker.strip()) and header.lstrip().startswith(marker.lstrip())


def inspect_initial_request(
    request: CapturedInitialRequest, index: RepositoryIndex, candidate: Candidate, *,
    scenario: WitnessScenarioHypothesis | None = None, scenario_empty: bool,
    private_markers: Sequence[str] = (),
) -> dict[str, Any]:
    """Allow only verified source text to carry B's undeclared scenario markers."""
    masked_messages = []
    source_records = []
    rendered_contexts = []
    for message in request.messages:
        content = message.content or ""
        stripped = content.lstrip()
        if message.role == "user" and stripped.startswith("{"):
            try:
                context, endpoint = json.JSONDecoder().raw_decode(stripped)
            except json.JSONDecodeError:
                context = None
            if isinstance(context, dict) and "retrieved_code" in context:
                descriptor = context.get("candidate", {})
                identity = {"candidate_id": candidate.candidate_id, "repository_id": candidate.repository_id,
                            "path": candidate.path, "line": candidate.line, "property_id": candidate.property_id}
                if any(descriptor.get(name) != value for name, value in identity.items()):
                    raise WitnessPreflightError("rendered candidate identity differs from the declared input")
                for source in context["retrieved_code"]:
                    document = index.document(source.get("path", ""))
                    text = source.get("text")
                    if (document is None or type(text) is not str or not text
                            or not document.text.startswith(text)
                            or document.repository_id != candidate.repository_id):
                        raise WitnessPreflightError("rendered source is not a bound indexed source prefix")
                    source_records.append({"path": source["path"], "characters": len(text),
                                           "text_sha256": hashlib.sha256(text.encode()).hexdigest()})
                    source["text"] = "<verified_repository_source>"
                scope = context.get("candidate", {}).get("analysis_scope", "")
                if "Declared entry code marker: " in scope:
                    prefix, remainder = scope.split("Declared entry code marker: ", 1)
                    marker, separator, tail = remainder.partition(". ")
                    entry = index.document(candidate.path)
                    if not separator or entry is None or not _entry_marker_matches(entry.text, marker):
                        raise WitnessPreflightError("declared entry marker is not copied from bound candidate source")
                    context["candidate"]["analysis_scope"] = prefix + "Declared entry code marker: <verified_entry_source>. " + tail
                rendered_contexts.append(context)
                content = json.dumps(context, sort_keys=True) + stripped[endpoint:]
        masked_messages.append({"role": message.role, "content": content})
    if len(rendered_contexts) != 1 or not source_records:
        raise WitnessPreflightError("preflight requires exactly one rendered initial source context")
    if scenario_empty and (candidate.input_parameters or candidate.entry_boolean_arguments
                           or candidate.entry_condition_assumptions or candidate.entry_value_assumptions):
        raise WitnessPreflightError("B candidate contains supplied scenario fields")
    outside_source = [*list(_strings(masked_messages)), *list(_strings(request.tools))]
    declarations = [marker for marker in _SUPPLIED_SCENARIO_DECLARATIONS
                    if any(marker in text for text in outside_source)]
    if scenario_empty and declarations:
        raise WitnessPreflightError("supplied scenario declarations outside source: " + ", ".join(declarations))
    markers = _scenario_markers(scenario) if scenario is not None else ()
    outside_counts = {marker: sum(_occurrences(text, marker) for text in outside_source) for marker in markers}
    leaked = [marker for marker in markers if outside_counts[marker]]
    if scenario_empty and leaked:
        raise WitnessPreflightError("undeclared scenario markers outside source: " + ", ".join(leaked))
    private = [marker for marker in private_markers if marker and len(marker) >= 4
               and any(_occurrences(text, marker) for text in outside_source)]
    if private:
        raise WitnessPreflightError("private case, commit or interpreter marker reaches the model: " + ", ".join(private))
    return {
        "passed": True, "live_model_requests": 0, "tool_calls": 0, "worker_executions": 0,
        "scenario_reference_provided": scenario is not None,
        "source_records": source_records, "outside_source_marker_counts": outside_counts,
        "tool_definitions_sha256": _digest(request.tools),
        "masked_context_sha256": _digest(rendered_contexts[0]),
        "initial_request_sha256": _digest({"messages": [m.model_dump(mode="json") for m in request.messages],
                                           "tools": request.tools}),
        "request": {"messages": [m.model_dump(mode="json") for m in request.messages], "tools": request.tools},
    }


def preflight_cells(cells, config) -> dict[str, Any]:
    origins = tuple(config.origins)
    if (not origins or len(set(origins)) != len(origins)
            or set(origins) - {"dataset_provided", "model_proposed"}):
        raise WitnessPreflightError("preflight requires declared unique supported scenario origins")
    if "dataset_provided" in origins and config.dataset_scenario is None:
        raise WitnessPreflightError("dataset condition requires its classified reference scenario")
    records = []
    for cell in cells:
        private = [cell.evaluation_case_id, str(cell.context.checkout_root)]
        if cell.context.python_executable is not None:
            private.append(str(cell.context.python_executable))
        for key in ("case_id", "pair_id", "entry_id", "commit", "configured_commit", "checkout"):
            value = cell.identity.get(key)
            if isinstance(value, str):
                private.append(value)
                if key in {"commit", "configured_commit"} and len(value) >= 8:
                    private.append(value[:8])
        request = capture_initial_request(cell.index, cell.candidate, cell.registered_tools)
        inspected = inspect_initial_request(request, cell.index, cell.candidate,
            scenario=config.dataset_scenario, scenario_empty=cell.scenario_origin == "model_proposed",
            private_markers=private)
        records.append({"evaluation_case_id": cell.evaluation_case_id,
                        "scenario_origin": cell.scenario_origin, "query": cell.candidate.query, **inspected})
    if (len(records) != 2 * len(origins)
            or {item["scenario_origin"] for item in records} != set(origins)
            or len({item["tool_definitions_sha256"] for item in records}) != 1):
        raise WitnessPreflightError("declared cells must share identical allowed tool definitions")
    controls = {}
    for origin in origins:
        selected = [item for item in records if item["scenario_origin"] == origin]
        selected_cells = [cell for cell in cells if cell.scenario_origin == origin]
        if len(selected) != 2:
            raise WitnessPreflightError("each condition requires two snapshots")
        for left, right in zip(selected_cells, selected_cells[1:]):
            if (left.candidate.query != right.candidate.query
                    or left.candidate.analysis_scope != right.candidate.analysis_scope
                    or left.candidate.input_parameters != right.candidate.input_parameters
                    or left.candidate.entry_boolean_arguments != right.candidate.entry_boolean_arguments
                    or left.candidate.entry_condition_assumptions != right.candidate.entry_condition_assumptions
                    or left.candidate.entry_value_assumptions != right.candidate.entry_value_assumptions
                    or left.context.runtime_root != right.context.runtime_root
                    or left.context.resource_profile != right.context.resource_profile
                    or left.context.read_grants != right.context.read_grants
                    or left.context.import_root != right.context.import_root):
                raise WitnessPreflightError("paired snapshots differ in supplied input or runtime policy")
        controls[origin] = {"same_supplied_inputs": True,
                            "source_characters": [sum(s["characters"] for s in item["source_records"]) for item in selected],
                            "same_initial_request": selected[0]["initial_request_sha256"] == selected[1]["initial_request_sha256"]}
    return {"passed": True, "live_model_requests": 0, "tool_calls": 0, "worker_executions": 0,
            "origins": origins, "cells": records, "controls": controls,
            "note": "Source code may differ by snapshot. A/B metadata can consume different source context; "
                    "recorded coverage makes that visible. Autonomous B hypotheses are not required to be identical."}
