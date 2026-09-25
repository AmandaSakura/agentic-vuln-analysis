"""Bounded intradocument and admitted call-graph may-flow analysis."""

from __future__ import annotations

import ast
import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, cast

from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.domain.evidence import ToolObservation, ValidationStatus
from cv_agent.tools.analysis.parameters import ast_parameters
from cv_agent.tools.analysis.python_flow import CallBinding, function_node, parameter_names, python_document_flow
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import CodeDocument, FrozenModel
from cv_agent.tools.validation.models import TraceDataflowInput
from cv_agent.tools.validation.patterns import SANITIZER_RULES, SINK_RULES, SOURCE_RULES
from cv_agent.tools.validation.scope import _admitted_document, _json_content


ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:final\s+)?(?:[\w.$<>\[\],?]+\s+)+)?"
    r"(?P<name>[A-Za-z_$][\w$]*)"
    r"(?:\s*:[^=]+)?\s*(?P<operator>:=|=(?!=))\s*"
    r"(?P<value>.+?)\s*;?\s*(?://.*)?$"
)


COLLECTION_PUT_RE = re.compile(
    r"\b(?P<name>[A-Za-z_$][\w$]*)\.put\s*\((?P<arguments>[^;]*)\)"
)


CALL_RE = re.compile(
    r"(?P<name>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*"
    r"\((?P<arguments>[^()]*)\)"
)


@dataclass(frozen=True)
class _DocumentFlow:
    path: str
    sources: tuple[dict[str, Any], ...]
    sinks: tuple[dict[str, Any], ...]
    sanitizers: tuple[dict[str, Any], ...]
    tainted_variables: tuple[str, ...]
    tainted_calls: tuple[str, ...]
    call_bindings: tuple[CallBinding, ...] = ()


def _parameters(document: CodeDocument) -> tuple[str, ...]:
    node = function_node(document)
    if node is not None:
        return parameter_names(node)
    parsed_parameters = ast_parameters(document)
    if parsed_parameters is not None:
        return parsed_parameters
    header = document.text.split("{", 1)[0]
    match = re.search(r"\((?P<parameters>[^)]*)\)", header)
    if not match:
        return ()
    parameters: list[str] = []
    for raw in match.group("parameters").split(","):
        raw = raw.strip()
        if not raw:
            continue
        name_match = re.search(
            r"([A-Za-z_$][\w$]*)\s*$",
            raw.split("=", maxsplit=1)[0].split(":", maxsplit=1)[0].strip(),
        )
        if name_match and name_match.group(1) not in {"self", "cls"}:
            parameters.append(name_match.group(1))
    return tuple(parameters)


def _contains_identifier(text: str, names: Iterable[str]) -> bool:
    return any(re.search(rf"\b{re.escape(name)}\b", text) for name in names)


def _value_is_tainted(
    value: str,
    *,
    tainted: set[str],
    tainted_containers: set[str],
    source_hits: Iterable[str] = (),
) -> bool:
    return (
        bool(tuple(source_hits))
        or _contains_identifier(value, tainted)
        or _contains_identifier(value, tainted_containers)
    )


def _document_flow(
    document: CodeDocument,
    *,
    initial_tainted: Iterable[str] = (),
    sink_category: str = "command-execution",
) -> _DocumentFlow:
    parsed = python_document_flow(
        document, initial_tainted=initial_tainted, sink_category=sink_category,
        source_rules=SOURCE_RULES, sink_rules=SINK_RULES, sanitizer_rules=SANITIZER_RULES,
    )
    if parsed is not None:
        return _DocumentFlow(**parsed)
    tainted = set(initial_tainted)
    tainted_containers: set[str] = set()
    sources: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    sanitizers: list[dict[str, Any]] = []
    tainted_calls: set[str] = set()
    call_bindings: list[CallBinding] = []

    for line_number, line in enumerate(document.text.splitlines(), start=1):
        code_line = line.split("//", maxsplit=1)[0]
        source_hits = [
            rule.category for rule in SOURCE_RULES if rule.pattern.search(code_line)
        ]
        sanitizer_hits = [
            rule.category for rule in SANITIZER_RULES if rule.pattern.search(code_line)
            and (
                (rule.category == "shell-escaping" and sink_category == "command-execution")
                or (rule.category == "numeric-validation" and sink_category in {"command-execution", "code-execution", "sql"})
            )
        ]
        assignment = ASSIGNMENT_RE.match(code_line)
        if source_hits:
            sources.append(
                {
                    "line": line_number,
                    "categories": source_hits,
                    "text": line.strip(),
                }
            )
        if sanitizer_hits:
            sanitizers.append(
                {
                    "line": line_number,
                    "categories": sanitizer_hits,
                    "text": line.strip(),
                }
            )
        if assignment:
            name = assignment.group("name")
            value = assignment.group("value")
            for put in COLLECTION_PUT_RE.finditer(code_line):
                if _value_is_tainted(
                    put.group("arguments"),
                    tainted=tainted,
                    tainted_containers=tainted_containers,
                    source_hits=source_hits,
                ):
                    tainted_containers.add(put.group("name"))
            if sanitizer_hits:
                tainted.discard(name)
            elif _value_is_tainted(
                value,
                tainted=tainted,
                tainted_containers=tainted_containers,
                source_hits=source_hits,
            ):
                tainted.add(name)
            else:
                tainted.discard(name)
        else:
            for put in COLLECTION_PUT_RE.finditer(code_line):
                if _value_is_tainted(
                    put.group("arguments"),
                    tainted=tainted,
                    tainted_containers=tainted_containers,
                    source_hits=source_hits,
                ):
                    tainted_containers.add(put.group("name"))

        line_is_tainted = (
            bool(source_hits)
            or _contains_identifier(code_line, tainted)
            or _contains_identifier(code_line, tainted_containers)
        )
        for rule in SINK_RULES:
            if rule.category != sink_category:
                continue
            match = rule.pattern.search(code_line)
            if match:
                sinks.append(
                    {
                        "category": rule.category,
                        "line": line_number,
                        "match": match.group(0),
                        "tainted": line_is_tainted and not sanitizer_hits,
                        "text": line.strip(),
                    }
                )
        if not re.match(r"^\s*(?:def|func|function)\b", code_line):
            for call in CALL_RE.finditer(code_line):
                try:
                    expression = ast.parse("f(" + call.group("arguments") + ")", mode="eval").body
                    arguments = tuple(
                        any(isinstance(node, ast.Name) and node.id in tainted for node in ast.walk(arg))
                        or any(rule.pattern.search(ast.unparse(arg)) for rule in SOURCE_RULES)
                        for arg in expression.args
                    )
                except SyntaxError:
                    # Unsupported argument syntax does not justify tainting every parameter.
                    continue
                if not any(arguments):
                    continue
                tainted_calls.add(call.group("name"))
                call_bindings.append(CallBinding(call.group("name"), arguments))

    return _DocumentFlow(
        path=document.path,
        sources=tuple(sources),
        sinks=tuple(sinks),
        sanitizers=tuple(sanitizers),
        tainted_variables=tuple(sorted(tainted)),
        tainted_calls=tuple(sorted(tainted_calls)),
        call_bindings=tuple(call_bindings),
    )


def _symbol_matches_target(symbol: str, target: CodeDocument) -> bool:
    final = symbol.rsplit(".", 1)[-1]
    return any(
        definition == symbol or definition.rsplit(".", 1)[-1] == final
        for definition in target.defines
    )


def trace_dataflow(
    index: RepositoryIndex,
    arguments: FrozenModel,
    scope: ToolExecutionScope,
) -> ToolObservation:
    value = cast(TraceDataflowInput, arguments)
    if scope.candidate_path is not None and value.source_path != scope.candidate_path:
        return ToolObservation(tool="trace_dataflow", status="blocked",
                               content="Dataflow must start at the candidate entry, not a retrieved helper")
    source, error = _admitted_document(
        index,
        value.source_path,
        scope,
        "trace_dataflow",
    )
    if error is not None:
        return error
    if value.sink_path is not None and value.sink_path not in scope.admitted_paths:
        return ToolObservation(
            tool="trace_dataflow",
            status="blocked",
            content="sink path is outside the retrieved execution scope",
        )

    declared_inputs = scope.subject.input_parameters if scope.subject is not None else ()
    entry_node = function_node(cast(CodeDocument, source))
    if declared_inputs and (entry_node is None or set(declared_inputs) - set(parameter_names(entry_node))):
        return ToolObservation(tool="trace_dataflow", status="error", content="Declared input is not an entry parameter")
    candidate_line = None
    if scope.subject is not None and scope.subject.entry_line is not None:
        span = re.search(r"::.+@(\d+)(?:-\d+)?(?:#\d+-\d+)?$", scope.subject.entry_path)
        candidate_line = scope.subject.entry_line - (int(span.group(1)) - 1 if span else 0)
    categories = (value.sink_category,) if value.sink_category is not None else dict.fromkeys(rule.category for rule in SINK_RULES)
    queue: deque[tuple[str, tuple[str, ...], tuple[dict[str, Any], ...], str]] = deque(
        (cast(CodeDocument, source).path, declared_inputs, (), category)
        for category in categories
    )
    visited: set[tuple[str, tuple[str, ...], str]] = set()
    unresolved_edges: list[dict[str, str]] = []
    confirmed_trace: tuple[dict[str, Any], ...] | None = None
    while queue:
        path, initial_tainted, trace, category = queue.popleft()
        state_key = (path, initial_tainted, category)
        if state_key in visited:
            continue
        visited.add(state_key)
        document = index.document(path)
        if document is None:
            continue
        flow = _document_flow(
            document, initial_tainted=initial_tainted, sink_category=category
        )
        step = {
            "path": path,
            "sanitizers": list(flow.sanitizers),
            "sinks": list(flow.sinks),
            "sources": list(flow.sources),
            "tainted_calls": list(flow.tainted_calls),
            "tainted_variables": list(flow.tainted_variables),
        }
        next_trace = (*trace, step)
        if any(sink["tainted"] for sink in flow.sinks) and (
            value.sink_path is None or path == value.sink_path
        ):
            if confirmed_trace is None:
                confirmed_trace = next_trace
            # A different sink category must not hide a witness at the candidate.
            # Keep the first may-flow if no candidate-line witness is available,
            # including flows whose sink is in an admitted helper.
            if candidate_line is None or (
                path == scope.subject.entry_path
                and any(sink["tainted"] and sink["line"] == candidate_line for sink in flow.sinks)
            ):
                confirmed_trace = next_trace
                break
            continue
        if len(next_trace) > value.max_hops:
            continue
        for neighbor in index.graph_neighbors(path, direction="forward"):
            if neighbor not in scope.admitted_paths:
                continue
            target = index.document(neighbor)
            if target is None:
                continue
            matching_calls = [
                call
                for call in flow.call_bindings
                if _symbol_matches_target(call.name, target)
            ]
            if not matching_calls:
                unresolved_edges.append({"from": path, "to": neighbor})
                continue
            parameters = _parameters(target)
            for call in matching_calls:
                tainted_parameters = {
                    name for name, is_tainted in zip(parameters, call.positional)
                    if is_tainted and name
                }
                tainted_parameters.update(
                    name for name, is_tainted in call.keywords
                    if is_tainted and name in parameters
                )
                if tainted_parameters:
                    queue.append((
                        neighbor, tuple(sorted(tainted_parameters)), next_trace, category
                    ))

    # A bounded may-analysis is useful evidence, not proof of exploitability.
    status = ValidationStatus.UNRESOLVED
    return ToolObservation(
        tool="trace_dataflow",
        status="ok",
        validation_status=status,
        content=_json_content(
            {
                "status": status,
                "flow_status": "MAY_REACH" if confirmed_trace is not None else "NOT_ESTABLISHED",
                "declared_input_parameters": declared_inputs,
                "trace": list(confirmed_trace or ()),
                "unresolved_edges": unresolved_edges,
            }
        ),
        evidence_ids=tuple(
            f"taint:{step['path']}" for step in (confirmed_trace or ())
        ),
    )
