"""Observe declared conditions on one source-bound candidate invocation.

Expressions are parsed as data, never evaluated. Quote spelling and redundant
parentheses normalize through the AST; an enclosing unary ``not`` only inverts
an observed arm. Actual branch edges must leave the matched test for its body
or alternative. Unsupported code layouts keep a concrete obligation gap.
"""

from __future__ import annotations

import _thread
import ast
import dis
import hashlib
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import CodeType, FrameType, MethodWrapperType, WrapperDescriptorType
from typing import Any, Callable

from cv_agent.runtime.witness_entry import (
    compiler_constants as _compiler_constants, identical_code as _identical_code,
)


_TOOL_ID = 4
_TOOL_NAME = "cv_agent.bounded-witness-conditions"


def _signature(node: ast.AST) -> str:
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def _span(node: ast.AST) -> tuple[tuple[int, int], tuple[int, int]]:
    return ((node.lineno, node.col_offset), (node.end_lineno, node.end_col_offset))


def _position(instruction: dis.Instruction):
    position = instruction.positions
    if any(value is None for value in (position.lineno, position.end_lineno,
                                       position.col_offset, position.end_col_offset)):
        return None
    return ((position.lineno, position.col_offset),
            (position.end_lineno, position.end_col_offset))


def _within(position, span) -> bool:
    return position is not None and span[0] <= position[0] and position[1] <= span[1]


def _codes(code: CodeType):
    yield code
    for value in code.co_consts:
        if isinstance(value, CodeType):
            yield from _codes(value)


def _code_key(code: CodeType) -> tuple[str, str, int]:
    return code.co_filename, code.co_qualname, code.co_firstlineno


@dataclass
class _Occurrence:
    expression: str
    expected: bool
    module: str
    file: str
    sha256: str
    node: ast.If | ast.IfExp
    inverted: bool
    values: set[bool] = field(default_factory=set)
    count: int = 0
    owner_keys: set[tuple[str, str, int]] = field(default_factory=set)
    pending: bool = False
    incomplete: bool = False
    observed_edges: dict[tuple[str, int, int, bool], int] = field(default_factory=dict)

    def observation(self) -> dict[str, Any]:
        return {"expression": self.expression, "expected": self.expected,
                "module": self.module, "file": self.file, "sha256": self.sha256,
                "line": self.node.lineno, "column": self.node.col_offset,
                "node_kind": type(self.node).__name__, "inverted": self.inverted,
                "actual_values": sorted(self.values), "execution_count": self.count,
                "branch_edges": [{"qualname": key[0], "instruction_offset": key[1],
                                  "destination_offset": key[2], "actual": key[3],
                                  "execution_count": count}
                                 for key, count in self.observed_edges.items()]}


@dataclass
class _CodePlan:
    template: CodeType
    edges: dict[tuple[int, int], list[tuple[_Occurrence, bool]]] = field(default_factory=dict)
    occurrences: list[_Occurrence] = field(default_factory=list)


def _branch_edges(code: CodeType, occurrence: _Occurrence):
    """Map only observed jumps that exit this AST test into a definite arm."""
    node = occurrence.node
    test_span = _span(node.test)
    body = [node.body] if isinstance(node, ast.IfExp) else node.body
    alternative = [node.orelse] if isinstance(node, ast.IfExp) else node.orelse
    body_spans = [_span(item) for item in body]
    alternative_spans = [_span(item) for item in alternative]
    instructions = list(dis.get_instructions(code))
    by_offset = {instruction.offset: instruction for instruction in instructions}
    edges: dict[tuple[int, int], bool] = {}
    conditional_seen = False
    ambiguous = False
    for index, instruction in enumerate(instructions):
        if ("IF" not in instruction.opname or "JUMP" not in instruction.opname
                or not _within(_position(instruction), test_span)):
            continue
        conditional_seen = True
        if not isinstance(instruction.argval, int) or index + 1 >= len(instructions):
            ambiguous = True
            continue
        destinations = (instruction.argval, instructions[index + 1].offset)
        for destination in destinations:
            target = by_offset.get(destination)
            position = _position(target) if target is not None else None
            if position is None:
                ambiguous = True
                continue
            if _within(position, test_span):
                # Short-circuit continuation is not the whole test's result.
                continue
            in_body = any(_within(position, span) for span in body_spans)
            in_alternative = any(_within(position, span) for span in alternative_spans)
            if in_body and not in_alternative:
                truth = True
            elif in_alternative and not in_body:
                truth = False
            elif not alternative and not in_body:
                truth = False
            else:
                ambiguous = True
                continue
            edges[instruction.offset, destination] = truth != occurrence.inverted
    # If an arm was optimized away, both destinations can share a later source
    # position. Such a map cannot establish which truth value was selected.
    if conditional_seen and set(edges.values()) != {False, True}:
        ambiguous = True
    return edges, conditional_seen, ambiguous


class BranchAssumptionObserver:
    """Own one monitoring tool and bind branch observations to entry ancestry.

    Construct before target imports to bind source contents. Install after the
    candidate method is available, immediately before invocation. ``on_entry``
    receives the actual candidate frame for independent raw-dictionary value
    checks. ``report`` is safe at a command audit event before worker exit.
    """

    def __init__(self, manifest: Any, *, monitoring_tool_id: int = _TOOL_ID):
        self.tool_id = monitoring_tool_id
        self._monitor = getattr(sys, "monitoring", None)
        self._gaps: list[str] = []
        self._conditions = dict(manifest.subject.entry_condition_assumptions)
        self._occurrences: list[_Occurrence] = []
        self._plans: dict[tuple[str, str, int], _CodePlan] = {}
        self._ambiguous_keys: set[tuple[str, str, int]] = set()
        self._paths: set[str] = set()
        self._runtime_plans: dict[CodeType, _CodePlan | None] = {}
        self._local_codes: set[CodeType] = set()
        self._local_masks: dict[CodeType, int] = {}
        self._installed = False
        self._configuring = False
        self._mutators = ({getattr(self._monitor, name) for name in (
            "set_events", "set_local_events", "register_callback", "use_tool_id",
            "free_tool_id", "restart_events")}
            if self._monitor is not None else set())
        self._entry_code: CodeType | None = None
        self._candidate_frame: FrameType | None = None
        self._candidate_thread: int | None = None
        self._entry_thread: int | None = None
        self._on_entry: Callable[[FrameType], None] | None = None
        self._build(manifest)

    def _gap(self, gap: str) -> None:
        if gap not in self._gaps:
            self._gaps.append(gap)

    def _build(self, manifest: Any) -> None:
        signatures: dict[str, str] = {}
        for expression, expected in self._conditions.items():
            if type(expected) is not bool:
                self._gap(f"condition_expected_boolean_required:{expression}")
                continue
            try:
                signatures[expression] = _signature(ast.parse(expression, mode="eval").body)
            except (SyntaxError, ValueError):
                self._gap(f"condition_expression_invalid:{expression}")
        root = Path(manifest.checkout_root).resolve()
        for binding in manifest.source_modules:
            try:
                path = (root / binding.relative_path).resolve(strict=True)
                path.relative_to(root)
                raw = path.read_bytes()
            except (OSError, ValueError):
                self._gap(f"condition_source_unavailable:{binding.module_name}")
                continue
            if hashlib.sha256(raw).hexdigest() != binding.sha256:
                self._gap(f"condition_source_mismatch:{binding.module_name}")
                continue
            filename = str(path)
            self._paths.add(filename)
            try:
                tree = ast.parse(raw, filename=filename)
            except (SyntaxError, ValueError):
                self._gap(f"condition_source_parse_failed:{binding.module_name}")
                continue
            matching_nodes = []
            for node in ast.walk(tree):
                if not isinstance(node, (ast.If, ast.IfExp)):
                    continue
                for expression, signature in signatures.items():
                    test = node.test
                    inverted = False
                    while (_signature(test) != signature and isinstance(test, ast.UnaryOp)
                           and isinstance(test.op, ast.Not)):
                        test = test.operand
                        inverted = not inverted
                    if _signature(test) == signature:
                        matching_nodes.append((node, expression, inverted))
            # Parse every admitted source, but compile only the entry source and
            # files with matching conditions. Unrelated duplicate comprehensions
            # do not create global ambiguity or instrument unrelated modules.
            entry_path = getattr(manifest, "entry_relative_path", binding.relative_path)
            if not matching_nodes and binding.relative_path != entry_path:
                self._paths.discard(filename)
                continue
            try:
                compiled = compile(raw, filename, "exec", dont_inherit=True, optimize=0)
            except (SyntaxError, ValueError):
                self._gap(f"condition_source_parse_failed:{binding.module_name}")
                continue
            source_codes = tuple(_codes(compiled))
            for code in source_codes:
                key = _code_key(code)
                if key in self._plans:
                    self._ambiguous_keys.add(key)
                    continue
                self._plans[key] = _CodePlan(template=code)
            for node, expression, inverted in matching_nodes:
                occurrence = _Occurrence(expression=expression,
                                         expected=self._conditions[expression],
                                         module=binding.module_name, file=filename,
                                         sha256=binding.sha256, node=node,
                                         inverted=inverted)
                self._occurrences.append(occurrence)
                for code in source_codes:
                    edges, seen, ambiguous = _branch_edges(code, occurrence)
                    if not seen:
                        continue
                    key = _code_key(code)
                    occurrence.owner_keys.add(key)
                    plan = self._plans[key]
                    plan.occurrences.append(occurrence)
                    # An ambiguous destination is never treated as an arm.
                    # Keep known edges only when the entire map is supported.
                    if ambiguous or not edges:
                        continue
                    for edge, value in edges.items():
                        plan.edges.setdefault(edge, []).append((occurrence, value))
            # Compilers can remove a constant test entirely. Mark these when
            # relevant candidate code executes, rather than guessing its truth.
            for occurrence in self._occurrences:
                if occurrence.file != filename or occurrence.owner_keys:
                    continue
                owners = [code for code in source_codes
                          if any(_within(_position(instruction), _span(occurrence.node))
                                 for instruction in dis.get_instructions(code))]
                for code in owners:
                    key = _code_key(code)
                    occurrence.owner_keys.add(key)
                    self._plans[key].occurrences.append(occurrence)
        for expression in signatures:
            if not any(item.expression == expression for item in self._occurrences):
                self._gap(f"condition_ast_not_found:{expression}")

    def install(self, expected_code: CodeType,
                on_entry: Callable[[FrameType], None] | None = None) -> None:
        if self._installed:
            raise RuntimeError("branch observer is already installed")
        monitor = self._monitor
        if monitor is None or not all(hasattr(monitor.events, event)
                                      for event in ("PY_START", "PY_RETURN", "PY_UNWIND", "LINE", "BRANCH")):
            self._gap("condition_monitor_unavailable")
            return
        if monitor.get_tool(self.tool_id) is not None:
            self._gap(f"condition_monitor_tool_id_occupied:{self.tool_id}")
            return
        plan = self._plans.get(_code_key(expected_code))
        if (_code_key(expected_code) in self._ambiguous_keys or plan is None
                or not _identical_code(expected_code, plan.template)):
            self._gap("condition_entry_code_mismatch")
            return
        self._entry_code = expected_code
        self._entry_thread = _thread.get_ident()
        self._on_entry = on_entry
        self._configuring = True
        try:
            monitor.use_tool_id(self.tool_id, _TOOL_NAME)
            self._installed = True
            monitor.register_callback(self.tool_id, monitor.events.PY_START, self._start)
            monitor.register_callback(self.tool_id, monitor.events.PY_RETURN, self._return)
            monitor.register_callback(self.tool_id, monitor.events.PY_UNWIND, self._return)
            monitor.register_callback(self.tool_id, monitor.events.LINE, self._line)
            monitor.register_callback(self.tool_id, monitor.events.BRANCH, self._branch)
            monitor.register_callback(self.tool_id, monitor.events.CALL, self._call)
            # The cheap start callback discovers lazily imported helpers. Only
            # SHA-bound runtime code receives local line/branch instrumentation.
            monitor.set_events(self.tool_id, self._global_mask())
            monitor.set_local_events(self.tool_id, expected_code,
                                     monitor.events.PY_RETURN)
            self._local_codes.add(expected_code)
            self._local_masks[expected_code] = monitor.events.PY_RETURN
        except BaseException as error:
            self._gap(f"condition_monitor_install_failed:{type(error).__name__}")
            self.close()
        finally:
            self._configuring = False

    def _global_mask(self) -> int:
        return (self._monitor.events.PY_START | self._monitor.events.PY_UNWIND
                | self._monitor.events.CALL)

    def audit_event(self, event: str, args: tuple[Any, ...]) -> None:
        """Receive the worker audit hook's monitoring-registration events."""
        if (self._installed and not self._configuring
                and event == "sys.monitoring.register_callback"):
            self._gap("condition_monitor_callback_changed")

    def _call(self, code: CodeType, instruction_offset: int,
              callable: Any, first_argument: Any) -> None:
        if self._configuring:
            return
        # Identity comparisons never dispatch target equality or descriptors.
        target = callable
        if type(target) is WrapperDescriptorType and target.__name__ == "__call__":
            target = first_argument
        for _ in range(32):
            if any(target is mutator for mutator in self._mutators):
                self._gap("condition_monitor_configuration_call")
                return
            if type(target) is not MethodWrapperType:
                return
            target = target.__self__

    def _candidate_ancestor(self, frame: FrameType | None) -> bool:
        if (_thread.get_ident() != self._candidate_thread or self._candidate_frame is None):
            return False
        while frame is not None:
            if frame is self._candidate_frame:
                return True
            frame = frame.f_back
        return False

    def _plan_for(self, code: CodeType) -> _CodePlan | None:
        if not _compiler_constants(code):
            self._gap(f"condition_runtime_code_mismatch:{code.co_qualname}")
            return None
        if code in self._runtime_plans:
            return self._runtime_plans[code]
        plan = self._plans.get(_code_key(code))
        if (_code_key(code) in self._ambiguous_keys or plan is None
                or not _identical_code(code, plan.template)):
            self._runtime_plans[code] = None
            if code.co_filename in self._paths:
                self._gap(f"condition_runtime_code_mismatch:{code.co_qualname}")
            return None
        self._runtime_plans[code] = plan
        return plan

    def _start(self, code: CodeType, instruction_offset: int) -> None:
        if code.co_filename not in self._paths:
            return
        frame = sys._getframe(1)
        if code is self._entry_code and _thread.get_ident() == self._entry_thread:
            if self._candidate_frame is None:
                self._candidate_frame = frame
                self._candidate_thread = _thread.get_ident()
                if self._on_entry is not None:
                    try:
                        self._on_entry(frame)
                    except BaseException as error:
                        self._gap(f"condition_entry_callback_failed:{type(error).__name__}")
        if not self._candidate_ancestor(frame):
            return
        plan = self._plan_for(code)
        if plan is None or not plan.occurrences:
            return
        events = self._monitor.events.LINE | self._monitor.events.BRANCH
        if code is self._entry_code:
            events |= self._monitor.events.PY_RETURN
        self._configuring = True
        try:
            self._monitor.set_local_events(self.tool_id, code, events)
        finally:
            self._configuring = False
        self._local_codes.add(code)
        self._local_masks[code] = events

    def _return(self, code: CodeType, instruction_offset: int, value: Any) -> None:
        if code is self._entry_code and sys._getframe(1) is self._candidate_frame:
            self._candidate_frame = None
            self._candidate_thread = None

    def _line(self, code: CodeType, line_number: int) -> None:
        if not self._candidate_ancestor(sys._getframe(1)):
            return
        plan = self._runtime_plans.get(code)
        if plan is None:
            return
        mapped = {id(occurrence) for edges in plan.edges.values() for occurrence, _ in edges}
        for occurrence in plan.occurrences:
            if line_number != occurrence.node.test.lineno:
                continue
            if occurrence.pending:
                occurrence.incomplete = True
            occurrence.pending = True
            if id(occurrence) not in mapped:
                self._gap(f"condition_bytecode_unsupported:{occurrence.expression}")

    def _branch(self, code: CodeType, instruction_offset: int, destination_offset: int) -> None:
        if not self._candidate_ancestor(sys._getframe(1)):
            return
        plan = self._runtime_plans.get(code)
        if plan is None:
            return
        for occurrence, value in plan.edges.get((instruction_offset, destination_offset), ()):
            occurrence.pending = False
            occurrence.values.add(value)
            occurrence.count += 1
            edge = code.co_qualname, instruction_offset, destination_offset, value
            occurrence.observed_edges[edge] = occurrence.observed_edges.get(edge, 0) + 1
            if value is not occurrence.expected:
                self._gap(f"entry_condition_assumption_mismatch:{occurrence.expression}")

    def report(self) -> dict[str, Any]:
        gaps = list(self._gaps)
        if self._installed and self._monitor.get_tool(self.tool_id) != _TOOL_NAME:
            gaps.append("condition_monitor_ownership_lost")
        elif self._installed:
            if self._monitor.get_events(self.tool_id) != self._global_mask():
                gaps.append("condition_monitor_global_events_changed")
            for code, expected_mask in self._local_masks.items():
                if self._monitor.get_local_events(self.tool_id, code) != expected_mask:
                    gaps.append(f"condition_monitor_local_events_changed:{code.co_qualname}")
        for expression in self._conditions:
            observed = [item for item in self._occurrences if item.expression == expression and item.count]
            if not observed:
                gaps.append(f"entry_condition_assumption_unverified:{expression}")
        for occurrence in self._occurrences:
            if occurrence.pending or occurrence.incomplete:
                gaps.append(f"condition_occurrence_unverified:{occurrence.expression}:"
                            f"{occurrence.module}:{occurrence.node.lineno}")
        return {"tool_id": self.tool_id, "expression_match": "canonical_ast_with_whole_test_not",
                "gaps": list(dict.fromkeys(gaps)),
                "observations": [item.observation() for item in self._occurrences if item.count]}

    def close(self) -> None:
        if not self._installed:
            return
        monitor = self._monitor
        self._candidate_frame = None
        self._candidate_thread = None
        self._configuring = True
        try:
            if monitor.get_tool(self.tool_id) == _TOOL_NAME:
                monitor.set_events(self.tool_id, 0)
                for code in self._local_codes:
                    monitor.set_local_events(self.tool_id, code, 0)
                for event in (monitor.events.PY_START, monitor.events.PY_RETURN,
                              monitor.events.PY_UNWIND, monitor.events.LINE,
                              monitor.events.BRANCH, monitor.events.CALL):
                    monitor.register_callback(self.tool_id, event, None)
                monitor.free_tool_id(self.tool_id)
        finally:
            self._installed = False
            self._configuring = False
