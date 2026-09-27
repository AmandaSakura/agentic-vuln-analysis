"""Bounded Python permission-mode analysis and its candidate-bound tool."""

from __future__ import annotations

import ast
import operator as operator_module
import re
import symtable
import textwrap
from dataclasses import dataclass
from typing import Any, cast

from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.identity import repository_source_digest, local_source_line
from cv_agent.domain.evidence import ToolObservation, ValidationStatus
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import CodeDocument, FrozenModel
from cv_agent.tools.validation.models import PathInput
from cv_agent.tools.validation.scope import _admitted_document, _json_content


CHMOD_MODE_RE = re.compile(
    r"\bos\.chmod\s*\([^,\n]+,\s*(?P<mode>0o[0-7]+|[1-9][0-9]*|0)\s*\)"
)


def _chmod_permission_assessment(document: CodeDocument) -> dict[str, Any] | None:
    modes: list[dict[str, Any]] = []
    for line_number, line in enumerate(document.text.splitlines(), start=1):
        for match in CHMOD_MODE_RE.finditer(line):
            token = match.group("mode")
            mode = int(token, 0)
            modes.append(
                {
                    "line": line_number,
                    "mode": token,
                    "others_write": bool(mode & 0o002),
                    "text": line.strip(),
                }
            )
    if not modes:
        return None
    return {
        "status": ValidationStatus.UNRESOLVED,
        "summary": (
            "Literal os.chmod mode patterns only; reachability, target identity, "
            "later permission changes and exploitability are not established"
        ),
        "modes": modes,
    }


@dataclass(frozen=True)
class _PermissionModeCall:
    line: int
    target: str
    mode: int | None
    mode_text: str | None
    text: str
    # Outermost-first path conditions of the nonconstant branches enclosing this call.
    branch_conditions: tuple[str, ...] = ()





def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _assigned_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for element in target.elts:
            names.update(_assigned_names(element))
        return names
    if isinstance(target, ast.Starred):
        return _assigned_names(target.value)
    return set()


def _literal_mode(node: ast.AST) -> tuple[int | None, str | None]:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value, ast.unparse(node)
    return None, ast.unparse(node)


def _is_os_chmod_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _call_name(node.func) == "os.chmod"


_CONSTANT_COMPARE_FUNCS = {
    ast.Lt: operator_module.lt,
    ast.LtE: operator_module.le,
    ast.Gt: operator_module.gt,
    ast.GtE: operator_module.ge,
    ast.Eq: operator_module.eq,
    ast.NotEq: operator_module.ne,
}


def _constant_compare(operator: ast.AST, left: object, right: object) -> bool | None:
    """Determinate constant comparison, or None when unproven (C2).

    Identity and membership tests are never folded: `is` depends on runtime
    interning and `in` on iteration protocols. A failed evaluation is also
    unproven rather than fatal: real Python would raise there, which the
    analyzer reports through the normal unsupported-expression path.
    """
    func = _CONSTANT_COMPARE_FUNCS.get(type(operator))
    if func is None:
        return None
    try:
        outcome = func(left, right)
    except Exception:
        return None
    return outcome if isinstance(outcome, bool) else None


def _statement_assigns_os(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.Import):
        return any((alias.asname or alias.name.split(".", 1)[0]) == "os" for alias in statement.names)
    if isinstance(statement, ast.ImportFrom):
        return any((alias.asname or alias.name) == "os" for alias in statement.names)
    targets: list[ast.AST] = []
    if isinstance(statement, ast.Assign):
        targets.extend(statement.targets)
    elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
        targets.append(statement.target)
    return any(
        "os" in _assigned_names(target)
        or _call_name(target) == "os.chmod"
        for target in targets
    )


def _os_shadowed_after_statement(statement: ast.stmt, shadowed_os: bool) -> bool:
    if isinstance(statement, ast.Import):
        for alias in statement.names:
            bound_name = alias.asname or alias.name.split(".", 1)[0]
            if bound_name == "os":
                shadowed_os = alias.name != "os"
        return shadowed_os
    if isinstance(statement, ast.ImportFrom):
        if any((alias.asname or alias.name) == "os" for alias in statement.names):
            return True
        return shadowed_os
    if _statement_assigns_os(statement):
        return True
    return shadowed_os


def _collect_permission_mode_calls(document: CodeDocument, *, entry_boolean_arguments: dict[str, bool] | None = None) -> tuple[
    tuple[_PermissionModeCall, ...],
    tuple[str, ...],
    tuple[str, ...],
]:
    """Collect literal chmod calls plus two disjoint gap categories (C2/C3).

    Returns ``(calls, issues, control_notes)``. ``issues`` are fatal coverage
    gaps (unproven values, bindings, os/chmod state or skipped executable
    positions) and block any typed verdict. ``control_notes`` are bounded
    reachability/conditionality caveats whose executable positions were all
    visited; the verdict may still type the collected literal mode sequence
    under those caveats. No caller may decide based on issue text.
    """
    try:
        tree = ast.parse(textwrap.dedent(document.text))
    except SyntaxError as error:
        return (), (f"syntax error: {error}",), ()
    lines = document.text.splitlines()
    issues: list[str] = []
    control_notes: list[str] = []
    calls: list[_PermissionModeCall] = []
    branch_conditions: list[str] = []
    unknown = object()
    lost = object()
    values: dict[str, object] = {}

    def merge_values(*states: dict[str, object]) -> None:
        values.clear()
        for name in set().union(*(state.keys() for state in states)):
            alternatives = [state.get(name, unknown) for state in states]
            first = alternatives[0]
            values[name] = first if all(type(item) is type(first) and item == first for item in alternatives) else lost

    def truth(value: object) -> bool | None:
        if value is unknown or value is lost:
            issues.append("permission condition has unresolved truth protocol or binding")
        return None if value is unknown or value is lost else bool(value)

    def bind(target: ast.AST, value: object) -> None:
        if isinstance(target, ast.Name):
            values[target.id] = lost if value is unknown else value
        else:
            for name in _assigned_names(target):
                values[name] = lost


    def source_line(node: ast.AST) -> str:
        line = getattr(node, "lineno", 0)
        return lines[line - 1].strip() if 1 <= line <= len(lines) else ast.unparse(node)

    def collect_expression(node: ast.AST, shadowed_os: bool) -> object:
        # Evaluate effects and bounded scalar values together: a later read
        # must see assignments, never a stale entry-scenario constant.
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return values.get(node.id, unknown)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            outcome = truth(collect_expression(node.operand, shadowed_os))
            return unknown if outcome is None else not outcome
        if isinstance(node, ast.BoolOp):
            skipped = []
            result = unknown
            for position, operand in enumerate(node.values):
                result = collect_expression(operand, shadowed_os)
                if position == len(node.values) - 1:
                    break
                outcome = truth(result)
                if outcome is None:
                    skipped.append(dict(values))
                    control_notes.append("short-circuit condition is not a literal")
                elif isinstance(node.op, ast.And) != outcome:
                    break
            if skipped:
                merge_values(*skipped, dict(values))
                return unknown
            return result
        if isinstance(node, ast.IfExp):
            outcome = truth(collect_expression(node.test, shadowed_os))
            if outcome is not None:
                return collect_expression(node.body if outcome else node.orelse, shadowed_os)
            before = dict(values)
            left = collect_expression(node.body, shadowed_os)
            left_state = dict(values)
            values.clear()
            values.update(before)
            right = collect_expression(node.orelse, shadowed_os)
            merge_values(left_state, dict(values))
            control_notes.append("conditional expression execution is unresolved")
            return left if type(left) is type(right) and left == right else unknown
        if isinstance(node, ast.Compare):
            current = collect_expression(node.left, shadowed_os)
            skipped = []
            result = True
            for operator, comparator in zip(node.ops, node.comparators):
                following = collect_expression(comparator, shadowed_os)
                if current is unknown or current is lost or following is unknown or following is lost:
                    issues.append("permission comparison has unresolved object protocol or binding")
                outcome = (None if current is unknown or current is lost or following is unknown or following is lost
                           else _constant_compare(operator, current, following))
                if outcome is False:
                    result = False
                    break
                if outcome is None:
                    skipped.append(dict(values))
                    result = unknown
                    control_notes.append("comparison relation is unresolved")
                current = following
            if skipped:
                merge_values(*skipped, dict(values))
            return result
        if isinstance(node, ast.NamedExpr):
            value = collect_expression(node.value, shadowed_os)
            bind(node.target, value)
            return value
        if isinstance(node, ast.Lambda):
            # Definition-time vs call-time separation (C2/C3): default
            # arguments execute immediately at definition and must be
            # visited; only the body is deferred. A call site, if ever
            # visited, is handled as an unknown call when reached.
            for default in node.args.defaults:
                collect_expression(default, shadowed_os)
            for default in node.args.kw_defaults:
                if default is not None:
                    collect_expression(default, shadowed_os)
            return unknown
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            issues.append("unsupported deferred or binding expression")
            return unknown
        if (isinstance(node, ast.Call) and _call_name(node.func) == "os.makedirs"
                and not shadowed_os and len(node.args) == 1
                and isinstance(node.args[0], (ast.Name, ast.Constant))
                and type(node.args[0].value if isinstance(node.args[0], ast.Constant)
                         else values.get(node.args[0].id, unknown)) in {str, bytes}
                and len(node.keywords) <= 1
                and all(keyword.arg == "exist_ok" and isinstance(keyword.value, ast.Constant)
                        and type(keyword.value.value) is bool for keyword in node.keywords)):
            # Only builtin paths exclude user-defined __fspath__ effects.
            # Under the existing stdlib-os binding premise, this call does not
            # rebind os or change a chmod literal. Filesystem success remains
            # a bounded reachability assumption, not an exploit witness.
            return None
        if isinstance(node, ast.Call) and not _is_os_chmod_call(node):
            # The function and its arguments are processed separately first so
            # permission-relevant operations inside them are retained; an
            # unknown callee without a verified summary then stays a fatal gap
            # even in a condition (C3): absence of chmod text proves nothing.
            collect_expression(node.func, shadowed_os)
            for argument in node.args:
                collect_expression(argument, shadowed_os)
            for keyword in node.keywords:
                collect_expression(keyword.value, shadowed_os)
            issues.append("unknown call may change permission bindings or terminate execution")
            return unknown
        if isinstance(node, ast.Attribute):
            # The supported stdlib entry points have an explicit binding
            # premise. Other reads may invoke descriptors/__getattribute__.
            if not (not shadowed_os and _call_name(node) in {"os.chmod", "os.makedirs"}):
                collect_expression(node.value, shadowed_os)
                issues.append("attribute read has unresolved permission-relevant effects")
            return unknown
        if not isinstance(node, (ast.Call, ast.Constant, ast.Name, ast.Attribute, ast.Load)):
            issues.append(f"unsupported permission expression: {type(node).__name__}")
            return unknown
        for child in ast.iter_child_nodes(node):
            collect_expression(child, shadowed_os)
        if isinstance(node, ast.Call) and _is_os_chmod_call(node):
            if shadowed_os:
                issues.append("os binding is shadowed before os.chmod")
            if len(node.args) != 2 or node.keywords:
                issues.append("os.chmod requires exactly two supported positional arguments")
                return unknown
            mode, mode_text = _literal_mode(node.args[1])
            mode_text = ast.get_source_segment(document.text, node.args[1]) or mode_text
            calls.append(
                _PermissionModeCall(
                    line=getattr(node, "lineno", 0),
                    target=ast.unparse(node.args[0]),
                    mode=mode,
                    mode_text=mode_text,
                    text=source_line(node),
                    branch_conditions=tuple(branch_conditions),
                )
            )

        return unknown

    def collect_statements(
        statements: list[ast.stmt],
        shadowed_os: bool,
    ) -> tuple[bool, bool]:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if (
                    statement.decorator_list or statement.args.defaults or any(statement.args.kw_defaults)
                    or statement.returns is not None
                    or any(isinstance(arg, ast.arg) and arg.annotation is not None for arg in ast.walk(statement.args))
                ):
                    issues.append("nested function definition can execute defaults or decorators")
                    return shadowed_os, True
                values[statement.name] = lost
                if statement.name == "os":
                    shadowed_os = True
                continue
            if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                if isinstance(statement, ast.Return) and statement.value is not None:
                    collect_expression(statement.value, shadowed_os)
                if isinstance(statement, ast.Raise) and statement.exc is not None:
                    collect_expression(statement.exc, shadowed_os)
                return shadowed_os, True
            if isinstance(statement, ast.If):
                outcome = truth(collect_expression(statement.test, shadowed_os))
                if outcome is not None:
                    branch = statement.body if outcome else statement.orelse
                    shadowed_os, terminated = collect_statements(branch, shadowed_os)
                    if terminated:
                        return shadowed_os, True
                    continue
                control_notes.append("permission mode check crosses a nonconstant branch")
                before = dict(values)
                condition = ast.unparse(statement.test)
                branch_conditions.append(condition)
                body_shadowed, body_terminated = collect_statements(statement.body, shadowed_os)
                branch_conditions.pop()
                body_values = dict(values)
                values.clear()
                values.update(before)
                branch_conditions.append(f"not ({condition})")
                else_shadowed, else_terminated = collect_statements(statement.orelse, shadowed_os)
                branch_conditions.pop()
                merge_values(body_values, dict(values))
                shadowed_os = body_shadowed or else_shadowed
                if body_terminated != else_terminated:
                    issues.append("permission branches have different termination paths")
                    return shadowed_os, True
                if body_terminated:
                    return shadowed_os, True
                continue
            if isinstance(statement, ast.Try):
                # Join all supported normal/handler paths, then inspect the
                # continuation. A return/raise inside try requires separate
                # unwinding semantics and remains explicitly unsupported.
                if any(handler.type is not None and not (
                    isinstance(handler.type, ast.Name)
                    or (isinstance(handler.type, ast.Tuple)
                        and all(isinstance(item, ast.Name) for item in handler.type.elts))
                ) for handler in statement.handlers):
                    issues.append("exception type evaluation has unsupported side effects")
                    return shadowed_os, True
                before = dict(values)
                branches = [collect_statements(statement.body, shadowed_os)]
                normal_shadowed, normal_terminated = collect_statements(statement.orelse, branches[0][0])
                branches[0] = (normal_shadowed, normal_terminated or branches[0][1])
                states = [dict(values)]
                handler_values = dict(before)
                for node in ast.walk(statement):
                    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                        handler_values[node.id] = lost

                for handler in statement.handlers:
                    values.clear()
                    values.update(handler_values)
                    if handler.name:
                        values[handler.name] = lost
                    before_handler = len(calls)
                    branches.append(collect_statements(handler.body, shadowed_os or handler.name == "os"))
                    states.append(dict(values))
                    if len(calls) != before_handler:
                        issues.append("permission calls in exception handlers require exception reachability")
                if any(terminated for _, terminated in branches):
                    issues.append("permission try termination requires exception unwinding")
                    return any(shadowed for shadowed, _ in branches), True
                shadowed_os = any(shadowed for shadowed, _ in branches)
                merge_values(*states)
                shadowed_os, terminated = collect_statements(statement.finalbody, shadowed_os)
                if terminated:
                    return shadowed_os, True
                continue
            if isinstance(statement, ast.Assert):
                if not isinstance(statement.test, ast.Constant) or not statement.test.value:
                    issues.append("assertion may terminate the permission path")
                    return shadowed_os, True
                continue
            if isinstance(statement, ast.Delete):
                issues.append("deletion makes permission bindings unresolved")
                return shadowed_os, True
            if isinstance(statement, ast.Expr):
                # C3: statement position never exempts executable effects.
                # The expression visitor handles arguments and verified summaries;
                # unknown callees remain coverage gaps even after a known chmod.
                collect_expression(statement.value, shadowed_os)
            elif isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                if any(isinstance(node, (ast.Attribute, ast.Subscript)) for target in targets for node in ast.walk(target)):
                    issues.append("attribute or container mutation may change aliased permission bindings")
                    return shadowed_os, True
                if statement.value is not None:
                    result = collect_expression(statement.value, shadowed_os)
                    for target in targets:
                        bind(target, unknown if isinstance(statement, ast.AugAssign) else result)
            elif not isinstance(statement, (ast.Import, ast.ImportFrom, ast.Pass, ast.Global)):
                # Includes try/try-star, loops, with, match and class creation.
                # All can prevent or change the following chmod execution.
                issues.append(f"unsupported permission statement: {type(statement).__name__}")
                return shadowed_os, True
            if isinstance(statement, ast.ImportFrom) and (statement.level or any(alias.name == "*" for alias in statement.names)):
                issues.append("relative or wildcard imports make permission bindings unresolved")
                return shadowed_os, True
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                for alias in statement.names:
                    values[alias.asname or alias.name.split(".")[0]] = lost
            shadowed_os = _os_shadowed_after_statement(statement, shadowed_os)
        return shadowed_os, False

    functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if len(functions) > 1:
        issues.append("multiple function bodies do not define a single execution path")
    module_shadowed = (
        "os" in document.module_rebindings
        or document.import_aliases.get("os", "os") != "os"
    )
    module_shadowed, _ = collect_statements(
        [node for node in tree.body if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))],
        module_shadowed,
    )
    for top_level in functions:
        if isinstance(top_level, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # A name alone proves neither wrapper identity nor its effects.
            # Even stdlib caches invoke argument hash/equality protocols and
            # may bypass the body. No decorator summary is currently modeled.
            if top_level.decorator_list:
                issues.append("decorated permission entry has unresolved execution semantics")
                continue
            try:
                symbols = symtable.symtable(ast.unparse(top_level), document.path, "exec").get_children()[0]
            except SyntaxError:
                issues.append("function binding scope is unavailable")
                continue
            parameters = {arg.arg for arg in (*top_level.args.posonlyargs, *top_level.args.args, *top_level.args.kwonlyargs)}
            scenario = entry_boolean_arguments or {}
            if set(scenario) - parameters or any(type(value) is not bool for value in scenario.values()):
                issues.append("invalid declared entry boolean arguments")
            values.clear()
            values.update(scenario)
            local_os = "os" in symbols.get_identifiers() and symbols.lookup("os").is_local()
            collect_statements(top_level.body, module_shadowed or local_os)
    merged = tuple(dict.fromkeys([*issues, *control_notes]))
    return tuple(calls), merged, tuple(control_notes)


def _permission_mode_assessment(document: CodeDocument, *, call_line: int | None = None, entry_boolean_arguments: dict[str, bool] | None = None) -> dict[str, Any]:
    calls, issues, control_notes = _collect_permission_mode_calls(document, entry_boolean_arguments=entry_boolean_arguments)
    if call_line is not None:
        calls = tuple(call for call in calls if call.line == call_line)
    fatal_issues = [issue for issue in issues if issue not in set(control_notes)]
    if not calls:
        return {
            "status": ValidationStatus.UNRESOLVED,
            "summary": "no reachable literal os.chmod call was found in the candidate span",
            "calls": [],
            "issues": list(issues),
        }
    if any(call.mode is None for call in calls):
        return {
            "status": ValidationStatus.UNRESOLVED,
            "summary": "permission mode check requires literal integer chmod modes",
            "calls": [call.__dict__ for call in calls],
            "issues": ["non-literal chmod mode"],
        }
    targets = {call.target for call in calls}
    if len(targets) != 1:
        return {
            "status": ValidationStatus.UNRESOLVED,
            "summary": "permission mode check requires one concrete chmod target",
            "calls": [call.__dict__ for call in calls],
            "issues": ["multiple chmod targets"],
        }
    unsafe_calls = [call for call in calls if cast(int, call.mode) & 0o002]
    # The verdict keys on gap categories recorded at creation (C2/C3), never on
    # issue text. Fatal gaps are unproven values, bindings or os/chmod state;
    # control notes are bounded reachability/conditionality caveats whose
    # executable positions were all visited.
    bounded_control_issues = bool(control_notes) and not fatal_issues
    if fatal_issues:
        return {
            "status": ValidationStatus.UNRESOLVED,
            "summary": "permission execution or binding is outside the supported bounded semantics",
            "calls": [call.__dict__ for call in calls],
            "issues": list(issues),
        }
    final_call = calls[-1]
    final_unsafe = bool(cast(int, final_call.mode) & 0o002)
    if issues and bounded_control_issues and final_unsafe:
        status = ValidationStatus.CONFIRMED
        summary = (
            "a collected literal chmod path grants others-write permission; unresolved "
            "control flow may affect reachability but the visible mode is others-writable"
        )
    elif issues and bounded_control_issues and unsafe_calls:
        status = ValidationStatus.UNRESOLVED
        summary = (
            "a collected others-writable chmod is followed by a narrower mode; temporal "
            "exposure and reachability are not modeled"
        )
    elif issues and bounded_control_issues:
        status = ValidationStatus.REFUTED
        summary = (
            "all collected literal chmod modes are non-others-writable; unresolved "
            "control flow may affect reachability but did not expose an others-writable mode"
        )
    elif unsafe_calls and not final_unsafe:
        status = ValidationStatus.UNRESOLVED
        summary = (
            "a world-writable chmod is followed by a narrower mode; temporal exposure "
            "and exploitability are not modeled"
        )
    elif final_unsafe:
        status = ValidationStatus.CONFIRMED
        summary = "the bounded permission check ends with an others-writable chmod mode"
    else:
        status = ValidationStatus.REFUTED
        summary = "the bounded permission check uses a non-others-writable literal chmod mode"
    return {
        "status": status,
        "summary": summary,
        "calls": [call.__dict__ for call in calls],
        "final_mode": final_call.mode_text,
        "final_others_write": final_unsafe,
        "issues": list(issues),
        "scope_note": (
            "This validates the literal chmod mode sequence in the candidate span only; "
            "it does not prove cross-process race exploitability or every runtime branch."
        ),
    }


def permission_mode(index: RepositoryIndex, arguments: FrozenModel, scope: ToolExecutionScope) -> ToolObservation:
    value = cast(PathInput, arguments)
    if scope.candidate_path is not None and value.path != scope.candidate_path:
        return ToolObservation(
            tool="validate_permission_mode",
            status="blocked",
            content="permission mode validation must inspect the candidate entry span",
        )
    if scope.subject is not None and scope.subject.source_digest != repository_source_digest(index):
        return ToolObservation(
            tool="validate_permission_mode",
            status="blocked",
            content="permission mode index source does not match the candidate subject",
        )
    document, error = _admitted_document(index, value.path, scope, "validate_permission_mode")
    if error is not None:
        return error
    source = cast(CodeDocument, document)
    local_line = local_source_line(value.path, scope.subject.entry_line) if scope.subject else None
    if scope.subject is not None and (
        scope.subject.entry_path != value.path
        or scope.subject.repository_id != source.repository_id
        or local_line is not None and not 1 <= local_line <= len(source.text.splitlines())
    ):
        return ToolObservation(
            tool="validate_permission_mode", status="blocked",
            content="permission mode subject does not match the indexed source span",
        )
    # A function header denotes the complete bounded sequence. Other positions
    # must identify a collected chmod call; a different sink cannot borrow it.
    try:
        tree = ast.parse(textwrap.dedent(source.text))
        headers = {line for node in tree.body
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                   for line in range(min([node.lineno, *(d.lineno for d in node.decorator_list)]), node.lineno + 1)}
    except SyntaxError:
        headers = set()
    assessment = _permission_mode_assessment(
        source, call_line=None if local_line in headers else local_line,
        entry_boolean_arguments=scope.subject.entry_boolean_arguments if scope.subject else None,
    )
    assessment["entry_boolean_arguments"] = dict(scope.subject.entry_boolean_arguments) if scope.subject else {}
    assessment["property_id"] = "chmod-mode-others-write"
    assessment["path"] = value.path
    assessment["subject_property_matches"] = bool(
        scope.subject and scope.subject.property_id == "chmod-mode-others-write"
    )
    status = ValidationStatus(assessment["status"])
    subject = (
        scope.subject
        if status in {ValidationStatus.CONFIRMED, ValidationStatus.REFUTED}
        and assessment["subject_property_matches"]
        else None
    )
    return ToolObservation(
        tool="validate_permission_mode",
        status="ok",
        validation_status=status,
        content=_json_content(assessment),
        evidence_ids=(f"permission_mode:{value.path}",),
        subject=subject,
    )
