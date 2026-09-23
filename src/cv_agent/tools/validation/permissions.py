"""Bounded Python permission-mode analysis and its candidate-bound tool."""

from __future__ import annotations

import ast
import re
import symtable
import textwrap
from dataclasses import dataclass
from typing import Any, cast

from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.identity import repository_source_digest
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


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


_PERMISSION_BODY_PRESERVING_DECORATORS = frozenset({
    "cache_return_value_per_process",
    "functools.cache",
    "functools.lru_cache",
    "lru_cache",
})


def _permission_decorator_is_body_preserving(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        if node.args or node.keywords:
            return False
        node = node.func
    name = _call_name(node)
    return name in _PERMISSION_BODY_PRESERVING_DECORATORS


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


def _collect_permission_mode_calls(document: CodeDocument) -> tuple[
    tuple[_PermissionModeCall, ...],
    tuple[str, ...],
]:
    try:
        tree = ast.parse(textwrap.dedent(document.text))
    except SyntaxError as error:
        return (), (f"syntax error: {error}",)
    lines = document.text.splitlines()
    issues: list[str] = []
    calls: list[_PermissionModeCall] = []

    def source_line(node: ast.AST) -> str:
        line = getattr(node, "lineno", 0)
        return lines[line - 1].strip() if 1 <= line <= len(lines) else ast.unparse(node)

    def collect_expression(node: ast.AST, shadowed_os: bool) -> None:
        # ast.walk is not execution order: boolean operands and conditional
        # expressions can contain calls which are never evaluated.
        if isinstance(node, ast.BoolOp):
            for position, operand in enumerate(node.values):
                collect_expression(operand, shadowed_os)
                if position == len(node.values) - 1:
                    break
                if not isinstance(operand, ast.Constant):
                    issues.append("short-circuit condition is not a literal")
                    break
                if isinstance(node.op, ast.And) != bool(operand.value):
                    break
            return
        if isinstance(node, ast.IfExp):
            if isinstance(node.test, ast.Constant):
                collect_expression(node.body if node.test.value else node.orelse, shadowed_os)
            else:
                issues.append("conditional expression execution is unresolved")
            return
        if isinstance(node, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp,
                             ast.GeneratorExp, ast.NamedExpr)):
            issues.append("unsupported deferred or binding expression")
            return
        if (isinstance(node, ast.Call) and _call_name(node.func) == "os.makedirs"
                and not shadowed_os and len(node.args) == 1
                and isinstance(node.args[0], (ast.Name, ast.Constant))
                and all(keyword.arg == "exist_ok" and isinstance(keyword.value, ast.Constant)
                        and type(keyword.value.value) is bool for keyword in node.keywords)):
            # This supported call does not rebind os or change a chmod literal.
            # Its success/reachability is not an exploit witness.
            return
        if isinstance(node, ast.Call) and not _is_os_chmod_call(node):
            issues.append("unknown call may change permission bindings or terminate execution")
            return
        if not isinstance(node, (ast.Call, ast.Constant, ast.Name, ast.Attribute, ast.Load)):
            issues.append(f"unsupported permission expression: {type(node).__name__}")
            return
        for child in ast.iter_child_nodes(node):
            collect_expression(child, shadowed_os)
        if isinstance(node, ast.Call) and _is_os_chmod_call(node):
            if shadowed_os:
                issues.append("os binding is shadowed before os.chmod")
            if len(node.args) != 2 or node.keywords:
                issues.append("os.chmod requires exactly two supported positional arguments")
                return
            mode, mode_text = _literal_mode(node.args[1])
            mode_text = ast.get_source_segment(document.text, node.args[1]) or mode_text
            calls.append(
                _PermissionModeCall(
                    line=getattr(node, "lineno", 0),
                    target=ast.unparse(node.args[0]),
                    mode=mode,
                    mode_text=mode_text,
                    text=source_line(node),
                )
            )

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
                if statement.name == "os":
                    shadowed_os = True
                continue
            if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                if isinstance(statement, ast.Return) and statement.value is not None:
                    collect_expression(statement.value, shadowed_os)
                if isinstance(statement, ast.Raise) and statement.exc is not None:
                    collect_expression(statement.exc, shadowed_os)
                return shadowed_os, True
            if isinstance(statement, ast.If) and isinstance(statement.test, ast.Constant):
                branch = statement.body if bool(statement.test.value) else statement.orelse
                shadowed_os, terminated = collect_statements(branch, shadowed_os)
                if terminated:
                    return shadowed_os, True
                continue
            if isinstance(statement, ast.If):
                issues.append("permission mode check crosses a nonconstant branch")
                body_shadowed, body_terminated = collect_statements(statement.body, shadowed_os)
                else_shadowed, else_terminated = collect_statements(statement.orelse, shadowed_os)
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
                branches = [collect_statements(statement.body, shadowed_os)]
                for handler in statement.handlers:
                    before_handler = len(calls)
                    branches.append(collect_statements(handler.body, shadowed_os or handler.name == "os"))
                    if len(calls) != before_handler:
                        issues.append("permission calls in exception handlers require exception reachability")
                if any(terminated for _, terminated in branches):
                    issues.append("permission try termination requires exception unwinding")
                    return any(shadowed for shadowed, _ in branches), True
                shadowed_os = any(shadowed for shadowed, _ in branches)
                shadowed_os, terminated = collect_statements(statement.orelse, shadowed_os)
                if terminated:
                    issues.append("permission try termination requires exception unwinding")
                    return shadowed_os, True
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
                if calls and isinstance(statement.value, ast.Call) and not _is_os_chmod_call(statement.value):
                    issues.append("unknown call after chmod may affect cleanup or termination")
                else:
                    collect_expression(statement.value, shadowed_os)
            elif isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                if any(isinstance(node, (ast.Attribute, ast.Subscript)) for target in targets for node in ast.walk(target)):
                    issues.append("attribute or container mutation may change aliased permission bindings")
                    return shadowed_os, True
                if statement.value is not None:
                    if isinstance(statement.value, ast.Call) and not _is_os_chmod_call(statement.value):
                        issues.append("unknown assigned call may affect permission values")
                    else:
                        collect_expression(statement.value, shadowed_os)
            elif not isinstance(statement, (ast.Import, ast.ImportFrom, ast.Pass, ast.Global)):
                # Includes try/try-star, loops, with, match and class creation.
                # All can prevent or change the following chmod execution.
                issues.append(f"unsupported permission statement: {type(statement).__name__}")
                return shadowed_os, True
            if isinstance(statement, ast.ImportFrom) and (statement.level or any(alias.name == "*" for alias in statement.names)):
                issues.append("relative or wildcard imports make permission bindings unresolved")
                return shadowed_os, True
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
            if top_level.decorator_list and not all(
                _permission_decorator_is_body_preserving(decorator)
                for decorator in top_level.decorator_list
            ):
                issues.append("decorated permission entry has unresolved execution semantics")
                continue
            try:
                symbols = symtable.symtable(ast.unparse(top_level), document.path, "exec").get_children()[0]
            except SyntaxError:
                issues.append("function binding scope is unavailable")
                continue
            local_os = "os" in symbols.get_identifiers() and symbols.lookup("os").is_local()
            collect_statements(top_level.body, module_shadowed or local_os)
    return tuple(calls), tuple(dict.fromkeys(issues))


def _permission_mode_assessment(document: CodeDocument) -> dict[str, Any]:
    calls, issues = _collect_permission_mode_calls(document)
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
    bounded_control_issues = issues and all(
        issue in {
            "permission mode check crosses a nonconstant branch",
            "unknown assigned call may affect permission values",
            "unknown call after chmod may affect cleanup or termination",
        }
        for issue in issues
    )
    if issues and not bounded_control_issues:
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
    assessment = _permission_mode_assessment(cast(CodeDocument, document))
    status = ValidationStatus(assessment["status"])
    subject = (
        scope.subject
        if status in {ValidationStatus.CONFIRMED, ValidationStatus.REFUTED}
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
