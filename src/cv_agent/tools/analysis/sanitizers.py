"""Bounded numeric helper-return links for unresolved Python eval assessments."""
from __future__ import annotations

import ast
import re

from cv_agent.domain.types import CodeDocument
from cv_agent.tools.analysis.python_flow import function_node, parameter_names


def _bindings(document: CodeDocument, function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    names = set(document.module_bindings) | set(document.module_rebindings)
    for node in ast.walk(function):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.alias):
            names.add(node.asname or node.name.split(".")[0])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
    return names


def numeric_helper_flows(
    entry: CodeDocument, helper: CodeDocument, entry_line: int | None,
    *, ambiguous_symbols: set[str],
) -> list[dict]:
    """Link a supported numeric helper return to the entire candidate eval argument.

    The caller must separately establish a unique admitted call-graph edge. These
    facts support an UNRESOLVED safety hypothesis, never a concrete refutation.
    """
    caller = function_node(entry)
    callee = function_node(helper)
    if not isinstance(caller, ast.FunctionDef) or not isinstance(callee, ast.FunctionDef):
        return []
    if caller.decorator_list or callee.decorator_list:
        return []
    parameters = parameter_names(callee)
    if len(parameters) != 1 or callee.args.vararg or callee.args.kwarg or callee.args.kwonlyargs:
        return []
    helper_bindings = _bindings(helper, callee) | set(helper.import_aliases)
    if {"int", "str"} & helper_bindings:
        return []
    # Values retain whether the returned number derives from the bound parameter.
    values: dict[str, tuple[str, tuple[int, ...]] | None] = {parameters[0]: ("input", ())}

    def numeric(expression: ast.expr) -> tuple[str, tuple[int, ...]] | None:
        if isinstance(expression, ast.Name):
            return values.get(expression.id)
        if not (isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name)
                and len(expression.args) == 1 and not expression.keywords):
            return None
        argument = numeric(expression.args[0])
        if argument is None:
            return None
        if expression.func.id == "int":
            return "numeric", (*argument[1], expression.lineno)
        if expression.func.id == "str" and argument[0] == "numeric":
            return argument
        return None

    returned = None
    return_line = None
    for position, statement in enumerate(callee.body):
        if (position == 0 and isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str)):
            continue
        if isinstance(statement, ast.Assign) and all(isinstance(t, ast.Name) for t in statement.targets):
            value = numeric(statement.value)
            for target in statement.targets:
                values[target.id] = value
        elif isinstance(statement, ast.Return) and statement.value is not None:
            returned = numeric(statement.value)
            return_line = statement.lineno
            break
        else:
            return []
    if returned is None or returned[0] != "numeric":
        return []

    caller_bindings = _bindings(entry, caller)
    # Module definitions can legitimately contain the helper's own name; local
    # assignments/parameters and module rebindings cannot establish that binding.
    local_bindings = _bindings(entry.model_copy(update={"module_bindings": ()}), caller)
    aliases: dict[str, ast.Call | None] = {}

    def helper_call(expression: ast.expr) -> ast.Call | None:
        if isinstance(expression, ast.Name):
            return aliases.get(expression.id)
        if not isinstance(expression, ast.Call):
            return None
        parts = ast.unparse(expression.func).split(".")
        if parts[0] in local_bindings:
            return None
        symbol = ".".join((entry.import_aliases.get(parts[0], parts[0]), *parts[1:]))
        if symbol not in helper.defines or symbol in ambiguous_symbols:
            return None
        if len(expression.args) == 1 and not expression.keywords:
            return expression
        if not expression.args and len(expression.keywords) == 1 and expression.keywords[0].arg == parameters[0]:
            return expression
        return None

    span = re.search(r"::.+@(\d+)(?:-\d+)?(?:#\d+-\d+)?$", entry.path)
    offset = int(span.group(1)) - 1 if span else 0
    flows: list[dict] = []
    sink_count = 0
    for statement in caller.body:
        if not isinstance(statement, (ast.Assign, ast.Expr, ast.Return)):
            return []
        expression = statement.value
        if isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name) and expression.func.id == "eval":
            sink_count += 1
            if "eval" in caller_bindings or "eval" in entry.import_aliases:
                return []
            sink_line = expression.lineno + offset
            if len(expression.args) == 1 and not expression.keywords and entry_line in {None, sink_line}:
                call = helper_call(expression.args[0])
                if call is not None:
                    flows.append({"source_path": entry.path, "sink_line": sink_line,
                                  "helper_path": helper.path, "call_line": call.lineno + offset,
                                  "return_line": return_line, "sanitizer_lines": list(returned[1])})
        if isinstance(statement, ast.Assign):
            if not all(isinstance(target, ast.Name) for target in statement.targets):
                return []
            value = helper_call(statement.value)
            for target in statement.targets:
                aliases[target.id] = value
        if isinstance(statement, ast.Return):
            break
    return flows if entry_line is not None or sink_count == 1 else []
