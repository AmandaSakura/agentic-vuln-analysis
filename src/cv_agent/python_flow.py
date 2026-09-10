"""Bounded Python AST dataflow used by the validation tool (not a full SAST engine)."""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass
from typing import Any, Iterable

from .types import CodeDocument


@dataclass(frozen=True)
class CallBinding:
    name: str
    positional: tuple[bool, ...]
    keywords: tuple[tuple[str, bool], ...] = ()


def function_node(document: CodeDocument) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    try:
        tree = ast.parse(textwrap.dedent(document.text))
    except (SyntaxError, ValueError):
        return None
    return next(
        (node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))),
        None,
    )


def parameter_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    return tuple(
        arg.arg for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
        if arg.arg not in {"self", "cls"}
    )


def python_document_flow(
    document: CodeDocument, *, initial_tainted: Iterable[str], sink_category: str,
    source_rules: Iterable[Any], sink_rules: Iterable[Any], sanitizer_rules: Iterable[Any],
) -> dict[str, Any] | None:
    node = function_node(document)
    if node is None:
        return None
    lines = textwrap.dedent(document.text).splitlines()
    sources: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    sanitizers: list[dict[str, Any]] = []
    bindings: list[CallBinding] = []

    def source(expression: ast.AST) -> bool:
        if isinstance(expression, ast.Call):
            text = ast.unparse(expression.func) + "("
        elif isinstance(expression, ast.Attribute):
            text = ast.unparse(expression)
        else:
            return False
        return any(rule.pattern.search(text) for rule in source_rules)

    def sanitized(expression: ast.Call) -> bool:
        name = ast.unparse(expression.func)
        if name in {"shlex.quote", "shellescape", "escapeShellArg"}:
            return sink_category == "command-execution"
        if name == "int":
            return sink_category in {"command-execution", "code-execution", "sql"}
        # Path normalization and schema validation do not establish sink safety.
        return False

    def tainted(expression: ast.AST | None, environment: set[str]) -> bool:
        if expression is None or isinstance(expression, ast.Constant):
            return False
        if source(expression):
            return True
        if isinstance(expression, ast.Name):
            return expression.id in environment
        if isinstance(expression, ast.Call):
            if sanitized(expression):
                return False
            return any(tainted(arg, environment) for arg in expression.args) or any(
                tainted(keyword.value, environment) for keyword in expression.keywords
            )
        return any(tainted(child, environment) for child in ast.iter_child_nodes(expression))

    def record(expression: ast.AST | None, environment: set[str]) -> None:
        if expression is None:
            return
        for item in ast.walk(expression):
            line = getattr(item, "lineno", 1)
            text = lines[line - 1].strip() if line <= len(lines) else ""
            if source(item):
                value = {"line": line, "categories": ["untrusted-input"], "text": text}
                if value not in sources:
                    sources.append(value)
            if not isinstance(item, ast.Call):
                continue
            name = ast.unparse(item.func)
            call_text = name + "("
            arguments = tuple(tainted(arg, environment) for arg in item.args)
            keywords = tuple(
                (keyword.arg, tainted(keyword.value, environment))
                for keyword in item.keywords if keyword.arg is not None
            )
            bindings.append(CallBinding(name, arguments, keywords))
            hits = [rule.category for rule in sanitizer_rules if rule.pattern.search(call_text)]
            if hits:
                sanitizers.append({"line": line, "categories": hits, "text": text})
            for rule in sink_rules:
                if rule.category != sink_category or not rule.pattern.search(call_text):
                    continue
                # These Python rules target the command/query/path expression.
                # A separate tainted SQL parameters argument is not SQL text.
                relevant = arguments[0] if arguments else dict(keywords).get(
                    {"sql": "query", "path-access": "file", "code-execution": "source",
                     "command-execution": "args", "outbound-request": "url"}.get(sink_category, ""),
                    False,
                )
                sinks.append({
                    "category": rule.category, "line": line, "match": call_text,
                    "tainted": relevant, "text": text,
                })

    def assign(target: ast.AST, value: bool, environment: set[str]) -> None:
        if isinstance(target, ast.Name):
            if value:
                environment.add(target.id)
            else:
                environment.discard(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                assign(child, value, environment)

    def visit(statements: list[ast.stmt], environment: set[str]) -> set[str]:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                value = statement.value
                record(value, environment)
                value_tainted = tainted(value, environment)
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    previous = tainted(target, environment) if isinstance(statement, ast.AugAssign) else False
                    assign(target, value_tainted or previous, environment)
            elif isinstance(statement, ast.If):
                record(statement.test, environment)
                # Join both feasible branches instead of letting one overwrite the other.
                if isinstance(statement.test, ast.Constant):
                    environment = visit(statement.body if statement.test.value else statement.orelse, environment)
                else:
                    environment = visit(statement.body, set(environment)) | visit(statement.orelse, set(environment))
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                expression = statement.test if isinstance(statement, ast.While) else statement.iter
                record(expression, environment)
                branch = set(environment)
                if not isinstance(statement, ast.While):
                    assign(statement.target, tainted(expression, environment), branch)
                environment |= visit(statement.body, branch)
                environment |= visit(statement.orelse, set(environment))
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    record(item.context_expr, environment)
                    if item.optional_vars is not None:
                        assign(item.optional_vars, tainted(item.context_expr, environment), environment)
                environment = visit(statement.body, environment)
            elif isinstance(statement, ast.Try):
                branches = [visit(statement.body, set(environment))]
                branches.extend(visit(handler.body, set(environment)) for handler in statement.handlers)
                environment |= set().union(*branches)
                environment = visit(statement.orelse + statement.finalbody, environment)
            else:
                record(statement, environment)
        return environment

    environment = visit(node.body, set(initial_tainted))
    return {
        "path": document.path, "sources": tuple(sources), "sinks": tuple(sinks),
        "sanitizers": tuple(sanitizers), "tainted_variables": tuple(sorted(environment)),
        "tainted_calls": tuple(sorted({binding.name for binding in bindings if
            any(binding.positional) or any(value for _, value in binding.keywords)})),
        "call_bindings": tuple(bindings),
    }
