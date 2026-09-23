"""Bounded Python AST dataflow used by the validation tool (not a full SAST engine)."""

from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass
from typing import Any, Iterable

from cv_agent.domain.types import CodeDocument


INTERPRETER_NAME_PATTERN = re.compile(
    r"^(?:"
    r"sh|bash|dash|zsh|ksh|fish|csh|tcsh|busybox|su|runuser|"
    r"cmd|powershell|pwsh|"
    r"(?:python|pypy|perl|ruby|node|nodejs|php)(?:[0-9]+(?:\.[0-9]+)*)?"
    r")(?:\.exe)?$",
    re.IGNORECASE,
)

LAUNCHER_COMMANDS = {
    "env", "sudo", "doas", "nohup", "nice", "ionice", "stdbuf", "time",
}


def resolve_executable(elts: list[ast.expr] | tuple[ast.expr, ...]) -> tuple[str | None, bool]:
    """Return (executable_basename, is_known) from an argv list, resolving launchers."""
    if not elts:
        return None, False
    first = elts[0]
    if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
        return None, False
    exe = first.value.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if exe not in LAUNCHER_COMMANDS:
        return exe, True

    idx = 1
    while exe in LAUNCHER_COMMANDS:
        if exe == "env":
            found = False
            while idx < len(elts):
                elt = elts[idx]
                idx += 1
                if not (isinstance(elt, ast.Constant) and isinstance(elt.value, str)):
                    return None, False
                val = elt.value
                if val == "--":
                    if idx < len(elts) and isinstance(elts[idx], ast.Constant) and isinstance(elts[idx].value, str):
                        exe = elts[idx].value.replace("\\", "/").rsplit("/", 1)[-1].lower()
                        idx += 1
                        found = True
                        break
                    return None, False
                if val in {"-u", "--unset", "-C", "--chdir"}:
                    if idx >= len(elts) or not (isinstance(elts[idx], ast.Constant) and isinstance(elts[idx].value, str)):
                        return None, False
                    idx += 1
                    continue
                if val.startswith(("-u", "-C")) and not val.startswith(("-u=", "-C=")):
                    continue
                if val in {"-i", "-0", "-v", "--null", "--ignore-environment", "--debug"}:
                    continue
                if val.startswith("-") or "=" in val:
                    if "=" in val and not val.startswith("-"):
                        continue
                    return None, False
                exe = val.replace("\\", "/").rsplit("/", 1)[-1].lower()
                found = True
                break
            if not found:
                return None, False

        elif exe == "sudo":
            found = False
            while idx < len(elts):
                elt = elts[idx]
                idx += 1
                if not (isinstance(elt, ast.Constant) and isinstance(elt.value, str)):
                    return None, False
                val = elt.value
                if val in {"-s", "--shell", "-i", "--login", "-e", "--edit"}:
                    return "sh", True
                if val == "--":
                    if idx < len(elts) and isinstance(elts[idx], ast.Constant) and isinstance(elts[idx].value, str):
                        exe = elts[idx].value.replace("\\", "/").rsplit("/", 1)[-1].lower()
                        idx += 1
                        found = True
                        break
                    return None, False
                if val in {"-u", "--user", "-g", "--group"}:
                    if idx >= len(elts) or not (isinstance(elts[idx], ast.Constant) and isinstance(elts[idx].value, str)):
                        return None, False
                    idx += 1
                    continue
                if val.startswith(("--user=", "--group=", "-u", "-g")):
                    continue
                if val in {"-E", "--preserve-env", "-b", "--background", "-n", "--non-interactive"}:
                    continue
                if val.startswith(("-E=", "--preserve-env=")):
                    continue
                if val.startswith("-"):
                    return None, False
                exe = val.replace("\\", "/").rsplit("/", 1)[-1].lower()
                found = True
                break
            if not found:
                return None, False

        else:
            return None, False

    return exe, True


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

    subprocess_sinks = {"subprocess.run", "subprocess.call", "subprocess.Popen"}

    def qualified_call(call: ast.Call) -> str:
        parts = ast.unparse(call.func).split(".")
        return ".".join([document.import_aliases.get(parts[0], parts[0]), *parts[1:]])

    # Only propagate argv structure for a dominating local assignment whose
    # container never escapes or mutates. Taint itself remains flow-sensitive.
    # A boolean taint environment cannot safely track arbitrary list aliases.
    parents = {child: parent for parent in ast.walk(node) for child in ast.iter_child_nodes(parent)}
    fixed_argv: dict[str, ast.List | ast.Tuple] = {}
    for statement in node.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
        elif isinstance(statement, ast.AnnAssign):
            target = statement.target
        else:
            continue
        if not isinstance(target, ast.Name) or not isinstance(statement.value, (ast.List, ast.Tuple)):
            continue
        references = [item for item in ast.walk(node) if isinstance(item, ast.Name) and item.id == target.id]
        if any(item is not target and not isinstance(item.ctx, ast.Load) for item in references):
            continue
        if any(
            (isinstance(item, (ast.Global, ast.Nonlocal)) and target.id in item.names)
            or (isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and item.name == target.id)
            or (isinstance(item, ast.alias) and (item.asname or item.name.split(".")[0]) == target.id)
            for item in ast.walk(node)
        ):
            continue
        for reference in references:
            if reference is target:
                continue
            parent = parents[reference]
            call = parents.get(parent) if isinstance(parent, ast.keyword) and parent.arg == "args" else parent
            if not (
                reference.lineno > statement.end_lineno
                and isinstance(call, ast.Call) and qualified_call(call) in subprocess_sinks
                and ((call.args and call.args[0] is reference)
                     or (isinstance(parent, ast.keyword) and parent.arg == "args"))
            ):
                break
        else:
            fixed_argv[target.id] = statement.value

    def ordinary_argv(expression: ast.AST | None) -> bool:
        if isinstance(expression, ast.Name):
            expression = fixed_argv.get(expression.id)
        if not (isinstance(expression, (ast.List, ast.Tuple)) and expression.elts):
            return False
        executable, known = resolve_executable(expression.elts)
        if not known or executable is None:
            return False
        # shell=False does not prevent the explicitly launched interpreter from
        # executing its command argument. Preserve possible flow in that case.
        return not bool(INTERPRETER_NAME_PATTERN.match(executable))

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
            name = qualified_call(item)
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
                if sink_category == "command-execution" and name in subprocess_sinks:
                    shell = next((kw.value for kw in item.keywords if kw.arg == "shell"),
                                 item.args[8] if len(item.args) >= 9 else ast.Constant(False))
                    argv = item.args[0] if item.args else next(
                        (kw.value for kw in item.keywords if kw.arg == "args"), None)
                    has_kw_executable = any(kw.arg in {"executable", None} for kw in item.keywords)
                    has_pos_executable = len(item.args) >= 3 and not (
                        isinstance(item.args[2], ast.Constant) and item.args[2].value is None
                    )
                    if (isinstance(shell, ast.Constant) and shell.value is False
                            and not has_kw_executable
                            and not has_pos_executable
                            and ordinary_argv(argv)):
                        # User data passed as argv to a fixed program is not shell text.
                        relevant = False
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

    def visit(statements: list[ast.stmt], environment: set[str]) -> set[str] | None:
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                record(statement, environment)
                return None
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
                    branches = [visit(statement.body, set(environment)), visit(statement.orelse, set(environment))]
                    remaining = [branch for branch in branches if branch is not None]
                    environment = set().union(*remaining) if remaining else None
                if environment is None:
                    return None
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                expression = statement.test if isinstance(statement, ast.While) else statement.iter
                record(expression, environment)
                if isinstance(statement, ast.While) and isinstance(expression, ast.Constant) and not expression.value:
                    environment = visit(statement.orelse, environment)
                    if environment is None:
                        return None
                    continue
                branch = set(environment)
                if not isinstance(statement, ast.While):
                    assign(statement.target, tainted(expression, environment), branch)
                environment |= visit(statement.body, branch) or set()
                environment |= visit(statement.orelse, set(environment)) or set()
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    record(item.context_expr, environment)
                    if item.optional_vars is not None:
                        assign(item.optional_vars, tainted(item.context_expr, environment), environment)
                environment = visit(statement.body, environment)
                if environment is None:
                    return None
            elif isinstance(statement, ast.Try):
                branches = [visit(statement.body, set(environment))]
                branches.extend(visit(handler.body, set(environment)) for handler in statement.handlers)
                environment |= set().union(*(branch for branch in branches if branch is not None))
                environment = visit(statement.orelse + statement.finalbody, environment)
                if environment is None:
                    return None
            else:
                record(statement, environment)
        return environment

    environment = visit(node.body, set(initial_tainted)) or set()
    return {
        "path": document.path, "sources": tuple(sources), "sinks": tuple(sinks),
        "sanitizers": tuple(sanitizers), "tainted_variables": tuple(sorted(environment)),
        "tainted_calls": tuple(sorted({binding.name for binding in bindings if
            any(binding.positional) or any(value for _, value in binding.keywords)})),
        "call_bindings": tuple(bindings),
    }
