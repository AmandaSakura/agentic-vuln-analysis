"""Bounded Python AST dataflow used by the validation tool (not a full SAST engine)."""

from __future__ import annotations

import ast
import builtins
import re
import textwrap
from dataclasses import dataclass
from typing import Any, Iterable

from cv_agent.domain.types import CodeDocument


ESTABLISHED_ORDINARY_PROGRAMS = {
    "echo",
}

LAUNCHER_COMMANDS = {
    "env", "sudo",
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
                        next_val = elts[idx].value
                        if "=" in next_val or next_val.startswith("-"):
                            return None, False
                        exe = next_val.replace("\\", "/").rsplit("/", 1)[-1].lower()
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
                        next_val = elts[idx].value
                        if "=" in next_val or next_val.startswith("-"):
                            return None, False
                        exe = next_val.replace("\\", "/").rsplit("/", 1)[-1].lower()
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
                if val.startswith("-") or "=" in val:
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


@dataclass(frozen=True)
class BlockFlow:
    normal: frozenset[str] | None
    breaks: tuple[frozenset[str], ...]
    continues: tuple[frozenset[str], ...]
    returns: tuple[frozenset[str], ...]
    exceptions: tuple[frozenset[str], ...]


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
    # `with a, b` enters b inside a's exception region. Normalize once so the
    # block cache and ordinary with handling also cover later entry failures.
    for statement in tuple(ast.walk(node)):
        if isinstance(statement, (ast.With, ast.AsyncWith)) and len(statement.items) > 1:
            body = statement.body
            for item in reversed(statement.items[1:]):
                nested = type(statement)(items=[item], body=body, type_comment=None)
                body = [ast.copy_location(nested, statement)]
            statement.items = statement.items[:1]
            statement.body = body
    lines = textwrap.dedent(document.text).splitlines()
    sources: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    sanitizers: list[dict[str, Any]] = []
    bindings: list[CallBinding] = []

    subprocess_sinks = {
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "subprocess.check_call", "subprocess.check_output",
        "subprocess.getoutput", "subprocess.getstatusoutput",
        "os.system", "os.popen",
    }

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
        # Only clear taint when the command has established non-executing parameter semantics.
        # Unknown programs, shells, and script engines (awk, sed, python, etc.) preserve possible flow.
        return executable in ESTABLISHED_ORDINARY_PROGRAMS

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
            binding = CallBinding(name, arguments, keywords)
            if binding not in bindings:
                bindings.append(binding)
            hits = [rule.category for rule in sanitizer_rules if rule.pattern.search(call_text)]
            if hits:
                sanitizer_entry = {"line": line, "categories": hits, "text": text}
                if sanitizer_entry not in sanitizers:
                    sanitizers.append(sanitizer_entry)
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
                sink_entry = {
                    "category": rule.category, "line": line, "match": call_text,
                    "tainted": relevant, "text": text,
                }
                for existing in sinks:
                    if (existing["category"], existing["line"], existing["match"], existing["text"]) == (
                        sink_entry["category"], sink_entry["line"], sink_entry["match"], sink_entry["text"]
                    ):
                        if relevant:
                            existing["tainted"] = True
                        break
                else:
                    sinks.append(sink_entry)

    def assign(target: ast.AST, value: bool, environment: set[str]) -> None:
        if isinstance(target, ast.Name):
            if value:
                environment.add(target.id)
            else:
                environment.discard(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                assign(child, value, environment)

    block_cache: dict[tuple[tuple[ast.stmt, ...], frozenset[str]], BlockFlow] = {}

    rebound_names = set(document.module_bindings) | set(document.module_rebindings) | set(document.import_aliases)
    for item in ast.walk(node):
        if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
            rebound_names.add(item.id)
        elif isinstance(item, ast.arg):
            rebound_names.add(item.arg)
        elif isinstance(item, ast.ExceptHandler) and item.name is not None:
            rebound_names.add(item.name)
        elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            rebound_names.add(item.name)
        elif isinstance(item, ast.alias):
            rebound_names.add(item.asname or item.name.split(".")[0])

    def valid_exception_type(expression: ast.expr | None) -> bool:
        if expression is None:
            return True
        if isinstance(expression, ast.Tuple):
            return all(isinstance(item, ast.Name) and valid_exception_type(item) for item in expression.elts)
        if not isinstance(expression, ast.Name) or expression.id in rebound_names:
            return False
        value = vars(builtins).get(expression.id)
        return isinstance(value, type) and issubclass(value, BaseException)

    def catches_base_exception(expression: ast.expr | None) -> bool:
        if not valid_exception_type(expression):
            return False
        if expression is None:
            return True
        if isinstance(expression, ast.Tuple):
            return any(catches_base_exception(item) for item in expression.elts)
        return isinstance(expression, ast.Name) and expression.id == "BaseException" and expression.id not in rebound_names

    def unpack_may_raise(target: ast.AST, value: ast.AST) -> bool:
        if isinstance(target, ast.Starred):
            return unpack_may_raise(target.value, value)
        if not isinstance(target, (ast.Tuple, ast.List)):
            return False
        if not isinstance(value, (ast.Tuple, ast.List)) or any(isinstance(item, ast.Starred) for item in value.elts):
            return True
        starred = next((i for i, item in enumerate(target.elts) if isinstance(item, ast.Starred)), None)
        values = value.elts
        if starred is None:
            if len(target.elts) != len(values):
                return True
        else:
            if len(values) < len(target.elts) - 1:
                return True
            end = len(values) - (len(target.elts) - starred - 1)
            values = [*values[:starred], ast.List(elts=values[starred:end], ctx=ast.Load()), *values[end:]]
        return any(unpack_may_raise(child, item) for child, item in zip(target.elts, values))

    def may_raise(statement: ast.stmt) -> bool:
        if isinstance(statement, (ast.Raise, ast.Import, ast.ImportFrom, ast.Delete, ast.AugAssign,
                                  ast.With, ast.AsyncWith, ast.AsyncFor, ast.ClassDef)):
            return True
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            evaluated = [*statement.decorator_list, *statement.args.defaults,
                         *(value for value in statement.args.kw_defaults if value is not None),
                         *(arg.annotation for arg in ast.walk(statement.args)
                           if isinstance(arg, ast.arg) and arg.annotation is not None)]
            if statement.returns is not None:
                evaluated.append(statement.returns)
            return bool(statement.decorator_list) or any(expression_may_raise(value) for value in evaluated)
        if isinstance(statement, ast.Assert):
            return not (isinstance(statement.test, ast.Constant) and statement.test.value)
        if isinstance(statement, ast.Assign) and any(
            unpack_may_raise(target, statement.value) for target in statement.targets
        ):
            return True
        if isinstance(statement, ast.For):
            if not isinstance(statement.iter, (ast.List, ast.Tuple)):
                return True  # Obtaining the iterator or its next item can fail.
            if any(unpack_may_raise(statement.target, item) for item in statement.iter.elts):
                return True
        # Only expressions evaluated by this statement, not nested bodies.
        # In particular, entering try or assigning a literal cannot bypass finally.
        expressions = [child for child in ast.iter_child_nodes(statement) if isinstance(child, ast.expr)]
        return any(expression_may_raise(expression) for expression in expressions)

    def expression_may_raise(expression: ast.expr) -> bool:
        # Prune only expressions with established nonthrowing construction. Other
        # expressions (formatting, comprehensions, lookups, calls, etc.) keep an edge.
        if isinstance(expression, ast.Constant):
            return False
        if isinstance(expression, ast.Name) and isinstance(expression.ctx, ast.Store):
            return False
        if isinstance(expression, (ast.Tuple, ast.List, ast.Set)):
            return container_may_raise(expression) or any(expression_may_raise(item) for item in expression.elts)
        if isinstance(expression, ast.Dict):
            return container_may_raise(expression) or any(
                expression_may_raise(item) for item in (*expression.keys, *expression.values) if item is not None
            )
        if isinstance(expression, ast.Starred):
            return container_may_raise(expression) or expression_may_raise(expression.value)
        if isinstance(expression, ast.BoolOp):
            return any(expression_may_raise(item) for item in expression.values)
        if isinstance(expression, ast.IfExp):
            return any(expression_may_raise(item) for item in (expression.test, expression.body, expression.orelse))
        return True

    def container_may_raise(expression: ast.AST) -> bool:
        if isinstance(expression, ast.Starred):
            try:
                iter(ast.literal_eval(expression.value))
            except (ValueError, TypeError, SyntaxError):
                return True
        elif isinstance(expression, (ast.Set, ast.Dict)):
            keys = expression.elts if isinstance(expression, ast.Set) else expression.keys
            for i, key in enumerate(keys):
                try:
                    if key is None:
                        if not isinstance(ast.literal_eval(expression.values[i]), dict):
                            return True
                    else:
                        hash(ast.literal_eval(key))
                except (ValueError, TypeError, SyntaxError):
                    return True
        return False

    def visit(
        statements: list[ast.stmt],
        environment: set[str],
        *,
        breaks: list[set[str]] | None = None,
        continues: list[set[str]] | None = None,
        returns: list[set[str]] | None = None,
        exceptions: list[set[str]] | None = None,
    ) -> set[str] | None:
        key = (tuple(statements), frozenset(environment))
        if key not in block_cache:
            block_breaks: list[set[str]] = []
            block_continues: list[set[str]] = []
            block_returns: list[set[str]] = []
            block_exceptions: list[set[str]] = []
            normal = visit_block(
                statements, set(environment), breaks=block_breaks, continues=block_continues,
                returns=block_returns, exceptions=block_exceptions,
            )
            block_cache[key] = BlockFlow(
                frozenset(normal) if normal is not None else None,
                *(tuple(dict.fromkeys(map(frozenset, states))) for states in
                  (block_breaks, block_continues, block_returns, block_exceptions)),
            )
        result = block_cache[key]
        # Findings are accumulated globally and deduplicated by record(). Cached
        # blocks must replay exits into the current enclosing control-flow scope.
        for target, states in (
            (breaks, result.breaks), (continues, result.continues),
            (returns, result.returns), (exceptions, result.exceptions),
        ):
            if target is not None:
                target.extend(set(state) for state in states)
        return set(result.normal) if result.normal is not None else None

    def visit_block(
        statements: list[ast.stmt],
        environment: set[str],
        *,
        breaks: list[set[str]] | None = None,
        continues: list[set[str]] | None = None,
        returns: list[set[str]] | None = None,
        exceptions: list[set[str]] | None = None,
    ) -> set[str] | None:
        for statement in statements:
            # A may-analysis retains the pre-statement state for implicit errors:
            # evaluating an RHS can fail before its assignment clears taint.
            if exceptions is not None and may_raise(statement):
                exceptions.append(set(environment))
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(statement, ast.Raise):
                record(statement, environment)
                return None
            if isinstance(statement, ast.Return):
                record(statement, environment)
                if returns is not None:
                    returns.append(set(environment))
                return None
            if isinstance(statement, ast.Break):
                record(statement, environment)
                if breaks is not None:
                    breaks.append(set(environment))
                return None
            if isinstance(statement, ast.Continue):
                record(statement, environment)
                if continues is not None:
                    continues.append(set(environment))
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
                    environment = visit(
                        statement.body if statement.test.value else statement.orelse,
                        environment,
                        breaks=breaks,
                        continues=continues,
                        returns=returns,
                        exceptions=exceptions,
                    )
                else:
                    branches = [
                        visit(statement.body, set(environment), breaks=breaks, continues=continues, returns=returns, exceptions=exceptions),
                        visit(statement.orelse, set(environment), breaks=breaks, continues=continues, returns=returns, exceptions=exceptions),
                    ]
                    remaining = [branch for branch in branches if branch is not None]
                    environment = set().union(*remaining) if remaining else None
                if environment is None:
                    return None
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                expression = statement.test if isinstance(statement, ast.While) else statement.iter
                record(expression, environment)
                if isinstance(statement, ast.While) and isinstance(expression, ast.Constant) and not expression.value:
                    environment = visit(statement.orelse, environment, breaks=breaks, continues=continues, returns=returns, exceptions=exceptions)
                    if environment is None:
                        return None
                    continue
                branch = set(environment)
                iterable_tainted = tainted(expression, environment)
                literal_items = (
                    tuple(tainted(item, environment) for item in expression.elts)
                    if isinstance(statement, ast.For) and isinstance(expression, (ast.List, ast.Tuple))
                    and not any(isinstance(item, ast.Starred) for item in expression.elts)
                    else None
                )
                iteration = 0
                loop_breaks: list[set[str]] = []
                normal_exit: set[str] | None = set(environment)

                while literal_items is None or iteration < len(literal_items):
                    iteration_breaks: list[set[str]] = []
                    loop_continues: list[set[str]] = []
                    # Rechecking a while condition or obtaining/binding the next
                    # item happens with the loop-carried state, before the body.
                    if isinstance(statement, ast.While):
                        record(expression, branch)
                        header_may_raise = expression_may_raise(expression)
                    else:
                        header_may_raise = (
                            literal_items is None
                            or unpack_may_raise(statement.target, expression.elts[iteration])
                            or expression_may_raise(statement.target)
                        )
                    if exceptions is not None and header_may_raise:
                        exceptions.append(set(branch))
                    # Keep the fixed-point entry independent of assignments in the body.
                    body_entry = set(branch)
                    if not isinstance(statement, ast.While):
                        # Python binds the next item before every body execution.
                        assign(statement.target, literal_items[iteration] if literal_items is not None else iterable_tainted, body_entry)
                    body_exit = visit(statement.body, body_entry, breaks=iteration_breaks, continues=loop_continues, returns=returns, exceptions=exceptions)
                    loop_breaks.extend(iteration_breaks)
                    backedge = (body_exit or set()) | (set().union(*loop_continues) if loop_continues else set())
                    if literal_items is not None:
                        iteration += 1
                        normal_exit = backedge if body_exit is not None or loop_continues else None
                        if normal_exit is None:
                            break
                        branch = backedge
                    elif backedge <= branch:
                        normal_exit = set(environment) | backedge
                        break
                    else:
                        branch |= backedge

                is_infinite_loop = (
                    isinstance(statement, ast.While)
                    and isinstance(expression, ast.Constant)
                    and bool(expression.value)
                )
                if is_infinite_loop:
                    normal_exit = None
                if statement.orelse:
                    orelse_exit = (
                        visit(statement.orelse, normal_exit, breaks=breaks, continues=continues, returns=returns, exceptions=exceptions)
                        if normal_exit is not None
                        else None
                    )
                else:
                    orelse_exit = normal_exit
                post_loop_exits: list[set[str]] = []
                if orelse_exit is not None:
                    post_loop_exits.append(orelse_exit)
                post_loop_exits.extend(loop_breaks)
                environment = set().union(*post_loop_exits) if post_loop_exits else None
                if environment is None:
                    return None
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    record(item.context_expr, environment)
                    if item.optional_vars is not None:
                        assign(item.optional_vars, tainted(item.context_expr, environment), environment)
                body_exceptions: list[set[str]] = []
                body_breaks: list[set[str]] = []
                body_continues: list[set[str]] = []
                body_returns: list[set[str]] = []
                body_exit = visit(statement.body, environment, breaks=body_breaks, continues=body_continues, returns=body_returns, exceptions=body_exceptions)
                # __exit__/__aexit__ may suppress body exceptions, even without
                # an outer try. Return/break/continue cannot be suppressed.
                continuations = [body_exit] if body_exit is not None else []
                continuations.extend(body_exceptions)
                if exceptions is not None:
                    # Exiting the context can itself raise on any body exit.
                    # That new error escapes this manager; only body errors can
                    # be suppressed by this manager's exit method.
                    exceptions.extend(continuations)
                    exceptions.extend([*body_breaks, *body_continues, *body_returns])
                for states, target in ((body_breaks, breaks), (body_continues, continues), (body_returns, returns)):
                    if target is not None:
                        target.extend(states)
                environment = set().union(*continuations) if continuations else None
                if environment is None:
                    return None
            elif isinstance(statement, ast.Try):
                try_breaks: list[set[str]] = []
                try_continues: list[set[str]] = []
                try_returns: list[set[str]] = []
                try_exceptions: list[set[str]] = []
                body_exit = visit(statement.body, environment, breaks=try_breaks, continues=try_continues, returns=try_returns, exceptions=try_exceptions)
                # Handler entry is the state at an exceptional edge, not the state
                # before entering try. Exceptions from handlers/else escape this try.
                # A bare or unshadowed BaseException handler consumes every exception.
                # Errors raised by handlers or else are still collected below.
                catches_all = False
                for handler in statement.handlers:
                    # Unknown type evaluation can raise before a later catch-all.
                    if not valid_exception_type(handler.type):
                        break
                    if catches_base_exception(handler.type):
                        catches_all = True
                        break
                escaping_exceptions = [] if catches_all else list(try_exceptions)
                if body_exit is not None and statement.orelse:
                    body_exit = visit(statement.orelse, body_exit, breaks=try_breaks, continues=try_continues, returns=try_returns, exceptions=escaping_exceptions)
                branches = [body_exit]
                if try_exceptions:
                    handler_entry = set().union(*try_exceptions)
                    for handler in statement.handlers:
                        branches.append(visit(handler.body, handler_entry, breaks=try_breaks, continues=try_continues, returns=try_returns, exceptions=escaping_exceptions))
                normal_branches = [branch for branch in branches if branch is not None]
                normal_env = set().union(*normal_branches) if normal_branches else None

                if statement.finalbody:
                    def run_finally(env_set: set[str]) -> set[str] | None:
                        return visit(
                            statement.finalbody, env_set,
                            breaks=breaks, continues=continues, returns=returns, exceptions=exceptions,
                        )

                    normal_env = run_finally(normal_env) if normal_env is not None else None
                    for states, target in (
                        (try_breaks, breaks), (try_continues, continues),
                        (try_returns, returns), (escaping_exceptions, exceptions),
                    ):
                        for state in dict.fromkeys(map(frozenset, states)):
                            updated = run_finally(set(state))
                            if updated is not None and target is not None:
                                target.append(updated)
                else:
                    for states, target in (
                        (try_breaks, breaks), (try_continues, continues),
                        (try_returns, returns), (escaping_exceptions, exceptions),
                    ):
                        if target is not None:
                            target.extend(states)
                if normal_env is None:
                    return None
                environment = normal_env
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
