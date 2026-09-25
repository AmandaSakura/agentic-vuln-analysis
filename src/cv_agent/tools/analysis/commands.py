"""Bounded, non-executing analysis of command values reaching POSIX shell sinks.

Supported paths are straight-line code, constant branches and small literal
loops. Unknown execution semantics stop interpretation, never preserve a stale
SANITIZED state. Strings retain fragments until the actual shell argument is
known; quoting is supported only at ordinary, unquoted argument boundaries.
"""
from __future__ import annotations

import ast
import re
import symtable
import textwrap
from dataclasses import dataclass, field
from typing import Any

from cv_agent.domain.types import CodeDocument


@dataclass(frozen=True)
class Fragment:
    kind: str
    text: str = ""


@dataclass(frozen=True)
class CommandString:
    fragments: tuple[Fragment, ...]


@dataclass(frozen=True)
class Binding:
    name: str


@dataclass(frozen=True)
class Choice:
    values: tuple[Any, ...]


UNKNOWN = object()
NUMERIC_VALUE = object()
NUMERIC_TEXT = object()


def choice(*values: Any) -> Any:
    flattened: list[Any] = []
    for value in values:
        if isinstance(value, Choice):
            flattened.extend(value.values)
        else:
            flattened.append(value)
    unique: list[Any] = []
    for value in flattened:
        if not any(value is current or value == current for current in unique):
            unique.append(value)
    if len(unique) == 1:
        return unique[0]
    return Choice(tuple(unique))


def literal(text: str) -> CommandString:
    return CommandString((Fragment("literal", text),))


def unknown_string() -> CommandString:
    return CommandString((Fragment("unknown"),))


def contains_command_string(value: Any) -> bool:
    if isinstance(value, CommandString):
        return True
    if isinstance(value, Choice):
        return any(contains_command_string(item) for item in value.values)
    if isinstance(value, tuple):
        return any(contains_command_string(item) for item in value)
    return False


def concatenate(left: Any, right: Any) -> Any:
    if isinstance(left, Choice):
        return choice(*(concatenate(value, right) for value in left.values))
    if isinstance(right, Choice):
        return choice(*(concatenate(left, value) for value in right.values))
    if isinstance(left, CommandString) and isinstance(right, CommandString):
        return CommandString(left.fragments + right.fragments)
    return UNKNOWN


def literal_text(value: Any) -> str | None:
    if isinstance(value, Choice):
        texts = {literal_text(item) for item in value.values}
        return texts.pop() if len(texts) == 1 and None not in texts else None
    if isinstance(value, CommandString) and all(part.kind == "literal" for part in value.fragments):
        return "".join(part.text for part in value.fragments)
    return None


def _literal_or_numeric_text(value: Any) -> bool:
    if isinstance(value, Choice):
        return all(_literal_or_numeric_text(item) for item in value.values)
    return value is NUMERIC_TEXT or literal_text(value) is not None


def _protected_argv(value: Any) -> bool:
    if isinstance(value, Choice):
        return all(_protected_argv(item) for item in value.values)
    return (isinstance(value, tuple) and bool(value)
            and literal_text(value[0]) not in {None, ""}
            and all(_literal_or_numeric_text(item) for item in value[1:]))


def _contains_numeric_text(value: Any) -> bool:
    if isinstance(value, Choice):
        return any(_contains_numeric_text(item) for item in value.values)
    if isinstance(value, tuple):
        return any(_contains_numeric_text(item) for item in value)
    return value is NUMERIC_TEXT


def _status_join(statuses: set[str]) -> str:
    if "UNSANITIZED" in statuses:
        return "UNSANITIZED"
    if "AMBIGUOUS" in statuses:
        return "AMBIGUOUS"
    if "NOT_ESTABLISHED" in statuses or not statuses:
        return "NOT_ESTABLISHED"
    return "SANITIZED"


def shell_status(value: Any) -> str:
    if isinstance(value, Choice):
        return _status_join({shell_status(item) for item in value.values})
    if not isinstance(value, CommandString):
        return "AMBIGUOUS"
    # Merge adjacent constants so quote/word boundaries survive concatenation.
    parts: list[Fragment] = []
    for part in value.fragments:
        if part.kind == "literal" and parts and parts[-1].kind == "literal":
            parts[-1] = Fragment("literal", parts[-1].text + part.text)
        else:
            parts.append(part)
    constants = " ".join(part.text for part in parts if part.kind == "literal")
    if re.search(r"[^\w\s/.,:=+%\-]", constants) or "\n" in constants or "\r" in constants:
        return "AMBIGUOUS"
    if re.search(r"\b(?:eval|bash|sh|zsh|dash|ksh)\b", constants):
        return "AMBIGUOUS"  # Secondary shell interpretation is outside this model.
    if any(part.kind == "unknown" for part in parts):
        return "AMBIGUOUS"
    if any(part.kind == "raw" for part in parts):
        return "UNSANITIZED"
    if any(part.kind == "quoted" for part in parts):
        prefix = parts[0].text.split() if parts and parts[0].kind == "literal" else []
        if prefix and prefix[0] == "exec":
            prefix = prefix[1:]
        if not prefix or prefix[0] in {"exec", "command", "env"} or prefix[0].startswith("-") or "=" in prefix[0]:
            return "AMBIGUOUS"  # A quoted executable name is not an escaped argument.
    for index, part in enumerate(parts):
        if part.kind != "quoted":
            continue
        before = parts[index - 1] if index else None
        after = parts[index + 1] if index + 1 < len(parts) else None
        # A quoted argument cannot be embedded in another word or command name.
        if before is None or before.kind != "literal" or not before.text or before.text[-1] not in " \t":
            return "AMBIGUOUS"
        if after is not None and (after.kind != "literal" or (after.text and after.text[0] not in " \t")):
            return "AMBIGUOUS"
    return "SANITIZED"


class UnsupportedSemantics(Exception):
    """An explicit boundary of the interpreter, not an execution failure."""


@dataclass
class Analysis:
    unresolved_calls: list[dict[str, Any]] = field(default_factory=list)
    returned: Any = UNKNOWN
    return_line: int | None = None
    sinks: list[dict[str, Any]] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)


def function_in(document: CodeDocument) -> ast.FunctionDef | ast.AsyncFunctionDef:
    tree = ast.parse(textwrap.dedent(document.text))
    functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if len(functions) != 1:
        raise UnsupportedSemantics("one candidate function is required")
    return functions[0]


class Interpreter:
    def __init__(self, document: CodeDocument, helpers: tuple[CodeDocument, ...], depth: int = 0):
        self.document = document
        self.helpers = helpers
        self.depth = depth
        self.result = Analysis()
        self.steps = 0
        self.env: dict[str, Any] = {}
        self.function = function_in(document)

    def run(self, arguments: dict[str, Any] | None = None) -> Analysis:
        try:
            if self.function.decorator_list or self.depth > 4:
                raise UnsupportedSemantics("decorated or recursive command construction")
            self.env = {name: Binding(name) for name in ("shlex", "subprocess", "os")}
            for helper in self.helpers:
                for definition in helper.defines:
                    pieces = definition.split(".")
                    if len(pieces) > 1:
                        self.env.setdefault(pieces[-2], Binding(".".join(pieces[:-1])))
                    if len(pieces) == 1:
                        self.env.setdefault(definition, Binding(definition))
            for name in ("int", "str"):
                if name not in self.document.module_bindings:
                    self.env.setdefault(name, Binding(f"builtins.{name}"))
            for name, binding in self.document.import_aliases.items():
                self.env[name] = Binding(binding)
            for name in self.document.module_rebindings:
                self.env[name] = UNKNOWN
            # An import/rebinding present in a full source document also applies.
            tree = ast.parse(textwrap.dedent(self.document.text))
            for node in tree.body:
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    self.import_binding(node)
                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        self.assign(target, UNKNOWN)
            symbols = symtable.symtable(ast.unparse(self.function), self.document.path, "exec").get_children()[0]
            for symbol in symbols.get_symbols():
                if symbol.is_local():
                    self.env[symbol.get_name()] = UNKNOWN
            parameters = (*self.function.args.posonlyargs, *self.function.args.args, *self.function.args.kwonlyargs)
            for parameter in parameters:
                self.env[parameter.arg] = (
                    arguments.get(parameter.arg, UNKNOWN) if arguments is not None
                    else CommandString((Fragment("raw", parameter.arg),))
                )
            signal = self.block(self.function.body)
            if signal not in {"return", "normal"}:
                raise UnsupportedSemantics("unresolved function termination")
        except (UnsupportedSemantics, SyntaxError) as error:
            self.result.returned = UNKNOWN
            self.result.issues.append(str(error))
        return self.result

    def import_binding(self, node: ast.Import | ast.ImportFrom) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            if isinstance(node, ast.ImportFrom):
                if node.level or alias.name == "*":
                    raise UnsupportedSemantics("relative or wildcard import")
                name = alias.asname or alias.name
                self.env[name] = Binding(f"{node.module}.{alias.name}")
            else:
                self.env[name] = Binding(alias.name if alias.asname else alias.name.split(".")[0])

    def assign(self, target: ast.AST, value: Any) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, Choice):
                alternatives = value.values
                if not all(isinstance(item, tuple) and len(item) == len(target.elts) for item in alternatives):
                    raise UnsupportedSemantics("unresolved destructuring assignment")
                for index, element in enumerate(target.elts):
                    self.assign(element, choice(*(item[index] for item in alternatives)))
                return
            if not isinstance(value, tuple) or len(target.elts) != len(value):
                raise UnsupportedSemantics("unresolved destructuring assignment")
            for element, item in zip(target.elts, value):
                self.assign(element, item)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            root = target.value if isinstance(target, ast.Attribute) else target.value
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name):
                current = self.env.get(root.id, UNKNOWN)
                if root.id not in {"shlex", "subprocess", "os"} and not isinstance(
                    current, (CommandString, Choice)
                ):
                    return
            raise UnsupportedSemantics("attribute or container mutation")
        else:
            raise UnsupportedSemantics("attribute or container mutation")

    def expression(self, node: ast.AST | None) -> Any:
        if node is None:
            return None
        if isinstance(node, ast.Constant):
            return literal(node.value) if isinstance(node.value, str) else node.value
        if isinstance(node, ast.Name):
            return self.env.get(node.id, UNKNOWN)
        if isinstance(node, ast.Attribute):
            base = self.expression(node.value)
            if isinstance(base, Choice):
                return choice(*(
                    Binding(f"{item.name}.{node.attr}") if isinstance(item, Binding) else UNKNOWN
                    for item in base.values
                ))
            return Binding(f"{base.name}.{node.attr}") if isinstance(base, Binding) else UNKNOWN
        if isinstance(node, (ast.Tuple, ast.List)):
            return tuple(self.expression(item) for item in node.elts)
        if isinstance(node, ast.Dict) and not node.keys:
            return UNKNOWN  # An unused environment return component, not a command.
        if isinstance(node, ast.Subscript):
            value = self.expression(node.value)
            index = self.expression(node.slice)
            if isinstance(value, tuple) and type(index) is int and -len(value) <= index < len(value):
                return value[index]
            return UNKNOWN
        if isinstance(node, ast.JoinedStr):
            value = literal("")
            for item in node.values:
                if isinstance(item, ast.FormattedValue):
                    if item.conversion != -1 or item.format_spec is not None:
                        return UNKNOWN
                    component = self.expression(item.value)
                else:
                    component = self.expression(item)
                value = concatenate(value, component)
            return value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return concatenate(self.expression(node.left), self.expression(node.right))
        if isinstance(node, ast.IfExp):
            test = self.expression(node.test)
            if type(test) in {bool, int}:
                return self.expression(node.body if test else node.orelse)
            return choice(self.expression(node.body), self.expression(node.orelse))
        if isinstance(node, (ast.BoolOp, ast.Compare, ast.UnaryOp)):
            return UNKNOWN
        if isinstance(node, ast.Call):
            return self.call(node)
        raise UnsupportedSemantics(f"unsupported expression: {type(node).__name__}")

    def call(self, node: ast.Call) -> Any:
        binding = self.expression(node.func)
        if isinstance(binding, Choice):
            results: list[Any] = []
            for item in binding.values:
                if isinstance(item, Binding):
                    result = self.call_bound(node, item)
                    results.append(result)
                else:
                    results.append(UNKNOWN)
            return choice(*results) if results else UNKNOWN
        if not isinstance(binding, Binding):
            self.result.unresolved_calls.append({"call": ast.unparse(node.func), "line": node.lineno})
            if any(keyword.arg is None for keyword in node.keywords):
                raise UnsupportedSemantics("expanded call arguments")
            args = tuple(self.expression(arg) for arg in node.args)
            kwargs = {item.arg: self.expression(item.value) for item in node.keywords}
            return unknown_string() if contains_command_string((*args, *kwargs.values())) else UNKNOWN
        return self.call_bound(node, binding)

    def call_bound(self, node: ast.Call, binding: Binding) -> Any:
        if any(keyword.arg is None for keyword in node.keywords):
            raise UnsupportedSemantics("expanded call arguments")
        args = tuple(self.expression(arg) for arg in node.args)
        kwargs = {item.arg: self.expression(item.value) for item in node.keywords}
        if binding.name == "builtins.int" and len(args) == 1 and not kwargs:
            return NUMERIC_VALUE
        if binding.name == "builtins.str" and len(args) == 1 and not kwargs and args[0] is NUMERIC_VALUE:
            return NUMERIC_TEXT
        if binding.name == "shlex.quote":
            if len(args) != 1 or kwargs or not isinstance(args[0], CommandString):
                return UNKNOWN
            return CommandString((Fragment("quoted"),))
        if binding.name in {
            "subprocess.Popen", "subprocess.run", "subprocess.call",
            "subprocess.check_call", "subprocess.check_output",
            "subprocess.getoutput", "subprocess.getstatusoutput", "os.system", "os.popen",
        }:
            self.record_sink(node, binding.name, args, kwargs)
            return UNKNOWN
        matches = [helper for helper in self.helpers if binding.name in helper.defines]
        if len(matches) != 1:
            self.result.unresolved_calls.append({"call": binding.name, "line": node.lineno})
            return unknown_string() if contains_command_string((*args, *kwargs.values())) else UNKNOWN
        helper = Interpreter(matches[0], self.helpers, self.depth + 1)
        if isinstance(helper.function, ast.AsyncFunctionDef):
            raise UnsupportedSemantics("an unawaited async helper does not return command values")
        positional = (*helper.function.args.posonlyargs, *helper.function.args.args)
        if len(args) > len(positional) or helper.function.args.vararg or helper.function.args.kwarg:
            raise UnsupportedSemantics("unsupported helper argument binding")
        values = {parameter.arg: value for parameter, value in zip(positional, args)}
        positional_only = {parameter.arg for parameter in helper.function.args.posonlyargs}
        declared = {parameter.arg for parameter in (*positional, *helper.function.args.kwonlyargs)}
        if values.keys() & kwargs.keys() or kwargs.keys() - declared or kwargs.keys() & positional_only:
            raise UnsupportedSemantics("invalid helper argument binding")
        values.update(kwargs)
        defaults = dict(zip([parameter.arg for parameter in positional[-len(helper.function.args.defaults):]], helper.function.args.defaults))
        defaults.update({parameter.arg: value for parameter, value in zip(helper.function.args.kwonlyargs, helper.function.args.kw_defaults) if value is not None})
        for name in declared - values.keys():
            default = defaults.get(name)
            if not isinstance(default, ast.Constant):
                raise UnsupportedSemantics("missing or nonliteral default helper argument")
            values[name] = literal(default.value) if isinstance(default.value, str) else default.value
        result = helper.run(values)
        if result.sinks:
            self.result.sinks.extend(result.sinks)
        if result.issues:
            raise UnsupportedSemantics("helper: " + "; ".join(result.issues))
        return result.returned

    def record_sink(self, node: ast.Call, name: str, args: tuple, kwargs: dict) -> None:
        command_keyword = {
            "os.system": "command", "os.popen": "cmd",
            "subprocess.getoutput": "cmd", "subprocess.getstatusoutput": "cmd",
        }.get(name, "args")
        command = args[0] if args else kwargs.get(command_keyword, UNKNOWN)
        shell = kwargs.get("shell", args[8] if len(args) > 8 else False)
        status = "NOT_ESTABLISHED"
        if isinstance(command, Choice):
            statuses: set[str] = set()
            for item in command.values:
                self.record_sink(node, name, (item, *args[1:]), kwargs)
                statuses.add(self.result.sinks.pop()["status"])
            status = _status_join(statuses)
        elif name in {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"} or shell is True:
            status = shell_status(command) if not isinstance(command, tuple) else "AMBIGUOUS"
        elif shell is not False:
            status = "AMBIGUOUS"
        elif isinstance(command, tuple):
            executable = literal_text(command[0]) if command else None
            if executable is None:
                status = "AMBIGUOUS"
            elif executable.rsplit("/", 1)[-1] in {"bash", "sh", "dash", "zsh", "ksh"}:
                status = (
                    shell_status(command[2]) if len(command) == 3 and literal_text(command[1]) == "-c"
                    else "AMBIGUOUS"
                )
        elif command is UNKNOWN:
            status = "AMBIGUOUS"
        fact = {"path": self.document.path, "line": node.lineno, "call": name, "status": status}
        if (status == "NOT_ESTABLISHED" and _protected_argv(command) and _contains_numeric_text(command)
                and kwargs.get("input") is None
                and all(kwargs.get(key, args[position] if len(args) > position else None) is None
                        for key, position in (("executable", 2), ("stdin", 3), ("preexec_fn", 7), ("cwd", 9), ("env", 10)))):
            # This is an affirmative argument-construction fact, not a claim
            # that merely failing to establish a shell makes execution safe.
            fact["numeric_argv"] = True
        self.result.sinks.append(fact)

    def _run_branch(self, statements: list[ast.stmt], env: dict[str, Any]):
        saved_env = self.env
        saved_sinks = list(self.result.sinks)
        saved_returned = self.result.returned
        saved_return_line = self.result.return_line
        self.env = dict(env)
        self.result.returned = UNKNOWN
        self.result.return_line = None
        signal = self.block(statements)
        branch_env = dict(self.env)
        branch_sinks = self.result.sinks[len(saved_sinks):]
        branch_returned = self.result.returned
        branch_return_line = self.result.return_line
        self.env = saved_env
        self.result.sinks = saved_sinks
        self.result.returned = saved_returned
        self.result.return_line = saved_return_line
        return signal, branch_env, branch_sinks, branch_returned, branch_return_line

    def _merge_envs(self, left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for key in left.keys() | right.keys():
            left_value = left.get(key, UNKNOWN)
            right_value = right.get(key, UNKNOWN)
            merged[key] = left_value if left_value == right_value else choice(left_value, right_value)
        return merged

    def block(self, statements: list[ast.stmt]) -> str:
        for node in statements:
            self.steps += 1
            if self.steps > 256:
                raise UnsupportedSemantics("bounded statement budget exceeded")
            if isinstance(node, ast.Assign):
                value = self.expression(node.value)
                for target in node.targets:
                    self.assign(target, value)
            elif isinstance(node, ast.AnnAssign):
                if node.value is not None:
                    self.assign(node.target, self.expression(node.value))
            elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
                self.assign(node.target, concatenate(self.expression(node.target), self.expression(node.value)))
            elif isinstance(node, ast.Return):
                self.result.returned = self.expression(node.value)
                self.result.return_line = node.lineno
                return "return"
            elif isinstance(node, ast.If):
                test = self.expression(node.test)
                if type(test) in {bool, int}:
                    signal = self.block(node.body if test else node.orelse)
                    if signal != "normal":
                        return signal
                    continue
                base_env = dict(self.env)
                body = self._run_branch(node.body, base_env)
                orelse = self._run_branch(node.orelse, base_env)
                body_signal, body_env, body_sinks, body_returned, body_line = body
                else_signal, else_env, else_sinks, else_returned, else_line = orelse
                self.result.sinks.extend([*body_sinks, *else_sinks])
                if body_signal == "return" and else_signal == "return":
                    self.env = self._merge_envs(body_env, else_env)
                    self.result.returned = choice(body_returned, else_returned)
                    self.result.return_line = body_line or else_line
                    return "return"
                if body_signal == "normal" and else_signal == "normal":
                    self.env = self._merge_envs(body_env, else_env)
                    continue
                if body_signal == "normal" and else_signal == "return":
                    self.env = body_env
                    continue
                if body_signal == "return" and else_signal == "normal":
                    self.env = else_env
                    continue
                raise UnsupportedSemantics("branch termination is unresolved")
            elif isinstance(node, ast.For) and isinstance(node.iter, (ast.List, ast.Tuple)):
                values = self.expression(node.iter)
                if len(values) > 16:
                    raise UnsupportedSemantics("bounded literal loop limit exceeded")
                signal = "normal"
                for value in values:
                    self.assign(node.target, value)
                    signal = self.block(node.body)
                    if signal in {"return", "break"}:
                        break
                if signal == "return":
                    return signal
                if signal != "break":
                    signal = self.block(node.orelse)
                    if signal != "normal":
                        return signal
            elif isinstance(node, ast.Break):
                return "break"
            elif isinstance(node, ast.Continue):
                return "continue"
            elif isinstance(node, ast.Raise):
                if node.exc is not None:
                    self.expression(node.exc)
                return "return"
            elif isinstance(node, ast.Expr):
                self.expression(node.value)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                self.import_binding(node)
            elif isinstance(node, ast.Pass):
                pass
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.decorator_list:
                if (
                    node.args.defaults or any(node.args.kw_defaults) or node.returns is not None
                    or any(isinstance(arg, ast.arg) and arg.annotation is not None for arg in ast.walk(node.args))
                ):
                    raise UnsupportedSemantics("nested defaults or annotations can execute code")
                self.env[node.name] = UNKNOWN
            else:
                raise UnsupportedSemantics(f"unsupported statement: {type(node).__name__}")
        return "normal"


def analyze_command(document: CodeDocument, helpers: tuple[CodeDocument, ...] = (), *, entry_boolean_arguments: dict[str, bool] | None = None) -> Analysis:
    try:
        interpreter = Interpreter(document, helpers)
        arguments = None
        if entry_boolean_arguments:
            parameters = (*interpreter.function.args.posonlyargs, *interpreter.function.args.args, *interpreter.function.args.kwonlyargs)
            arguments = {parameter.arg: CommandString((Fragment("raw", parameter.arg),)) for parameter in parameters}
            if entry_boolean_arguments.keys() - arguments.keys() or any(type(value) is not bool for value in entry_boolean_arguments.values()):
                raise UnsupportedSemantics("invalid declared entry boolean arguments")
            arguments.update(entry_boolean_arguments)
        return interpreter.run(arguments)
    except (SyntaxError, UnsupportedSemantics) as error:
        return Analysis(issues=[str(error)])


def returned_command(analysis: Analysis) -> Any:
    if analysis.issues:
        return UNKNOWN
    result = analysis.returned
    return result[0] if isinstance(result, tuple) and result else result


def command_status(analysis: Analysis) -> str:
    if analysis.issues:
        return "AMBIGUOUS"
    return _status_join({sink["status"] for sink in analysis.sinks})
