"""Bounded, non-executing analysis of command values reaching POSIX shell sinks.

Supported paths include straight-line code, bounded boolean branches and small
literal loops. Unknown execution semantics stop interpretation, never preserve a stale
SANITIZED state. Strings retain fragments until the actual shell argument is
known; quoting is supported only at ordinary, unquoted argument boundaries.
"""
from __future__ import annotations

import ast
import copy
import operator
import ntpath
import posixpath
import re
import symtable
import textwrap
from dataclasses import dataclass, field
from itertools import product
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
    stdlib_os_path: bool = False


def imported_binding(name: str) -> Binding:
    """Retain evidence that os.path came from an executed stdlib import."""
    return Binding(name, name == "os" or name == "os.path" or name.startswith("os.path."))


@dataclass(frozen=True)
class Choice:
    values: tuple[Any, ...]


@dataclass(frozen=True)
class NegatedTruth:
    value: Any


@dataclass(frozen=True)
class EnvironmentPredicate:
    """One external-state read; repeated reads need not agree."""
    source_path: str
    line: int
    ordinal: int
    operation: str


@dataclass(frozen=True)
class OwnedDictionary:
    identity: Any = field(default_factory=object)


@dataclass(frozen=True)
class OwnedDictionaryMethod:
    dictionary: OwnedDictionary
    name: str


def pure_dictionary_key(value: Any) -> bool:
    if value is None or type(value) in {bool, int, float} or isinstance(value, CommandString):
        return True
    return isinstance(value, tuple) and all(pure_dictionary_key(item) for item in value)


UNKNOWN = object()
NUMERIC_VALUE = object()
NUMERIC_TEXT = object()
OPAQUE_PRIMITIVE = object()


def primitive_value(value: Any) -> bool:
    """Values whose supported operations cannot dispatch user-defined hooks."""
    if value is NUMERIC_VALUE or value is NUMERIC_TEXT or value is OPAQUE_PRIMITIVE or value is None:
        return True
    if type(value) in {bool, int, float} or isinstance(value, (CommandString, EnvironmentPredicate)):
        return True
    if isinstance(value, NegatedTruth):
        return primitive_value(value.value)
    if isinstance(value, Choice):
        return all(primitive_value(item) for item in value.values)
    return isinstance(value, tuple) and all(primitive_value(item) for item in value)


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
    text = literal_text(value)
    return value is NUMERIC_TEXT or (text is not None and re.fullmatch(r"[+-]?[0-9]+", text) is not None)


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


class KnownPathFailure(UnsupportedSemantics):
    """This path raises before its normal successor; other paths remain live."""


class ForkCondition(Exception):
    """A helper needs the caller to keep an input's truth paths separate."""
    def __init__(self, value: Any):
        self.value = value


@dataclass
class BoundAssignment(ast.stmt):
    """Internal loop binding; the iterable was evaluated exactly once."""
    target: ast.AST
    value: Any


@dataclass
class ContinueAt(ast.stmt):
    """Internal lexical loop exit, with an explicit successor sequence."""
    statements: list[ast.stmt]


def loop_body(statements: list[ast.stmt], on_break: list[ast.stmt], on_continue: list[ast.stmt]) -> list[ast.stmt]:
    result = []
    for node in statements:
        if isinstance(node, ast.Break):
            result.append(ContinueAt(on_break))
        elif isinstance(node, ast.Continue):
            result.append(ContinueAt(on_continue))
        elif isinstance(node, ast.If):
            branch = copy.copy(node)
            branch.body = loop_body(node.body, on_break, on_continue)
            branch.orelse = loop_body(node.orelse, on_break, on_continue)
            result.append(branch)
        elif isinstance(node, ast.For):
            nested = copy.copy(node)
            # The nested body owns its exits, but its else suite runs outside
            # that loop: break/continue there target this enclosing loop.
            nested.orelse = loop_body(node.orelse, on_break, on_continue)
            result.append(nested)
        else:
            # Nested loops own their break/continue targets. Unsupported
            # compound statements remain unsupported by block().
            result.append(node)
    return result


def boolean_condition_names(node: ast.AST) -> set[str] | None:
    """Names in a pure truth expression, without assuming arbitrary calls pure."""
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Constant) and type(node.value) in {bool, int}:
        return set()
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return boolean_condition_names(node.operand)
    if isinstance(node, ast.BoolOp):
        groups = [boolean_condition_names(item) for item in node.values]
        if all(group is not None for group in groups):
            return set().union(*groups)
    return None


@dataclass
class Analysis:
    # Diagnostic coverage, never proof that every discovered helper executes.
    inspected_helpers: list[str] = field(default_factory=list)
    function_header_lines: tuple[int, ...] = ()
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
    def __init__(
        self,
        document: CodeDocument,
        helpers: tuple[CodeDocument, ...],
        depth: int = 0,
        condition_assumptions: dict[str, bool] | None = None,
        value_assumptions: dict[str, Any] | None = None,
    ):
        self.document = document
        self.helpers = helpers
        self.depth = depth
        self.condition_assumptions = condition_assumptions or {}
        self.value_assumptions = value_assumptions or {}
        self.result = Analysis()
        self.steps = 0
        self.external_read_count = 0
        self.env: dict[str, Any] = {}
        self.conditions: dict[str, tuple[Any, bool]] = {}
        self.value_conditions: dict[CommandString | EnvironmentPredicate, bool] = {}
        self.function = function_in(document)
        self.result.function_header_lines = tuple(range(
            min([self.function.lineno, *(item.lineno for item in self.function.decorator_list)]),
            self.function.lineno + 1,
        ))

    def run(self, arguments: dict[str, Any] | None = None) -> Analysis:
        try:
            if self.function.decorator_list or self.depth > 4:
                raise UnsupportedSemantics("decorated or recursive command construction")
            self.env = {name: Binding(name) for name in ("shlex", "subprocess", "os", "get_artifact_repository")}
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
                self.env[name] = imported_binding(binding)
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
                self.env[name] = imported_binding(f"{node.module}.{alias.name}")
            else:
                self.env[name] = imported_binding(alias.name if alias.asname else alias.name.split(".")[0])

    def _unpack_outcomes(self, target: ast.AST, value: Any) -> list[list[tuple]]:
        """Split one unpacking into per-path action lists (C2/T06).

        Each outcome is a list of actions: ("bind", name, value) for plain
        names, ("assign", target, value) for attribute/subscript leaves
        (applied with self.assign inside the fork, where it may fail that
        fork), ("raise", message) for alternatives that deterministically
        fail before anything after them executes. Alternatives keep their own
        bindings: elements from different alternatives are never mixed into
        commands that never existed. Statically malformed patterns (Starred
        and other non-destructurable targets) raise immediately, preserving
        historical whole-analysis behavior.
        """
        if isinstance(target, ast.Starred):
            raise UnsupportedSemantics("attribute or container mutation")
        if isinstance(target, ast.Name):
            return [[("bind", target.id, value)]]
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            return [[("assign", target, value)]]
        if isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, Choice):
                outcomes: list[list[tuple]] = []
                for alternative in value.values:
                    outcomes.extend(self._unpack_outcomes(target, alternative))
                return outcomes
            if isinstance(value, tuple):
                if len(value) != len(target.elts):
                    return [[("raise", "unresolved destructuring assignment")]]
                outcomes = [[]]
                for element, item in zip(target.elts, value):
                    outcomes = [
                        base + step
                        for base in outcomes
                        for step in self._unpack_outcomes(element, item)
                    ]
                return outcomes
            # Unlike a known tuple length error, unknown iteration can execute
            # user code. Keep this alternative as an effect gap, not a dead
            # branch silently discarded before merging successful alternatives.
            return [[("unsupported", "unresolved destructuring iteration effects")]]
        raise UnsupportedSemantics("attribute or container mutation")

    def _run_unpack_forks(
        self, target: ast.AST, value: Any, rest: list[ast.stmt],
    ) -> str:
        """Run the statements after a multi-shape unpacking path by path.

        Extends the branch-execution machinery: every viable alternative binds
        its own names and runs the remainder independently, so a failing
        alternative terminates without deleting the facts other paths
        established. Constructs met inside one fork but unsupported stay as
        issues while successful forks still count. Returns the merged signal
        for the remainder (the caller must return it directly).
        """
        viable = [
            actions for actions in self._unpack_outcomes(target, value)
            if not any(action[0] == "raise" for action in actions)
        ]
        if not viable:
            raise KnownPathFailure("unresolved destructuring assignment")
        return self._run_forks(viable, rest)

    def _run_forks(self, viable: list[list[tuple]], rest: list[ast.stmt]) -> str:
        saved_env = self.env
        saved_conditions = dict(self.conditions)
        saved_value_conditions = dict(self.value_conditions)
        saved_sinks = list(self.result.sinks)
        saved_returned = self.result.returned
        saved_return_line = self.result.return_line
        saved_issues = list(self.result.issues)
        companions: list[tuple] = []
        saved_read_count = self.external_read_count
        highest_read_count = saved_read_count
        for actions in viable:
            highest_read_count = max(highest_read_count, self.external_read_count)
            self.external_read_count = saved_read_count
            self.env = dict(saved_env)
            self.conditions = dict(saved_conditions)
            self.value_conditions = dict(saved_value_conditions)
            self.result.sinks = list(saved_sinks)
            self.result.returned = saved_returned
            self.result.return_line = saved_return_line
            self.result.issues = list(saved_issues)
            failure = None
            signal = "normal"
            for action in actions:
                if action[0] == "unsupported":
                    failure = action[1]
                    break
                elif action[0] == "bind":
                    _, name, val = action
                    self.env[name] = val
                elif action[0] == "assume":
                    _, name, truth = action
                    self.conditions[name] = (self.env.get(name, UNKNOWN), truth)
                    value = self.env.get(name, UNKNOWN)
                    if not self.assume_value(value, truth):
                        signal = "terminated"
                        break
                elif action[0] == "assume_value":
                    _, value, truth = action
                    if not self.assume_value(value, truth):
                        signal = "terminated"
                        break
                elif action[0] == "block":
                    try:
                        signal = self.block(action[1])
                    except KnownPathFailure:
                        signal = "terminated"
                        break
                    except UnsupportedSemantics as error:
                        failure = str(error)
                        break
                else:
                    try:
                        self.assign(action[1], action[2])
                    except UnsupportedSemantics as error:
                        failure = str(error)
                        break
            if failure is not None:
                companions.append(("failed", None, self.result.sinks[len(saved_sinks):],
                                   None, None, [*self.result.issues[len(saved_issues):], failure]))
                continue
            if signal == "terminated":
                companions.append((signal, None, self.result.sinks[len(saved_sinks):], None, None, []))
                continue
            try:
                if signal == "normal":
                    signal = self.block(rest)
            except KnownPathFailure:
                companions.append(("terminated", None, self.result.sinks[len(saved_sinks):], None, None, []))
                continue
            except UnsupportedSemantics as error:
                companions.append((
                    "aborted", None,
                    self.result.sinks[len(saved_sinks):],
                    None, None,
                    [*self.result.issues[len(saved_issues):], str(error)],
                ))
                continue
            companions.append((
                signal, dict(self.env),
                self.result.sinks[len(saved_sinks):],
                self.result.returned, self.result.return_line,
                self.result.issues[len(saved_issues):],
            ))
        self.external_read_count = max(highest_read_count, self.external_read_count)
        self.conditions = saved_conditions
        self.value_conditions = saved_value_conditions
        live = [item for item in companions if item[0] in ("normal", "return", "break", "continue")]
        if not live:
            first_error = next(
                (issue for item in companions for issue in item[5]),
                "unresolved destructuring assignment",
            )
            raise UnsupportedSemantics(first_error)
        self.result.sinks = saved_sinks + [sink for item in companions for sink in item[2]]
        merged_issues = list(saved_issues)
        for item in companions:
            for issue in item[5]:
                if issue not in merged_issues:
                    merged_issues.append(issue)
        self.result.issues = merged_issues
        # Join rule (C2): merge actual successor states only. Seeding from the
        # pre-fork environment would resurrect values every path overwrote, so
        # the seed is always the first live fork: names a fork never touched
        # still carry the saved value inside its own env copy. A saved value
        # joins the merge only through a path that genuinely still holds it.
        signals = {item[0] for item in live}
        if signals <= {"normal"}:
            env: dict[str, Any] = dict(live[0][1])
            for _, fork_env, _, _, _, _ in live[1:]:
                env = self._merge_envs(env, fork_env)
            self.env = env
            self.result.returned = saved_returned
            self.result.return_line = saved_return_line
            return "normal"
        if signals <= {"normal", "return"}:
            normals = [item for item in live if item[0] == "normal"]
            returns = [item for item in live if item[0] == "return"]
            if normals and returns:
                env = dict(normals[0][1])
                for _, fork_env, _, _, _, _ in normals[1:]:
                    env = self._merge_envs(env, fork_env)
                self.env = env
                self.result.returned = saved_returned
                self.result.return_line = saved_return_line
                return "normal"
            env = dict(returns[0][1])
            values = []
            line = None
            for position, (_, fork_env, _, fork_returned, fork_line, _) in enumerate(returns):
                if position:
                    env = self._merge_envs(env, fork_env)
                values.append(fork_returned)
                line = line if line is not None else fork_line
            self.env = env
            self.result.returned = choice(*values)
            self.result.return_line = line
            return "return"
        if len(signals) == 1:
            signal = next(iter(signals))
            env = dict(live[0][1])
            for _, fork_env, _, _, _, _ in live[1:]:
                env = self._merge_envs(env, fork_env)
            self.env = env
            self.result.returned = saved_returned
            self.result.return_line = saved_return_line
            return signal
        raise UnsupportedSemantics("branch termination is unresolved")

    def _needs_unpack_fork(self, target: ast.AST, value: Any) -> bool:
        """Whether one unpacking needs per-path execution (C2/T06).

        Only tuple/list targets unpacked from a Choice with at least one
        known-tuple alternative can proceed differently per path. Everything
        else keeps single-shot handling: plain tuples bind exactly (or abort
        the path on known length mismatch), unknown iteration retains a gap.
        """
        return (
            isinstance(target, (ast.Tuple, ast.List))
            and isinstance(value, Choice)
            and any(isinstance(alternative, tuple) for alternative in value.values)
        )

    def assign(self, target: ast.AST, value: Any) -> None:
        if isinstance(target, ast.Name):
            if value is UNKNOWN:
                self.conditions.pop(target.id, None)
            self.env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, Choice):
                alternatives = value.values
                if all(isinstance(item, tuple) and len(item) == len(target.elts) for item in alternatives):
                    for index, element in enumerate(target.elts):
                        self.assign(element, choice(*(item[index] for item in alternatives)))
                    return
                if alternatives and all(isinstance(item, tuple) for item in alternatives):
                    # Every possible value has a known length that cannot fill the
                    # targets: unpacking deterministically raises before any later
                    # sink executes, so the path must abort instead of minting an
                    # UNSANITIZED fact for unreachable code.
                    raise KnownPathFailure("unresolved destructuring assignment")
            elif isinstance(value, tuple):
                if len(target.elts) == len(value):
                    for element, item in zip(target.elts, value):
                        self.assign(element, item)
                    return
                raise KnownPathFailure("unresolved destructuring assignment")
            raise UnsupportedSemantics("unresolved destructuring iteration effects")
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            container = self.expression(target.value)
            if isinstance(target, ast.Subscript):
                key = self.expression(target.slice)
                # Only an allocated builtin dict has a known setter here.
                # UNKNOWN, module aliases and arbitrary objects do not acquire
                # purity merely because their return value is unused.
                if isinstance(container, OwnedDictionary) and pure_dictionary_key(key):
                    return
            raise UnsupportedSemantics("attribute or container mutation")
        else:
            raise UnsupportedSemantics("attribute or container mutation")

    def assume_value(self, value: Any, truth: bool) -> bool:
        while isinstance(value, NegatedTruth):
            value, truth = value.value, not truth
        if isinstance(value, (CommandString, EnvironmentPredicate)):
            if value in self.value_conditions and self.value_conditions[value] != truth:
                return False
            self.value_conditions[value] = truth
        return True

    def known_truth(self, value: Any) -> Any:
        if isinstance(value, EnvironmentPredicate):
            return self.value_conditions.get(value, UNKNOWN)
        if isinstance(value, NegatedTruth):
            truth = self.known_truth(value.value)
            return not truth if truth is not UNKNOWN else UNKNOWN
        if type(value) in {bool, int}:
            return bool(value)
        if value is None:
            return False
        if isinstance(value, tuple):
            return bool(value)
        if value is NUMERIC_TEXT:
            return True
        if value is OPAQUE_PRIMITIVE:
            return UNKNOWN
        if isinstance(value, CommandString):
            if any(part.kind == "quoted" or (part.kind == "literal" and part.text) for part in value.fragments):
                return True
            if value in self.value_conditions:
                return self.value_conditions[value]
            text = literal_text(value)
            if text is not None:
                return bool(text)
        return UNKNOWN

    def condition(self, node: ast.AST) -> Any:
        try:
            condition_key = ast.unparse(node)
        except Exception:
            condition_key = ""
        if condition_key in self.condition_assumptions:
            return self.condition_assumptions[condition_key]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            try:
                operand_key = ast.unparse(node.operand)
            except Exception:
                operand_key = ""
            if operand_key in self.condition_assumptions:
                return not self.condition_assumptions[operand_key]
        if isinstance(node, ast.Name):
            known = self.conditions.get(node.id)
            if known is not None and self.env.get(node.id, UNKNOWN) is known[0]:
                return known[1]
        value = self.expression(node)
        truth = self.known_truth(value)
        if truth is not UNKNOWN:
            return truth
        base = value
        while isinstance(base, NegatedTruth):
            base = base.value
        if isinstance(base, EnvironmentPredicate):
            raise ForkCondition(value)
        if (value is NUMERIC_VALUE or
                isinstance(base, CommandString) and any(part.kind == "unknown" for part in base.fragments)):
            raise UnsupportedSemantics("unresolved truth condition identity")
        if self.depth > 0 and isinstance(base, CommandString) and any(part.kind == "raw" for part in base.fragments):
            raise ForkCondition(value)
        if not primitive_value(value) and not isinstance(node, (ast.BoolOp, ast.Compare)):
            raise UnsupportedSemantics("unresolved truth-testing effects")
        return UNKNOWN

    def expression(self, node: ast.AST | None) -> Any:
        if node is None:
            return None
        try:
            value_key = ast.unparse(node)
        except Exception:
            value_key = ""
        if value_key in self.value_assumptions:
            return self.assumed_value(self.value_assumptions[value_key])
        if isinstance(node, ast.Constant):
            return literal(node.value) if isinstance(node.value, str) else node.value
        if isinstance(node, ast.Name):
            return self.env.get(node.id, UNKNOWN)
        if isinstance(node, ast.Attribute):
            if (
                isinstance(node.value, ast.Name)
                and node.value.id in {"_logger", "logger"}
                and self.document.import_aliases.get("logging") == "logging"
            ):
                return Binding(f"logging.Logger.{node.attr}")
            base = self.expression(node.value)
            if isinstance(base, Choice):
                if all(isinstance(item, Binding) for item in base.values):
                    return choice(*(Binding(f"{item.name}.{node.attr}", item.stdlib_os_path) for item in base.values))
                raise UnsupportedSemantics("unresolved attribute access effects")
            if isinstance(base, Binding):
                return Binding(f"{base.name}.{node.attr}", base.stdlib_os_path)
            if isinstance(base, OwnedDictionary):
                return OwnedDictionaryMethod(base, node.attr)
            raise UnsupportedSemantics("unresolved attribute access effects")
        if isinstance(node, (ast.Tuple, ast.List)):
            return tuple(self.expression(item) for item in node.elts)
        if isinstance(node, ast.Dict) and not node.keys:
            return OwnedDictionary()
        if isinstance(node, ast.Subscript):
            value = self.expression(node.value)
            index = self.expression(node.slice)
            if isinstance(value, tuple) and type(index) in {bool, int}:
                if -len(value) <= index < len(value):
                    return value[index]
                raise KnownPathFailure("known subscript index out of range")
            text = literal_text(value)
            if text is not None and type(index) in {bool, int}:
                if -len(text) <= index < len(text):
                    return literal(text[index])
                raise KnownPathFailure("known subscript index out of range")
            if isinstance(value, CommandString) and type(index) in {bool, int}:
                return unknown_string()
            raise UnsupportedSemantics("unresolved subscript protocol or bounds")
        if isinstance(node, ast.JoinedStr):
            value = literal("")
            for item in node.values:
                if isinstance(item, ast.FormattedValue):
                    component = self.expression(item.value)
                    if item.format_spec is not None:
                        self.expression(item.format_spec)
                    if not primitive_value(component):
                        raise UnsupportedSemantics("unresolved formatting effects")
                    if item.conversion != -1 or item.format_spec is not None:
                        raise UnsupportedSemantics("unsupported formatting conversion or specification")
                    if type(component) in {bool, int, float} or component is None:
                        component = literal(str(component))
                    elif not isinstance(component, (CommandString, Choice)):
                        component = unknown_string()
                else:
                    component = self.expression(item)
                value = concatenate(value, component)
            return value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.expression(node.left), self.expression(node.right)
            if isinstance(left, tuple) and isinstance(right, tuple):
                return left + right
            if not primitive_value(left) or not primitive_value(right):
                raise UnsupportedSemantics("unresolved addition effects")
            if type(left) in {bool, int, float} and type(right) in {bool, int, float}:
                return left + right
            left_text = isinstance(left, CommandString) or left is NUMERIC_TEXT
            right_text = isinstance(right, CommandString) or right is NUMERIC_TEXT
            left_number = type(left) in {bool, int, float} or left is NUMERIC_VALUE
            right_number = type(right) in {bool, int, float} or right is NUMERIC_VALUE
            if (left_text and right_number) or (right_text and left_number):
                raise KnownPathFailure("known incompatible addition operands")
            return concatenate(left, right)
        if isinstance(node, ast.IfExp):
            test = self.condition(node.test)
            if type(test) in {bool, int}:
                return self.expression(node.body if test else node.orelse)
            names = boolean_condition_names(node.test)
            for name in sorted(names or ()):
                if self.condition(ast.Name(id=name, ctx=ast.Load())) is UNKNOWN:
                    # Nested expressions need the same continuation split as
                    # top-level assignments; an unqualified Choice would lose
                    # the guard before a helper or a later caller condition.
                    raise ForkCondition(self.env[name])
            raise UnsupportedSemantics("unresolved conditional expression correlation")
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = self.expression(node.operand)
            if not primitive_value(value):
                raise UnsupportedSemantics("unresolved truth-testing effects")
            truth = self.known_truth(value)
            if isinstance(node.operand, ast.Name):
                known = self.conditions.get(node.operand.id)
                if known is not None and value is known[0]:
                    truth = known[1]
            if truth is not UNKNOWN:
                return not truth
            return NegatedTruth(value) if isinstance(value, (CommandString, NegatedTruth, EnvironmentPredicate)) else UNKNOWN
        if isinstance(node, ast.BoolOp):
            uncertain = False
            value = UNKNOWN
            for operand in node.values:
                value = self.condition(operand)
                if type(value) in {bool, int} or value is None:
                    if (isinstance(node.op, ast.And) and not value) or (isinstance(node.op, ast.Or) and value):
                        return UNKNOWN if uncertain else value
                else:
                    uncertain = True
            return UNKNOWN if uncertain else value
        if isinstance(node, ast.Compare):
            left = self.expression(node.left)
            uncertain = False
            comparisons = {ast.Eq: operator.eq, ast.NotEq: operator.ne,
                           ast.Lt: operator.lt, ast.LtE: operator.le,
                           ast.Gt: operator.gt, ast.GtE: operator.ge}
            for operation, comparator in zip(node.ops, node.comparators):
                right = self.expression(comparator)
                if not primitive_value(left) or not primitive_value(right):
                    raise UnsupportedSemantics("unresolved comparison effects")
                left_constant = literal_text(left) if isinstance(left, CommandString) else left
                right_constant = literal_text(right) if isinstance(right, CommandString) else right
                left_known = left is None or type(left) in {bool, int, float} or isinstance(left, CommandString) and left_constant is not None
                right_known = right is None or type(right) in {bool, int, float} or isinstance(right, CommandString) and right_constant is not None
                if left_known and right_known and type(operation) in comparisons:
                    try:
                        result = comparisons[type(operation)](left_constant, right_constant)
                    except TypeError as error:
                        raise KnownPathFailure("known incompatible comparison operands") from error
                    if not result:
                        return UNKNOWN if uncertain else False
                else:
                    uncertain = True
                left = right
            return UNKNOWN if uncertain else True
        if isinstance(node, ast.UnaryOp):
            value = self.expression(node.operand)
            operations = {ast.UAdd: operator.pos, ast.USub: operator.neg, ast.Invert: operator.invert}
            if type(value) in {bool, int} and type(node.op) in operations:
                return operations[type(node.op)](value)
            if value is NUMERIC_VALUE:
                return NUMERIC_VALUE
            raise UnsupportedSemantics("unresolved unary operation effects")
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
        if isinstance(binding, OwnedDictionaryMethod):
            return self.call_owned_dictionary_method(node, binding)
        if not isinstance(binding, Binding):
            self.result.unresolved_calls.append({"call": ast.unparse(node.func), "line": node.lineno, "source_path": self.document.path})
            if any(keyword.arg is None for keyword in node.keywords):
                raise UnsupportedSemantics("expanded call arguments")
            args = tuple(self.expression(arg) for arg in node.args)
            kwargs = {item.arg: self.expression(item.value) for item in node.keywords}
            raise UnsupportedSemantics("unresolved call effects: " + ast.unparse(node.func))
        return self.call_bound(node, binding)

    def call_owned_dictionary_method(self, node: ast.Call, binding: OwnedDictionaryMethod) -> Any:
        if any(keyword.arg is None for keyword in node.keywords):
            raise UnsupportedSemantics("expanded call arguments")
        args = tuple(self.expression(arg) for arg in node.args)
        kwargs = {item.arg: self.expression(item.value) for item in node.keywords}
        if binding.name == "get":
            if kwargs or len(args) not in {1, 2} or not pure_dictionary_key(args[0]):
                raise UnsupportedSemantics("unresolved dictionary get effects")
            if len(args) == 2:
                return choice(OPAQUE_PRIMITIVE, args[1])
            return OPAQUE_PRIMITIVE
        raise UnsupportedSemantics("unresolved dictionary method effects")

    def call_bound(self, node: ast.Call, binding: Binding) -> Any:
        if any(keyword.arg is None for keyword in node.keywords):
            raise UnsupportedSemantics("expanded call arguments")
        args = tuple(self.expression(arg) for arg in node.args)
        kwargs = {item.arg: self.expression(item.value) for item in node.keywords}
        if binding.name == "os.environ.copy" and not args and not kwargs:
            return OwnedDictionary()
        if binding.name in {
            "logging.Logger.debug", "logging.Logger.info", "logging.Logger.warning",
            "logging.Logger.error", "logging.Logger.exception", "logging.Logger.critical",
        }:
            if not all(primitive_value(arg) for arg in (*args, *kwargs.values())):
                raise UnsupportedSemantics("unresolved logging argument effects")
            return None
        if binding.name == "builtins.int" and len(args) == 1 and not kwargs:
            if not primitive_value(args[0]):
                raise UnsupportedSemantics("unresolved integer conversion effects")
            text = literal_text(args[0])
            if text is not None or type(args[0]) in {bool, int, float}:
                try:
                    return int(text if text is not None else args[0])
                except (ValueError, OverflowError) as error:
                    raise KnownPathFailure("known invalid integer conversion") from error
            if args[0] is None or isinstance(args[0], tuple):
                raise KnownPathFailure("known invalid integer conversion type")
            return NUMERIC_VALUE
        if binding.name == "builtins.str" and len(args) == 1 and not kwargs:
            if args[0] is NUMERIC_VALUE:
                return NUMERIC_TEXT
            if type(args[0]) in {bool, int, float} or args[0] is None:
                return literal(str(args[0]))
            if isinstance(args[0], CommandString) or args[0] is NUMERIC_TEXT:
                return args[0]
        if binding.name in {"os.path.exists", "posixpath.exists", "ntpath.exists"}:
            if len(args) != 1 or kwargs or not isinstance(args[0], CommandString):
                raise UnsupportedSemantics("filesystem predicate requires a builtin string path")
            # Model both normal boolean outcomes; never inspect this host's files.
            # Input PathLike hooks and unresolved bindings do not enter this summary.
            self.external_read_count += 1
            return EnvironmentPredicate(self.document.path, node.lineno,
                                        self.external_read_count, binding.name)
        path_module, _, path_operation = binding.name.rpartition(".")
        if (path_module == "os.path" and binding.stdlib_os_path
                and self.condition_assumptions.get("sys.platform.startswith('linux')") is True
                and self.condition_assumptions.get("is_windows()") is False):
            # os.path is posixpath only under the subject's explicit Linux,
            # non-Windows preconditions. The resolved Binding still has to be
            # the stdlib os.path; a rebound os/path never reaches this case.
            path_module = "posixpath"
        if path_module in {"posixpath", "ntpath"} and path_operation in {
            "basename", "dirname", "normpath", "join",
        }:
            # These lexical stdlib operations do not consult the host filesystem.
            # Only builtin-string abstract values qualify: PathLike protocols,
            # bytes and unresolved module bindings require separate semantics.
            if (kwargs or not args or (path_operation != "join" and len(args) != 1)
                    or not all(isinstance(arg, CommandString) for arg in args)):
                raise UnsupportedSemantics("unresolved lexical path argument semantics")
            texts = [literal_text(arg) for arg in args]
            if path_module == "posixpath" and path_operation == "join":
                # A later absolute POSIX component discards earlier path values;
                # arguments have already been evaluated, preserving their effects.
                resets = [i for i, text in enumerate(texts)
                          if text is not None and text.startswith("/")]
                if resets:
                    texts = texts[resets[-1]:]
            if all(text is not None for text in texts):
                module = posixpath if path_module == "posixpath" else ntpath
                return literal(getattr(module, path_operation)(*texts))
            # A lexical transform can erase source characters or shell quoting.
            # Preserve string type, but neither attacker control nor sanitation.
            return unknown_string()
        if binding.name == "shlex.quote":
            if len(args) != 1 or kwargs or not isinstance(args[0], CommandString):
                raise UnsupportedSemantics("unresolved quote argument semantics")
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
            self.result.unresolved_calls.append({"call": binding.name, "line": node.lineno, "source_path": self.document.path})
            if binding.name == "get_artifact_repository" or binding.name.endswith(".get_artifact_repository"):
                # The path/platform predicates do not identify the selected
                # repository implementation. A return-value-only summary
                # would invent both its returned value and its purity.
                raise UnsupportedSemantics("unverified artifact repository dispatch and download effects")
            raise UnsupportedSemantics("unresolved call effects: " + binding.name)
        self.result.inspected_helpers.append(matches[0].path)
        helper = Interpreter(
            matches[0],
            self.helpers,
            self.depth + 1,
            self.condition_assumptions,
            self.value_assumptions,
        )
        helper.value_conditions = dict(self.value_conditions)
        helper.external_read_count = self.external_read_count
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
        actual_nodes = {parameter.arg: argument for parameter, argument in zip(positional, node.args)}
        actual_nodes.update({item.arg: item.value for item in node.keywords})
        for parameter, argument in actual_nodes.items():
            if isinstance(argument, ast.Name):
                known = self.conditions.get(argument.id)
                if known is not None and values[parameter] is known[0]:
                    helper.conditions[parameter] = known
        defaults = dict(zip([parameter.arg for parameter in positional[-len(helper.function.args.defaults):]], helper.function.args.defaults))
        defaults.update({parameter.arg: value for parameter, value in zip(helper.function.args.kwonlyargs, helper.function.args.kw_defaults) if value is not None})
        for name in declared - values.keys():
            default = defaults.get(name)
            if not isinstance(default, ast.Constant):
                raise UnsupportedSemantics("missing or nonliteral default helper argument")
            values[name] = literal(default.value) if isinstance(default.value, str) else default.value
        result = helper.run(values)
        self.external_read_count = helper.external_read_count
        self.result.inspected_helpers.extend(result.inspected_helpers)
        self.result.unresolved_calls.extend(result.unresolved_calls)
        if result.sinks:
            self.result.sinks.extend(result.sinks)
        if result.issues:
            # A helper we cannot analyse may itself execute or transform a command, so
            # this stays fatal: it is what keeps an unsupported helper body from
            # supporting a SAFE vote.
            raise UnsupportedSemantics("helper: " + "; ".join(result.issues))
        return result.returned

    def assumed_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return literal(value)
        if value is None or type(value) in {bool, int, float}:
            return value
        return UNKNOWN

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
        requirements = [
            {"source_path": predicate.source_path, "line": predicate.line,
             "read": predicate.ordinal, "operation": predicate.operation, "value": truth}
            for predicate, truth in self.value_conditions.items()
            if isinstance(predicate, EnvironmentPredicate)
            and predicate.ordinal <= self.external_read_count
        ]
        if requirements and status == "UNSANITIZED":
            # An existential attack claim needs a witness for external premises.
            # Universal protection can still be checked across both outcomes.
            status = "AMBIGUOUS"
        fact = {"path": self.document.path, "line": node.lineno, "call": name, "status": status}
        if requirements:
            fact["environment_requirements"] = requirements
        if (status == "NOT_ESTABLISHED" and _protected_argv(command) and _contains_numeric_text(command)
                and kwargs.get("input") is None
                and all(kwargs.get(key, args[position] if len(args) > position else None) is None
                        for key, position in (("executable", 2), ("stdin", 3), ("preexec_fn", 7), ("cwd", 9), ("env", 10)))):
            # This is an affirmative argument-construction fact, not a claim
            # that merely failing to establish a shell makes execution safe.
            fact["numeric_argv"] = True
        self.result.sinks.append(fact)

    def _merge_envs(self, left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for key in left.keys() | right.keys():
            left_value = left.get(key, UNKNOWN)
            right_value = right.get(key, UNKNOWN)
            merged[key] = left_value if left_value == right_value else choice(left_value, right_value)
        return merged

    def block(self, statements: list[ast.stmt]) -> str:
        if self.depth > 0:
            return self._block(statements)
        # Interpretation has no real side effects. On an unresolved helper
        # input, restore this block's abstract state and replay each feasible
        # truth path, including the caller continuation. Never flatten the
        # helper's conditional return into an unrelated Choice.
        saved_env = dict(self.env)
        saved_conditions = dict(self.conditions)
        saved_values = dict(self.value_conditions)
        saved_read_count = self.external_read_count
        saved_result = copy.copy(self.result)
        saved_result.sinks = list(self.result.sinks)
        saved_result.issues = list(self.result.issues)
        saved_result.unresolved_calls = list(self.result.unresolved_calls)
        saved_result.inspected_helpers = list(self.result.inspected_helpers)
        try:
            return self._block(statements)
        except ForkCondition as condition:
            self.env = saved_env
            self.conditions = saved_conditions
            self.value_conditions = saved_values
            self.external_read_count = saved_read_count
            self.result = saved_result
            return self._run_forks([
                [("assume_value", condition.value, truth), ("block", statements)]
                for truth in (False, True)
            ], [])

    def _block(self, statements: list[ast.stmt]) -> str:
        for index, node in enumerate(statements):
            self.steps += 1
            if self.steps > 256:
                raise UnsupportedSemantics("bounded statement budget exceeded")
            if isinstance(node, ContinueAt):
                return self.block(node.statements)
            if isinstance(node, BoundAssignment):
                if self._needs_unpack_fork(node.target, node.value):
                    return self._run_unpack_forks(node.target, node.value, statements[index + 1:])
                self.assign(node.target, node.value)
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.Return)) and isinstance(node.value, ast.IfExp):
                # A conditional value and its successors belong to the same
                # path; flattening it to an unqualified Choice loses that link.
                left, right = copy.copy(node), copy.copy(node)
                left.value, right.value = node.value.body, node.value.orelse
                branch = ast.copy_location(ast.If(test=node.value.test, body=[left], orelse=[right]), node)
                return self.block([branch, *statements[index + 1:]])
            if isinstance(node, ast.Assign):
                value = self.expression(node.value)
                if len(node.targets) > 1 and isinstance(value, Choice):
                    # All targets receive the same evaluated RHS alternative.
                    # A tuple of repeated alternatives lets the unpacking
                    # machinery preserve that correlation across every target.
                    pattern = ast.Tuple(elts=node.targets, ctx=ast.Store())
                    alternatives = choice(*(tuple(item for _ in node.targets) for item in value.values))
                    return self._run_unpack_forks(pattern, alternatives, statements[index + 1:])
                if len(node.targets) == 1 and self._needs_unpack_fork(node.targets[0], value):
                    # Multi-shape unpacking runs the remainder path by path so
                    # one failing alternative cannot delete the facts other
                    # paths established (C2/T06).
                    return self._run_unpack_forks(node.targets[0], value, statements[index + 1:])
                for target in node.targets:
                    self.assign(target, value)
            elif isinstance(node, ast.AnnAssign):
                if node.value is not None:
                    value = self.expression(node.value)
                    if self._needs_unpack_fork(node.target, value):
                        return self._run_unpack_forks(node.target, value, statements[index + 1:])
                    self.assign(node.target, value)
            elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
                self.assign(node.target, concatenate(self.expression(node.target), self.expression(node.value)))
            elif isinstance(node, ast.Return):
                self.result.returned = self.expression(node.value)
                self.result.return_line = node.lineno
                return "return"
            elif isinstance(node, ast.If):
                test = self.condition(node.test)
                if type(test) in {bool, int}:
                    return self.block((node.body if test else node.orelse) + statements[index + 1:])
                # Keep each continuation with its own bindings and truth
                # assumption. Merging values before later conditions creates
                # combinations no concrete execution can take.
                guard = node.test
                inverted = False
                while isinstance(guard, ast.UnaryOp) and isinstance(guard.op, ast.Not):
                    guard = guard.operand
                    inverted = not inverted
                if isinstance(guard, ast.Name):
                    return self._run_forks([
                        [("assume", guard.id, not inverted),
                         ("block", node.body + statements[index + 1:])],
                        [("assume", guard.id, inverted),
                         ("block", node.orelse + statements[index + 1:])],
                    ], [])
                names = boolean_condition_names(node.test)
                if names:
                    unresolved = sorted(name for name in names
                                        if type(self.condition(ast.Name(id=name, ctx=ast.Load()))) not in {bool, int})
                    if len(unresolved) > 4:
                        raise UnsupportedSemantics("bounded boolean path limit exceeded")
                    if unresolved:
                        return self._run_forks([
                            [("assume", name, truth) for name, truth in zip(unresolved, values)]
                            + [("block", statements[index:])]
                            for values in product((False, True), repeat=len(unresolved))
                        ], [])
                raise UnsupportedSemantics("unresolved condition correlation")
            elif isinstance(node, ast.For) and isinstance(node.iter, (ast.List, ast.Tuple)):
                values = self.expression(node.iter)
                if len(values) > 16:
                    raise UnsupportedSemantics("bounded literal loop limit exceeded")
                after_loop = statements[index + 1:]
                remaining = node.orelse + after_loop
                for value in reversed(values):
                    body = loop_body(node.body, after_loop, remaining)
                    remaining = [BoundAssignment(node.target, value), *body, *remaining]
                return self.block(remaining)
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


def analyze_command(
    document: CodeDocument,
    helpers: tuple[CodeDocument, ...] = (),
    *,
    entry_boolean_arguments: dict[str, bool] | None = None,
    entry_condition_assumptions: dict[str, bool] | None = None,
    entry_value_assumptions: dict[str, Any] | None = None,
    input_parameters: tuple[str, ...] | None = None,
) -> Analysis:
    try:
        interpreter = Interpreter(
            document,
            helpers,
            condition_assumptions=entry_condition_assumptions,
            value_assumptions=entry_value_assumptions,
        )
        arguments = None
        if input_parameters is not None or entry_boolean_arguments:
            parameters = (*interpreter.function.args.posonlyargs, *interpreter.function.args.args, *interpreter.function.args.kwonlyargs)
            names = {parameter.arg for parameter in parameters}
            if input_parameters is not None and set(input_parameters) - names:
                raise UnsupportedSemantics("invalid declared entry input parameters")
            # A symbolic helper diagnostic can range over all string arguments.
            # Candidate analysis instead supplies its explicit source set. Other
            # arguments stay UNKNOWN, including their type and possible effects.
            arguments = {
                name: CommandString((Fragment("raw", name),))
                if input_parameters is None or name in input_parameters else UNKNOWN
                for name in names
            }
            if entry_boolean_arguments:
                if entry_boolean_arguments.keys() - names or any(type(value) is not bool for value in entry_boolean_arguments.values()):
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
