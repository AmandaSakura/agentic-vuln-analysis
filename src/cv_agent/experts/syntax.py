"""Textual expressions and control-flow syntax for deterministic Java experts."""
from __future__ import annotations

from collections.abc import Sequence
import ast
import re

from ..java_lexical import (
    COLLECTION_GET_RE,
    SINK_VALUE_NAMES,
    STRING_LITERAL_RE,
    value_identifiers as _value_identifiers,
)
from ..types import Evidence


JAVA_TYPED_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:final\s+)?(?:[\w.$<>\[\],?]+\s+)+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?::=|=(?!=))\s*"
)


COLLECTION_ADD_RE = re.compile(
    r"\b(?P<name>[A-Za-z_$][\w$]*)\.add\s*\((?P<value>[^;]*)\)"
)


RETURN_RE = re.compile(r"\breturn\s+(?P<value>.+?)\s*;")


LEADING_CAST_RE = re.compile(r"^\s*(?:\([\w.$<>\[\],?]+\)\s*)+")


IF_RE = re.compile(r"^\s*if\s*\((?P<condition>.*)\)\s*(?P<trailing>.*)$")


ELSE_RE = re.compile(r"^\s*else\b\s*(?P<trailing>.*)$")


SWITCH_RE = re.compile(r"^\s*switch\s*\((?P<value>.*)\)\s*\{\s*$")


CASE_RE = re.compile(r"^\s*case\s+(?P<value>'(?:\\.|[^'\\])'|\"(?:\\.|[^\"\\])*\")\s*:\s*$")


DEFAULT_RE = re.compile(r"^\s*default\s*:\s*$")


CHAR_AT_RE = re.compile(
    r"^(?P<name>[A-Za-z_$][\w$]*)\.charAt\((?P<index>\d+)\)$"
)


TERNARY_RE = re.compile(
    r"^(?P<condition>.+?)\?(?P<when_true>.+):(?P<when_false>.+)$"
)


def _contains_identifier(text: str, names: Sequence[str] | set[str]) -> bool:
    return any(re.search(rf"\b{re.escape(name)}\b", text) for name in names)


def _contains_clean_sink_value(text: str, clean: set[str]) -> bool:
    return any(
        name.casefold() in SINK_VALUE_NAMES
        and re.search(rf"\b{re.escape(name)}\b", text)
        for name in clean
    )


def _numeric_expression(value: str, numeric_values: dict[str, float]) -> str | None:
    expression = STRING_LITERAL_RE.sub("", value).strip().rstrip(";")
    expression = expression.replace("&&", " and ").replace("||", " or ")
    for name, number in numeric_values.items():
        expression = re.sub(rf"\b{re.escape(name)}\b", repr(number), expression)
    if _value_identifiers(expression):
        return None
    return expression


def _safe_eval_numeric(value: str, numeric_values: dict[str, float]) -> float | None:
    expression = _numeric_expression(value, numeric_values)
    if not expression:
        return None
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return None
    allowed = (
        ast.Expression,
        ast.Constant,
        ast.BinOp,
        ast.UnaryOp,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.FloorDiv,
        ast.Mod,
        ast.Pow,
        ast.USub,
        ast.UAdd,
    )
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        return None
    try:
        result = eval(compile(tree, "<numeric-expression>", "eval"), {"__builtins__": {}}, {})
    except Exception:
        return None
    return float(result) if isinstance(result, int | float) else None


def _safe_eval_condition(value: str, numeric_values: dict[str, float]) -> bool | None:
    expression = _numeric_expression(value, numeric_values)
    if not expression:
        return None
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return None
    allowed = (
        ast.Expression,
        ast.Constant,
        ast.BinOp,
        ast.UnaryOp,
        ast.BoolOp,
        ast.Compare,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.FloorDiv,
        ast.Mod,
        ast.Pow,
        ast.USub,
        ast.UAdd,
        ast.And,
        ast.Or,
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
    )
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        return None
    try:
        result = eval(compile(tree, "<condition-expression>", "eval"), {"__builtins__": {}}, {})
    except Exception:
        return None
    return bool(result) if isinstance(result, bool) else None


def _literal_string(value: str) -> str | None:
    expression = value.strip().rstrip(";")
    if not STRING_LITERAL_RE.fullmatch(expression):
        return None
    try:
        result = ast.literal_eval(expression)
    except (SyntaxError, ValueError):
        return None
    return result if isinstance(result, str) else None


def _split_arguments(arguments: str) -> list[str]:
    """Split Java/Python call arguments without splitting nested expressions."""

    values: list[str] = []
    start = 0
    depth = 0
    in_quote: str | None = None
    escaped = False
    for index, char in enumerate(arguments):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if in_quote:
            if char == in_quote:
                in_quote = None
            continue
        if char in {"'", '"'}:
            in_quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}" and depth:
            depth -= 1
            continue
        if char == "," and depth == 0:
            values.append(arguments[start:index].strip())
            start = index + 1
    tail = arguments[start:].strip()
    if tail:
        values.append(tail)
    return values


def _outer_call_parts(value: str) -> tuple[str, str, str | None] | None:
    """Parse the final call in an expression using balanced parentheses."""

    expression = value.strip().rstrip(";")
    if not expression.endswith(")"):
        return None
    depth = 0
    in_quote: str | None = None
    escaped = False
    for index in range(len(expression) - 1, -1, -1):
        char = expression[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if in_quote:
            if char == in_quote:
                in_quote = None
            continue
        if char in {"'", '"'}:
            in_quote = char
            continue
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth != 0:
                continue
            prefix = expression[:index].rstrip()
            method_match = re.search(r"(?P<method>[A-Za-z_$][\w$]*)$", prefix)
            if not method_match:
                return None
            receiver = prefix[: method_match.start()].rstrip()
            if receiver.endswith("."):
                receiver = receiver[:-1].rstrip()
            return (
                method_match.group("method"),
                expression[index + 1 : -1],
                receiver or None,
            )
    return None


def _sink_arguments(line: str, patterns: Sequence[re.Pattern[str]]) -> list[str]:
    """Return balanced argument expressions for security-sensitive calls."""

    arguments: list[str] = []
    masked = STRING_LITERAL_RE.sub(lambda match: " " * len(match.group(0)), line)
    for pattern in patterns:
        for match in pattern.finditer(masked):
            open_index = masked.rfind("(", match.start(), match.end())
            if open_index < 0:
                continue
            depth = 0
            for index in range(open_index, len(masked)):
                char = masked[index]
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth == 0:
                        arguments.append(line[open_index + 1 : index].strip())
                        break
    return arguments


def _value_with_known_clean_collection_gets_removed(
    value: str,
    collection_values: dict[str, dict[str, bool]],
) -> str:
    def replace(match: re.Match[str]) -> str:
        key = _literal_string(match.group("key"))
        if key is not None and collection_values.get(match.group("name"), {}).get(key) is False:
            return ""
        return match.group(0)

    return COLLECTION_GET_RE.sub(replace, value)


def _logical_code_lines(text: str) -> list[str]:
    """Collapse continuation lines without hiding Java/Python control-flow markers."""

    lines: list[str] = []
    pending: list[str] = []
    for raw_line in text.splitlines():
        stripped = raw_line.split("//", 1)[0].strip()
        if not stripped:
            continue
        if pending:
            pending.append(stripped)
            if stripped.endswith(";"):
                lines.append(" ".join(pending))
                pending = []
            continue
        if (
            stripped.startswith("@")
            or stripped.endswith(";")
            or stripped.endswith("{")
            or stripped in {"}", "};"}
            or stripped.startswith(("case ", "default:", "try", "catch", "finally"))
        ):
            lines.append(stripped)
            continue
        if JAVA_TYPED_ASSIGNMENT_RE.match(stripped):
            pending.append(stripped)
            continue
        lines.append(stripped)
    if pending:
        lines.append(" ".join(pending))
    return lines


def _constant_return_method_names(
    evidence: Sequence[Evidence],
    sources: Sequence[re.Pattern[str]],
) -> set[str]:
    method_results: dict[str, list[bool]] = {}
    for item in evidence:
        if "::" not in item.path:
            continue
        symbol = item.path.split("::", 1)[1].rsplit("@", 1)[0]
        name = symbol.rsplit(".", 1)[-1]
        returns = [match.group("value") for match in RETURN_RE.finditer(item.text)]
        if returns:
            method_results.setdefault(name, []).append(
                all(
                    not any(pattern.search(value) for pattern in sources)
                    and (
                        _literal_string(value) is not None
                        or not _value_identifiers(value)
                    )
                    for value in returns
                )
            )
    return {
        name
        for name, results in method_results.items()
        if results and all(results)
    }
