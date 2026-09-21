"""Shared Java-like lexical primitives for retrieval and deterministic experts.

These helpers parse text; detector-specific evidence rules belong to their callers.
"""
from __future__ import annotations

import re


ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:final\s+)?(?:[\w.$<>\[\],?]+\s+)+)?"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?::=|=(?!=))\s*"
    r"(?P<value>.+?)\s*;?\s*(?://.*)?$"
)


COLLECTION_GET_RE = re.compile(
    r"\b(?P<name>[A-Za-z_$][\w$]*)\.get\s*\(\s*"
    r"(?P<key>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')\s*\)"
)


COLLECTION_PUT_RE = re.compile(
    r"\b(?P<name>[A-Za-z_$][\w$]*)\.put\s*\((?P<arguments>[^;]*)\)"
)


STRING_LITERAL_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


IDENTIFIER_RE = re.compile(r"\b[A-Za-z_$][\w$]*\b")


NON_VALUE_IDENTIFIERS = frozenset(
    {
        "String",
        "Object",
        "Integer",
        "Boolean",
        "Long",
        "Double",
        "Float",
        "new",
        "null",
        "true",
        "false",
    }
)


SINK_VALUE_NAMES = frozenset(
    {
        "bar",
        "cmd",
        "command",
        "file",
        "filename",
        "filter",
        "name",
        "param",
        "path",
        "query",
        "sql",
        "value",
    }
)


def value_identifiers(value: str) -> set[str]:
    without_literals = STRING_LITERAL_RE.sub("", value)
    return {
        name
        for name in IDENTIFIER_RE.findall(without_literals)
        if name not in NON_VALUE_IDENTIFIERS and not name[:1].isupper()
    }


def split_first_argument(arguments: str) -> tuple[str, str] | None:
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
        if char == ",":
            return arguments[:index].strip(), arguments[index + 1 :].strip()
    return None
