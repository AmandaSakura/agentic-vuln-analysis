"""Textual assignment dependencies used to retain security context."""
from __future__ import annotations

import re

from ..java_lexical import (
    ASSIGNMENT_RE,
    COLLECTION_GET_RE,
    COLLECTION_PUT_RE,
    SINK_VALUE_NAMES,
    STRING_LITERAL_RE,
    split_first_argument as _split_first_argument,
    value_identifiers as _value_identifiers,
)


INLINE_IF_RE = re.compile(r"^\s*if\s*\([^)]*\)\s*(?P<trailing>.+)$")


IF_CONDITION_RE = re.compile(r"^\s*if\s*\((?P<condition>.*)\)\s*$")


SWITCH_RE = re.compile(r"^\s*switch\s*\((?P<value>.*)\)\s*\{?\s*$")


CALL_ARGUMENT_RE = re.compile(r"\((?P<arguments>[^()]*)\)")


MAP_GET_RE = re.compile(r"\b(?P<receiver>[A-Za-z_$][\w$]*)\.get\s*\(")


METHOD_RECEIVER_RE = re.compile(
    r"\b(?P<receiver>[A-Za-z_$][\w$]*)\.[A-Za-z_$][\w$]*\s*\("
)


VALUE_TRANSFORM_RECEIVER_RE = re.compile(
    r"\b(?P<receiver>[A-Za-z_$][\w$]*)\."
    r"(?:substring|trim|toString|toLowerCase|toUpperCase|replace|split)\s*\(",
    re.IGNORECASE,
)


def _sink_value_identifiers(line: str) -> set[str]:
    call_arguments = CALL_ARGUMENT_RE.findall(line)
    identifiers = _value_identifiers(" ".join(call_arguments) if call_arguments else line)
    focused = {name for name in identifiers if name.casefold() in SINK_VALUE_NAMES}
    return focused or identifiers


def _assignment_value_dependencies(value: str) -> set[str]:
    expression = STRING_LITERAL_RE.sub("", value)
    dependencies: set[str] = set()
    if transform := VALUE_TRANSFORM_RECEIVER_RE.search(expression):
        receiver = transform.group("receiver")
        if not receiver[:1].isupper():
            dependencies.add(receiver)
            return dependencies
    for receiver_match in METHOD_RECEIVER_RE.finditer(expression):
        receiver = receiver_match.group("receiver")
        if not receiver[:1].isupper():
            dependencies.add(receiver)
    if map_get := MAP_GET_RE.search(expression):
        dependencies.add(map_get.group("receiver"))
    call_arguments = CALL_ARGUMENT_RE.findall(expression)
    if call_arguments:
        argument_identifiers = _value_identifiers(" ".join(call_arguments))
        if argument_identifiers:
            dependencies.update(argument_identifiers)
            return dependencies
    dependencies.update(_value_identifiers(expression))
    return dependencies


def _assignment_match(line: str) -> re.Match[str] | None:
    stripped = line.strip()
    match = ASSIGNMENT_RE.match(stripped)
    if match:
        return match
    inline_if = INLINE_IF_RE.match(stripped)
    if inline_if:
        return ASSIGNMENT_RE.match(inline_if.group("trailing"))
    return None


def _collection_put_dependencies(
    lines: list[str],
    value: str,
    before_index: int,
) -> tuple[list[int], set[str]]:
    anchors: list[int] = []
    dependencies: set[str] = set()
    collection_gets = [
        (match.group("name"), match.group("key"))
        for match in COLLECTION_GET_RE.finditer(value)
    ]
    if not collection_gets:
        return anchors, dependencies
    for index in range(before_index - 1, -1, -1):
        for put in COLLECTION_PUT_RE.finditer(lines[index]):
            split_arguments = _split_first_argument(put.group("arguments"))
            if split_arguments is None:
                continue
            key, put_value = split_arguments
            if (put.group("name"), key) not in collection_gets:
                continue
            anchors.append(index)
            dependencies.update(_assignment_value_dependencies(put_value))
    return sorted(set(anchors)), dependencies


def _nearby_if_dependencies(
    lines: list[str],
    line_index: int,
    *,
    lookback: int = 4,
) -> tuple[list[int], set[str]]:
    for index in range(line_index - 1, max(-1, line_index - lookback - 1), -1):
        match = IF_CONDITION_RE.match(lines[index].strip())
        if match:
            return [index], _value_identifiers(match.group("condition"))
    return [], set()


def _is_low_priority_initializer(lines: list[str], index: int, anchors: list[int]) -> bool:
    match = _assignment_match(lines[index])
    if not match:
        return False
    name = match.group("name")
    value = match.group("value").strip()
    later_same_name = any(
        later > index
        and (later_match := _assignment_match(lines[later])) is not None
        and later_match.group("name") == name
        for later in anchors
    )
    if later_same_name and STRING_LITERAL_RE.fullmatch(value.rstrip(";")):
        return True
    return bool(re.match(r"new\s+(?:java\.util\.)?(?:HashMap|Map|ArrayList)\b", value))


def _enclosing_switch_index(lines: list[str], line_index: int) -> int | None:
    stack: list[int] = []
    for index, line in enumerate(lines[: line_index + 1]):
        stripped = line.strip()
        if SWITCH_RE.match(stripped):
            stack.append(index)
        elif stripped == "}" and stack:
            stack.pop()
    return stack[-1] if stack else None


def _switch_range(lines: list[str], switch_index: int) -> tuple[int, int]:
    depth = 0
    for index in range(switch_index, len(lines)):
        stripped = lines[index].strip()
        if SWITCH_RE.match(stripped):
            depth += 1
            continue
        if stripped == "}" and depth:
            depth -= 1
            if depth == 0:
                return switch_index, index + 1
    return switch_index, min(len(lines), switch_index + 1)


def _assignment_dependency_context(
    lines: list[str],
    sink_indices: list[int],
    *,
    max_depth: int = 6,
) -> tuple[list[int], list[tuple[int, int]]]:
    if not sink_indices:
        return [], []
    first_sink = min(sink_indices)
    needed: set[str] = set()
    for sink_index in sink_indices:
        needed.update(_sink_value_identifiers(lines[sink_index]))
    anchors: set[int] = set()
    ranges: set[tuple[int, int]] = set()
    resolved: set[str] = set()
    for _ in range(max_depth):
        unresolved = needed - resolved
        if not unresolved:
            break
        found_names: set[str] = set()
        discovered: set[str] = set()
        for index in range(first_sink - 1, -1, -1):
            match = _assignment_match(lines[index])
            if not match:
                continue
            name = match.group("name")
            if name not in unresolved:
                continue
            found_names.add(name)
            discovered.update(_assignment_value_dependencies(match.group("value")))
            put_indices, put_dependencies = _collection_put_dependencies(
                lines,
                match.group("value"),
                index,
            )
            anchors.update(put_indices)
            discovered.update(put_dependencies)
            if_indices, if_dependencies = _nearby_if_dependencies(lines, index)
            anchors.update(if_indices)
            discovered.update(if_dependencies)
            switch_index = _enclosing_switch_index(lines, index)
            if switch_index is not None:
                ranges.add(_switch_range(lines, switch_index))
                switch_match = SWITCH_RE.match(lines[switch_index].strip())
                if switch_match:
                    discovered.update(_value_identifiers(switch_match.group("value")))
            else:
                anchors.add(index)
        if not found_names:
            break
        resolved.update(found_names)
        needed.update(discovered)
    return sorted(anchors), sorted(ranges)
