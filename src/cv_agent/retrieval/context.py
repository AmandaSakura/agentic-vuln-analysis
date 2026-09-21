"""Source spans and focused context windows under a fixed budget."""
from __future__ import annotations

import re

from ..java_lexical import STRING_LITERAL_RE
from ..types import CodeDocument
from .dependencies import _assignment_dependency_context, _is_low_priority_initializer
from .tokens import CONTEXT_TOKEN_RE, context_text_token_count, tokenize


DOCUMENT_SPAN_RE = re.compile(
    r"^(?P<file>.+)::(?P<symbol>.+)@(?P<start>\d+)-(?P<end>\d+)(?:#\d+-\d+)?$"
)


SECURITY_SINK_FOCUS_RE = re.compile(
    r"(?<![\w.])(?:eval|exec)\s*\(|"
    r"Runtime\.getRuntime\(\)\.exec|"
    r"\bProcessBuilder\s*\(|"
    r"\bsubprocess\.(?:run|popen|call)|"
    r"\.(?:execute|executeQuery|executeUpdate|prepareStatement|prepareCall)\s*\(|"
    r"\.search\s*\(|"
    r"\b(?:FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(|"
    r"\.delete\s*\(|"
    r"shell\s*=\s*True",
    re.IGNORECASE,
)


SECURITY_SOURCE_FOCUS_RE = re.compile(
    r"\b(?:request|req)\.(?:args|query|body|params|headers|cookies)\b|"
    r"\brequest\.get(?:Header|Headers|Parameter|ParameterMap|ParameterNames|ParameterValues|"
    r"Cookies?|QueryString)\s*\(|"
    r"\.getTheParameter\s*\(|"
    r"\btheCookie\.getValue\s*\(|"
    r"\b(?:input\s*\(|sys\.argv\b|os\.environ\b|process\.env\b)",
    re.IGNORECASE,
)


NON_ADJACENT_CONTEXT_MARKER = "\n[... omitted non-adjacent context ...]\n"


def _security_focus_score(line: str) -> int:
    score = 0
    if SECURITY_SINK_FOCUS_RE.search(line):
        score += 3
    if SECURITY_SOURCE_FOCUS_RE.search(line):
        score += 1
    return score


def _uses_get_cmd_shell_construction(document: CodeDocument | None) -> bool:
    if document is None:
        return False
    return (
        "get_cmd" in document.text
        and (
            "subprocess.Popen" in document.text
            or "bash" in document.text
            or ".execute(" in document.text
        )
    )


def _is_textual_get_cmd_helper(document: CodeDocument | None) -> bool:
    if document is None:
        return False
    return (
        "::get_cmd@" in document.path
        or bool(re.search(r"^\s*def\s+get_cmd\s*\(", document.text, re.MULTILINE))
    )


def _render_non_overlapping_ranges(
    lines: list[str],
    ranges: list[tuple[int, int]],
) -> str:
    if not ranges:
        return ""
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
    return NON_ADJACENT_CONTEXT_MARKER.join(
        "".join(lines[start:end]).strip("\n") for start, end in merged
    )


def _line_window_range(
    lines: list[str],
    center_index: int,
    token_budget: int,
) -> tuple[int, int]:
    if not lines:
        return (0, 0)
    center_index = min(max(center_index, 0), len(lines) - 1)
    start = center_index
    end = center_index + 1

    def rendered(next_start: int, next_end: int) -> str:
        return "".join(lines[next_start:next_end])

    if context_text_token_count(rendered(start, end)) >= token_budget:
        return start, end

    while True:
        changed = False
        if start > 0:
            candidate = rendered(start - 1, end)
            if context_text_token_count(candidate) <= token_budget:
                start -= 1
                changed = True
        if end < len(lines):
            candidate = rendered(start, end + 1)
            if context_text_token_count(candidate) <= token_budget:
                end += 1
                changed = True
        if not changed:
            break
    return start, end


def _logical_statement_range(lines: list[str], start: int) -> tuple[int, int]:
    """Expand a Java call anchor through its balanced multiline statement."""

    depth = 0
    saw_parenthesis = False
    for index in range(start, len(lines)):
        masked = STRING_LITERAL_RE.sub("", lines[index])
        for char in masked:
            if char == "(":
                depth += 1
                saw_parenthesis = True
            elif char == ")" and depth:
                depth -= 1
        if saw_parenthesis and depth == 0 and ";" in masked:
            return start, index + 1
    return start, min(len(lines), start + 1)


def _security_focused_text(lines: list[str], token_budget: int) -> str | None:
    source_indices = [
        index for index, line in enumerate(lines) if SECURITY_SOURCE_FOCUS_RE.search(line)
    ]
    sink_indices = [
        index for index, line in enumerate(lines) if SECURITY_SINK_FOCUS_RE.search(line)
    ]
    if not source_indices and not sink_indices:
        return None
    if source_indices and sink_indices:
        sink_index = sink_indices[0]
        preceding_sources = [index for index in source_indices if index <= sink_index]
        source_index = preceding_sources[-1] if preceding_sources else source_indices[0]
        dependency_indices, dependency_ranges = _assignment_dependency_context(
            lines,
            sink_indices,
        )
        anchors = sorted({source_index, *dependency_indices, sink_index})
    else:
        dependency_ranges = []
        anchors = [source_indices[0] if source_indices else sink_indices[0]]

    sink_statement_ranges = [
        _logical_statement_range(lines, index) for index in sink_indices
    ]

    marker_budget = (
        context_text_token_count(NON_ADJACENT_CONTEXT_MARKER) * (len(anchors) - 1)
    )
    chunk_budget = max(1, (token_budget - marker_budget) // len(anchors))
    ranges = [
        *dependency_ranges,
        *sink_statement_ranges,
        *(_line_window_range(lines, anchor, chunk_budget) for anchor in anchors),
    ]
    focused = _render_non_overlapping_ranges(lines, ranges)
    if context_text_token_count(focused) <= token_budget:
        return focused
    compact_ranges = [
        *dependency_ranges,
        *sink_statement_ranges,
        *((anchor, anchor + 1) for anchor in anchors),
    ]
    compact = _render_non_overlapping_ranges(lines, compact_ranges)
    if context_text_token_count(compact) <= token_budget:
        return compact
    prioritized_anchors = [
        anchor
        for anchor in anchors
        if not _is_low_priority_initializer(lines, anchor, anchors)
    ]
    prioritized_compact = _render_non_overlapping_ranges(
        lines,
        [
            *dependency_ranges,
            *sink_statement_ranges,
            *((anchor, anchor + 1) for anchor in prioritized_anchors),
        ],
    )
    if context_text_token_count(prioritized_compact) <= token_budget:
        return prioritized_compact
    return None


def _line_bounds_from_path(path: str) -> tuple[int, int] | None:
    match = DOCUMENT_SPAN_RE.match(path)
    if not match:
        return None
    return int(match.group("start")), int(match.group("end"))


def _line_window_around(
    lines: list[str],
    center_index: int,
    token_budget: int,
) -> str:
    start, end = _line_window_range(lines, center_index, token_budget)
    text = "".join(lines[start:end])
    if context_text_token_count(text) > token_budget:
        token_ends = [match.end() for match in CONTEXT_TOKEN_RE.finditer(text)]
        return text[: token_ends[token_budget - 1]] if token_ends else ""
    return text


def _focused_text(
    text: str,
    *,
    query: str,
    token_budget: int,
    fallback_relative_line: int | None = None,
    security_focus: bool = False,
) -> str:
    if context_text_token_count(text) <= token_budget:
        return text
    lines = text.splitlines(keepends=True)
    if not lines:
        return text
    query_terms = set(tokenize(query))
    fallback_index = (
        min(max(fallback_relative_line - 1, 0), len(lines) - 1)
        if fallback_relative_line is not None
        else 0
    )
    if security_focus:
        focused = _security_focused_text(lines, token_budget)
        if focused is not None:
            return focused
    scored = [
        (
            _security_focus_score(line) if security_focus else 0,
            len(set(tokenize(line)) & query_terms),
            -abs(index - fallback_index),
            index,
        )
        for index, line in enumerate(lines)
    ]
    best_security_score, best_query_score, _, best_index = max(scored)
    center = best_index if best_security_score > 0 or best_query_score > 0 else fallback_index
    return _line_window_around(lines, center, token_budget)
