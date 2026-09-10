from __future__ import annotations

import math
import re
from collections import Counter, defaultdict, deque
from collections.abc import Callable, Iterable
from functools import lru_cache
from typing import Literal

from .harness import RetrievalBudget, RetrievalMode
from .types import Candidate, CodeDocument, Evidence


TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}")
CONTEXT_TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)
DOCUMENT_SPAN_RE = re.compile(
    r"^(?P<file>.+)::(?P<symbol>.+)@(?P<start>\d+)-(?P<end>\d+)$"
)
ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:final\s+)?(?:[\w.$<>\[\],?]+\s+)+)?"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?::=|=(?!=))\s*"
    r"(?P<value>.+?)\s*;?\s*(?://.*)?$"
)
INLINE_IF_RE = re.compile(r"^\s*if\s*\([^)]*\)\s*(?P<trailing>.+)$")
IF_CONDITION_RE = re.compile(r"^\s*if\s*\((?P<condition>.*)\)\s*$")
SWITCH_RE = re.compile(r"^\s*switch\s*\((?P<value>.*)\)\s*\{?\s*$")
COLLECTION_GET_RE = re.compile(
    r"\b(?P<name>[A-Za-z_$][\w$]*)\.get\s*\(\s*"
    r"(?P<key>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')\s*\)"
)
COLLECTION_PUT_RE = re.compile(
    r"\b(?P<name>[A-Za-z_$][\w$]*)\.put\s*\((?P<arguments>[^;]*)\)"
)
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


def tokenize(text: str) -> list[str]:
    return [token.casefold() for token in TOKEN_RE.findall(text)]


def _value_identifiers(value: str) -> set[str]:
    without_literals = STRING_LITERAL_RE.sub("", value)
    return {
        name
        for name in IDENTIFIER_RE.findall(without_literals)
        if name not in NON_VALUE_IDENTIFIERS and not name[:1].isupper()
    }


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


def _split_first_argument(arguments: str) -> tuple[str, str] | None:
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


def context_token_count(evidence: Iterable[Evidence]) -> int:
    return sum(context_text_token_count(item.text) for item in evidence)


def context_text_token_count(text: str) -> int:
    """Legacy lexical units for deterministic development experiments."""
    return len(CONTEXT_TOKEN_RE.findall(text))


def prompt_token_upper_bound(text: str) -> int:
    """UTF-8 byte bound for model-visible text, separate from provider usage.

    Byte-based tokenizers cannot require more text tokens than input bytes.
    Chat framing and tool schemas are outside this retrieved-text budget.
    """
    return len(text.encode("utf-8"))


def _security_focus_score(line: str) -> int:
    score = 0
    if SECURITY_SINK_FOCUS_RE.search(line):
        score += 3
    if SECURITY_SOURCE_FOCUS_RE.search(line):
        score += 1
    return score


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


def fit_text_to_serialized_context(
    text: str,
    *,
    token_budget: int,
    render: Callable[[str], str],
    count_tokens: Callable[[str], int] = context_text_token_count,
) -> tuple[str, str, int] | None:
    """Fit a text field while charging the exact serialized model-visible payload."""

    if token_budget < 0:
        raise ValueError("serialized context token budget cannot be negative")
    empty_payload = render("")
    empty_tokens = count_tokens(empty_payload)
    if empty_tokens > token_budget:
        return None
    full_payload = render(text)
    full_tokens = count_tokens(full_payload)
    if full_tokens <= token_budget:
        return text, full_payload, full_tokens

    token_ends = (
        range(1, len(text) + 1)
        if count_tokens is prompt_token_upper_bound
        else [match.end() for match in CONTEXT_TOKEN_RE.finditer(text)]
    )
    low = 0
    high = len(token_ends)
    best = ("", empty_payload, empty_tokens)
    while low <= high:
        middle = (low + high) // 2
        prefix = text[: token_ends[middle - 1]] if middle else ""
        payload = render(prefix)
        count = count_tokens(payload)
        if count <= token_budget:
            best = (prefix, payload, count)
            low = middle + 1
        else:
            high = middle - 1
    return best


def limit_evidence_context(
    evidence: Iterable[Evidence],
    *,
    token_budget: int,
) -> list[Evidence]:
    """Apply one deterministic context-token budget across ranked evidence."""

    if token_budget < 1:
        raise ValueError("context token budget must be positive")
    limited: list[Evidence] = []
    remaining = token_budget
    for item in evidence:
        matches = list(CONTEXT_TOKEN_RE.finditer(item.text))
        if not matches:
            continue
        if len(matches) <= remaining:
            limited.append(item)
            remaining -= len(matches)
        else:
            cutoff = matches[remaining - 1].end()
            limited.append(item.model_copy(update={"text": item.text[:cutoff]}))
            remaining = 0
        if remaining == 0:
            break
    return limited


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


class RepositoryIndex:
    def __init__(self, documents: Iterable[CodeDocument]) -> None:
        docs = list(documents)
        if not docs:
            raise ValueError("repository index requires at least one document")
        self.documents = {doc.path: doc for doc in docs}
        if len(self.documents) != len(docs):
            raise ValueError("duplicate document path")
        self._term_frequency = {path: Counter(tokenize(doc.text)) for path, doc in self.documents.items()}
        document_frequency: Counter[str] = Counter()
        for terms in self._term_frequency.values():
            document_frequency.update(terms.keys())
        count = len(self.documents)
        self._idf = {term: math.log((count + 1) / (frequency + 1)) + 1.0 for term, frequency in document_frequency.items()}
        self._forward_graph, self._reverse_graph = self._build_graph(docs)

    @staticmethod
    def _build_graph(
        documents: list[CodeDocument],
    ) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
        definitions: dict[str, set[str]] = defaultdict(set)
        for doc in documents:
            for symbol in doc.defines:
                definitions[symbol].add(doc.path)
        forward: dict[str, set[str]] = {doc.path: set() for doc in documents}
        reverse: dict[str, set[str]] = {doc.path: set() for doc in documents}
        for caller in documents:
            precise_bases = {
                symbol.split("(", 1)[0].split("#", 1)[0]
                for symbol in caller.calls
                if "(" in symbol or "#" in symbol
            }
            for symbol in caller.calls:
                if symbol in precise_bases:
                    continue
                targets = definitions.get(symbol, set())
                # Bare symbols are useful only when they resolve uniquely. Linking every
                # same-named method creates artificial repository-wide shortcuts.
                if "." not in symbol and len(targets) != 1:
                    continue
                for callee_path in targets:
                    if callee_path != caller.path:
                        forward[caller.path].add(callee_path)
                        reverse[callee_path].add(caller.path)
        return forward, reverse

    @lru_cache(maxsize=1)
    def _lexical_scores(self, query: str) -> dict[str, float]:
        """Score one candidate query and reuse it across its V2-V5 retrieval calls."""

        query_terms = Counter(tokenize(query))
        scores: dict[str, float] = {}
        for path, terms in self._term_frequency.items():
            score = 0.0
            for term, query_count in query_terms.items():
                frequency = terms.get(term, 0)
                if frequency:
                    score += query_count * (1.0 + math.log(frequency)) * self._idf.get(term, 1.0)
            scores[path] = score
        return scores

    def local(self, candidate: Candidate) -> list[Evidence]:
        document = self.documents.get(candidate.path)
        if document is None:
            return []
        return [Evidence(evidence_id=f"local:{document.path}", path=document.path, text=document.text, retrieval="local", score=1.0)]

    def _focused_local(
        self,
        candidate: Candidate,
        *,
        token_budget: int,
    ) -> list[Evidence]:
        document = self.documents.get(candidate.path)
        if document is None:
            return []
        bounds = _line_bounds_from_path(candidate.path)
        fallback_relative_line = (
            candidate.line - bounds[0] + 1
            if bounds is not None and bounds[0] <= candidate.line <= bounds[1]
            else None
        )
        return [
            Evidence(
                evidence_id=f"local:{document.path}",
                path=document.path,
                text=_focused_text(
                    document.text,
                    query=candidate.query,
                    token_budget=token_budget,
                    fallback_relative_line=fallback_relative_line,
                ),
                retrieval="local",
                score=1.0,
            )
        ]

    def _focused_augmentation(
        self,
        evidence: list[Evidence],
        candidate: Candidate,
        *,
        token_budget: int,
    ) -> list[Evidence]:
        if not evidence:
            return []
        if len(evidence) == 1 or token_budget < len(evidence):
            item_budgets = [max(1, token_budget // len(evidence))] * len(evidence)
        else:
            equal_share = token_budget // len(evidence)
            priority_budget = min(
                token_budget - (len(evidence) - 1),
                max(equal_share, min(512, token_budget // 2)),
            )
            remaining = token_budget - priority_budget
            share, extra = divmod(remaining, len(evidence) - 1)
            item_budgets = [priority_budget] + [
                share + (1 if index < extra else 0)
                for index in range(len(evidence) - 1)
            ]
        return [
            item.model_copy(
                update={
                    "text": _focused_text(
                        item.text,
                        query=candidate.query,
                        token_budget=item_budget,
                        security_focus=(
                            item.retrieval in {"graph", "hybrid"}
                            and item.graph_distance is not None
                        ),
                    )
                }
            )
            for item, item_budget in zip(evidence, item_budgets, strict=True)
        ]

    def document(self, path: str) -> CodeDocument | None:
        return self.documents.get(path)

    def graph_neighbors(
        self,
        path: str,
        *,
        direction: Literal["forward", "reverse"],
    ) -> tuple[str, ...]:
        graph = self._forward_graph if direction == "forward" else self._reverse_graph
        return tuple(sorted(graph.get(path, ())))

    def text_search(
        self,
        query: str,
        *,
        top_k: int = 5,
        allowed_paths: Iterable[str] | None = None,
    ) -> list[Evidence]:
        scores = self._lexical_scores(query)
        candidates = set(scores)
        if allowed_paths is not None:
            candidates &= set(allowed_paths)
        ranked = sorted(candidates, key=lambda path: (-scores[path], path))[:top_k]
        return [
            Evidence(
                evidence_id=f"text:{path}",
                path=path,
                text=self.documents[path].text,
                retrieval="text",
                score=scores[path],
            )
            for path in ranked
            if scores[path] > 0
        ]

    @staticmethod
    def _walk_graph(
        seeds: list[str],
        graph: dict[str, set[str]],
        *,
        max_hops: int,
    ) -> dict[str, int]:
        distances: dict[str, int] = {}
        queue: deque[tuple[str, int]] = deque((path, 0) for path in seeds)
        while queue:
            path, distance = queue.popleft()
            if path in distances and distances[path] <= distance:
                continue
            distances[path] = distance
            if distance >= max_hops:
                continue
            for neighbor in sorted(graph.get(path, ())):
                queue.append((neighbor, distance + 1))
        return distances

    def _rank_graph_evidence(
        self,
        distances: dict[str, int],
        lexical: dict[str, float],
        *,
        top_k: int,
        retrieval: Literal["graph", "hybrid"],
    ) -> list[Evidence]:
        ranked = sorted(
            distances,
            key=lambda path: (
                -(lexical.get(path, 0.0) + 1.0 / (1 + distances[path])),
                distances[path],
                path,
            ),
        )[:top_k]
        return [
            Evidence(
                evidence_id=f"{retrieval}:{path}",
                path=path,
                text=self.documents[path].text,
                retrieval=retrieval,
                score=lexical.get(path, 0.0) + 1.0 / (1 + distances[path]),
                graph_distance=distances[path],
            )
            for path in ranked
        ]

    def graph_search(
        self,
        candidate: Candidate,
        *,
        top_k: int = 8,
        max_hops: int = 2,
        direction: Literal["forward", "reverse", "both"] = "forward",
    ) -> list[Evidence]:
        """Search only nodes reachable from the candidate in the requested direction."""

        if candidate.path not in self.documents:
            return []
        lexical = self._lexical_scores(candidate.query)
        if direction == "forward":
            graph = self._forward_graph
        elif direction == "reverse":
            graph = self._reverse_graph
        else:
            graph = {
                path: self._forward_graph[path] | self._reverse_graph[path]
                for path in self.documents
            }
        distances = self._walk_graph([candidate.path], graph, max_hops=max_hops)
        return self._rank_graph_evidence(
            distances,
            lexical,
            top_k=top_k,
            retrieval="graph",
        )

    def hybrid_search(
        self,
        candidate: Candidate,
        *,
        top_k: int = 8,
        max_hops: int = 2,
    ) -> list[Evidence]:
        """Combine text retrieval with entry- and lexical-seeded graph retrieval."""

        lexical = self._lexical_scores(candidate.query)
        combined: list[Evidence] = []
        seen: set[str] = set()

        def branch_cap(items: Iterable[Evidence]) -> list[Evidence]:
            return [item for item in items if item.path != candidate.path][:top_k]

        def append(items: Iterable[Evidence]) -> None:
            for item in items:
                if item.path in seen:
                    continue
                seen.add(item.path)
                combined.append(
                    item.model_copy(
                        update={
                            "evidence_id": f"hybrid:{item.path}",
                            "retrieval": "hybrid",
                        }
                    )
                )

        if candidate.path in self.documents:
            append(
                branch_cap(
                    self.graph_search(
                        candidate,
                        top_k=top_k + 1,
                        max_hops=max_hops,
                    )
                )
            )

        append(branch_cap(self.text_search(candidate.query, top_k=top_k + 1)))

        lexical_seeds = [
            path
            for path in sorted(lexical, key=lambda item: (-lexical[item], item))
            if lexical[path] > 0 and path != candidate.path
        ]
        for seed in lexical_seeds[:1]:
            distances = self._walk_graph([seed], self._forward_graph, max_hops=max_hops)
            append(
                branch_cap(
                    self._rank_graph_evidence(
                        distances,
                        lexical,
                        top_k=top_k + 1,
                        retrieval="hybrid",
                    )
                )
            )
        return combined

    def retrieve_context(
        self,
        candidate: Candidate,
        *,
        mode: RetrievalMode,
        budget: RetrievalBudget,
    ) -> list[Evidence]:
        """Assemble a fixed local base plus a separately budgeted augmentation."""

        base = limit_evidence_context(
            self._focused_local(
                candidate,
                token_budget=budget.base_context_tokens,
            ),
            token_budget=budget.base_context_tokens,
        )
        if mode == RetrievalMode.LOCAL:
            return base
        if budget.top_k == 0:
            return base

        requested = budget.top_k + 1
        if mode == RetrievalMode.TEXT:
            raw_augmentation = self.text_search(candidate.query, top_k=requested)
        elif mode == RetrievalMode.GRAPH:
            raw_augmentation = self.graph_search(
                candidate,
                top_k=requested,
                max_hops=budget.graph_hops,
            )
        elif mode == RetrievalMode.HYBRID:
            raw_augmentation = self.hybrid_search(
                candidate,
                top_k=budget.top_k,
                max_hops=budget.graph_hops,
            )
        else:
            raise ValueError(f"unsupported retrieval mode: {mode}")

        filtered_augmentation = [
            item for item in raw_augmentation if item.path != candidate.path
        ]
        augmentation = (
            filtered_augmentation
            if mode == RetrievalMode.HYBRID
            else filtered_augmentation[: budget.top_k]
        )
        if not augmentation or budget.augmentation_context_tokens == 0:
            return base
        limited_augmentation = limit_evidence_context(
            self._focused_augmentation(
                augmentation,
                candidate,
                token_budget=budget.augmentation_context_tokens,
            ),
            token_budget=budget.augmentation_context_tokens,
        )
        return [*base, *limited_augmentation]
