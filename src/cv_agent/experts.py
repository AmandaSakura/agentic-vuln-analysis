from __future__ import annotations

import ast
import re
from collections.abc import Sequence
from typing import Protocol

from .types import Candidate, Evidence, ExpertVote, ReasoningStep


class Expert(Protocol):
    name: str

    def evaluate(self, candidate: Candidate, evidence: Sequence[Evidence]) -> ExpertVote: ...


def _matching_evidence(evidence: Sequence[Evidence], patterns: Sequence[re.Pattern[str]]) -> list[Evidence]:
    return [item for item in evidence if any(pattern.search(item.text) for pattern in patterns)]


def _positions(text: str, patterns: Sequence[re.Pattern[str]]) -> list[int]:
    return sorted(match.start() for pattern in patterns for match in pattern.finditer(text))


ASSIGNMENT_RE = re.compile(
    r"^\s*(?:(?:final\s+)?(?:[\w.$<>\[\],?]+\s+)+)?"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?::=|=(?!=))\s*"
    r"(?P<value>.+?)\s*;?\s*(?://.*)?$"
)
JAVA_TYPED_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:final\s+)?(?:[\w.$<>\[\],?]+\s+)+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?::=|=(?!=))\s*"
)
COLLECTION_PUT_RE = re.compile(
    r"\b(?P<name>[A-Za-z_$][\w$]*)\.put\s*\((?P<arguments>[^;]*)\)"
)
COLLECTION_GET_RE = re.compile(
    r"\b(?P<name>[A-Za-z_$][\w$]*)\.get\s*\(\s*"
    r"(?P<key>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')\s*\)"
)
RETURN_RE = re.compile(r"\breturn\s+(?P<value>.+?)\s*;")
CALL_RE = re.compile(
    r"(?:(?P<receiver>[A-Za-z_$][\w$]*)\s*\.)?"
    r"(?P<method>[A-Za-z_$][\w$]*)\s*\((?P<arguments>.*)\)"
)
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


def _contains_identifier(text: str, names: Sequence[str] | set[str]) -> bool:
    return any(re.search(rf"\b{re.escape(name)}\b", text) for name in names)


def _contains_clean_sink_value(text: str, clean: set[str]) -> bool:
    return any(
        name.casefold() in SINK_VALUE_NAMES
        and re.search(rf"\b{re.escape(name)}\b", text)
        for name in clean
    )


def _value_identifiers(value: str) -> set[str]:
    without_literals = STRING_LITERAL_RE.sub("", value)
    return {
        name
        for name in IDENTIFIER_RE.findall(without_literals)
        if name not in NON_VALUE_IDENTIFIERS and not name[:1].isupper()
    }


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


def _sink_arguments(line: str, patterns: Sequence[re.Pattern[str]]) -> list[str]:
    """Return balanced argument expressions for security-sensitive calls."""

    arguments: list[str] = []
    for pattern in patterns:
        for match in pattern.finditer(line):
            open_index = line.rfind("(", match.start(), match.end())
            if open_index < 0:
                continue
            depth = 0
            in_quote: str | None = None
            escaped = False
            for index in range(open_index, len(line)):
                char = line[index]
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


class ScanExpert:
    name = "scan"
    sinks = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"(?<![\w.])(?:eval|exec)\s*\(",
            r"subprocess\.(?:run|popen|call)",
            r"Runtime\.getRuntime\(\)\.exec",
            r"\bProcessBuilder\s*\(",
            r"\.(?:execute|executeQuery|executeUpdate|prepareStatement|prepareCall)\s*\(",
            r"\.(?:search|compile|evaluate)\s*\(",
            r"\b(?:FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(",
            r"\.delete\s*\(",
            r"shell\s*=\s*True",
        )
    )

    def evaluate(self, candidate: Candidate, evidence: Sequence[Evidence]) -> ExpertVote:
        matches = _matching_evidence(evidence, self.sinks)
        if matches:
            ids = tuple(item.evidence_id for item in matches)
            return ExpertVote(
                expert="scan",
                label="VULNERABLE",
                confidence=min(0.95, 0.80 + 0.05 * len(matches)),
                evidence_ids=ids,
                rationale="A security-sensitive sink is present in retrieved code.",
                trace=(ReasoningStep(action="scan_sinks", observation=f"matched {len(matches)} evidence item(s)"),),
            )
        return ExpertVote(
            expert="scan",
            label="ABSTAIN",
            confidence=0.35,
            rationale="The configured scanner found no sink; limited rule coverage cannot prove safety.",
            trace=(ReasoningStep(action="scan_sinks", observation="no sink match; safety not established"),),
        )


class TaintExpert:
    name = "taint"
    sources = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"\b(?:request|req)\.(?:args|query|body|params|headers|cookies)\b",
            r"\brequest\.get(?:Header|Headers|Parameter|ParameterMap|"
            r"ParameterNames|ParameterValues|Cookies?|QueryString)\s*\(",
            r"\btheCookie\.getValue\s*\(",
            r"\.getTheParameter\s*\(",
            r"\buser_input\b",
            r"\binput\s*\(",
        )
    )
    sinks = ScanExpert.sinks
    sanitizers = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"sanitize",
            r"escape",
            r"encodeFor(?:HTML|URL|JavaScript|SQL)",
            r"allowlist",
            r"validate",
        )
    )

    def _value_is_tainted(
        self,
        value: str,
        tainted: set[str],
        tainted_containers: set[str],
        collection_values: dict[str, dict[str, bool]],
        constant_methods: set[str],
    ) -> bool:
        call_value = re.sub(r"^new\s+", "", LEADING_CAST_RE.sub("", value.strip()))
        call = CALL_RE.fullmatch(call_value.rstrip(";"))
        if call and call.group("method") in constant_methods:
            return False
        for match in COLLECTION_GET_RE.finditer(value):
            key = _literal_string(match.group("key"))
            if key is not None and collection_values.get(match.group("name"), {}).get(key) is True:
                return True
        value_for_identifier_checks = _value_with_known_clean_collection_gets_removed(
            value,
            collection_values,
        )
        return (
            any(pattern.search(value) for pattern in self.sources)
            or _contains_identifier(value_for_identifier_checks, tainted)
            or _contains_identifier(value_for_identifier_checks, tainted_containers)
        )

    def _value_is_clean(
        self,
        value: str,
        clean: set[str],
        collection_values: dict[str, dict[str, bool]],
        constant_methods: set[str],
    ) -> bool:
        call_value = re.sub(r"^new\s+", "", LEADING_CAST_RE.sub("", value.strip()))
        call = CALL_RE.fullmatch(call_value.rstrip(";"))
        if call and call.group("method") in constant_methods:
            return True
        if any(pattern.search(value) for pattern in self.sources):
            return False
        value = _value_with_known_clean_collection_gets_removed(
            value,
            collection_values,
        )
        call_arguments = re.search(r"\((?P<arguments>.*)\)", value)
        if call_arguments:
            argument_identifiers = _value_identifiers(call_arguments.group("arguments"))
            if argument_identifiers and argument_identifiers.issubset(clean):
                return True
        identifiers = _value_identifiers(value)
        sink_value_identifiers = {
            name for name in identifiers if name.casefold() in SINK_VALUE_NAMES
        }
        if sink_value_identifiers:
            return sink_value_identifiers.issubset(clean)
        return not identifiers or identifiers.issubset(clean)

    def _legacy_source_before_sink(self, item: Evidence) -> bool:
        sources = _positions(item.text, self.sources)
        sinks = _positions(item.text, self.sinks)
        sanitizers = _positions(item.text, self.sanitizers)
        for sink in sinks:
            preceding_sources = [source for source in sources if source < sink]
            if not preceding_sources:
                continue
            source = max(preceding_sources)
            if any(source < sanitizer < sink for sanitizer in sanitizers):
                continue
            return True
        return False

    def _sink_arguments_are_clean(self, line: str, clean: set[str]) -> bool:
        for arguments in _sink_arguments(line, self.sinks):
            identifiers = _value_identifiers(arguments)
            focused = {
                name
                for name in identifiers
                if name.casefold() in (SINK_VALUE_NAMES | {"expression"})
            }
            required = focused or identifiers
            if required and required.issubset(clean):
                return True
            if (
                not required
                and arguments.strip()
                and not any(pattern.search(arguments) for pattern in self.sources)
            ):
                return True
        return False

    def evaluate(self, candidate: Candidate, evidence: Sequence[Evidence]) -> ExpertVote:
        constant_methods = _constant_return_method_names(evidence, self.sources)
        vulnerable_ids: list[str] = []
        safe_ids: list[str] = []
        fallback_vulnerable_ids: list[str] = []
        partial_ids: list[str] = []
        for item in evidence:
            tainted: set[str] = set()
            clean: set[str] = set()
            numeric_values: dict[str, float] = {}
            tainted_containers: set[str] = set()
            collection_values: dict[str, dict[str, bool]] = {}
            source_seen = False
            sink_seen = False
            sanitizer_seen = False
            string_values: dict[str, str] = {}
            char_values: dict[str, str] = {}

            def process_line(line: str, *, allow_clean_update: bool = True) -> None:
                nonlocal source_seen, sink_seen, sanitizer_seen
                source_hits = any(pattern.search(line) for pattern in self.sources)
                sanitizer_hits = any(pattern.search(line) for pattern in self.sanitizers)
                assignment = ASSIGNMENT_RE.match(line)
                if source_hits:
                    source_seen = True
                if sanitizer_hits:
                    sanitizer_seen = True

                for put in COLLECTION_PUT_RE.finditer(line):
                    split_arguments = _split_first_argument(put.group("arguments"))
                    key: str | None = None
                    value_argument = put.group("arguments")
                    if split_arguments is not None:
                        key = _literal_string(split_arguments[0])
                        value_argument = split_arguments[1]
                    if self._value_is_tainted(
                        value_argument,
                        tainted,
                        tainted_containers,
                        collection_values,
                        constant_methods,
                    ):
                        collection_values.setdefault(put.group("name"), {})
                        if key is None:
                            tainted_containers.add(put.group("name"))
                        else:
                            collection_values[put.group("name")][key] = True
                            tainted_containers.add(put.group("name"))
                    elif key is not None and self._value_is_clean(
                        value_argument,
                        clean,
                        collection_values,
                        constant_methods,
                    ):
                        collection_values.setdefault(put.group("name"), {})[key] = False

                if assignment:
                    name = assignment.group("name")
                    value = assignment.group("value")
                    literal = _literal_string(value)
                    char_at = CHAR_AT_RE.match(value.strip().rstrip(";"))
                    if literal is not None:
                        string_values[name] = literal
                        if len(literal) == 1:
                            char_values[name] = literal
                        else:
                            char_values.pop(name, None)
                    elif char_at and char_at.group("name") in string_values:
                        source = string_values[char_at.group("name")]
                        index = int(char_at.group("index"))
                        string_values.pop(name, None)
                        if 0 <= index < len(source):
                            char_values[name] = source[index]
                        else:
                            char_values.pop(name, None)
                    else:
                        string_values.pop(name, None)
                        char_values.pop(name, None)
                    ternary = TERNARY_RE.match(value)
                    if ternary:
                        decision = _safe_eval_condition(
                            ternary.group("condition"),
                            numeric_values,
                        )
                        if decision is not None:
                            value = ternary.group(
                                "when_true" if decision else "when_false"
                            )
                    numeric_value = _safe_eval_numeric(value, numeric_values)
                    if numeric_value is None:
                        numeric_values.pop(name, None)
                    else:
                        numeric_values[name] = numeric_value
                    if sanitizer_hits:
                        if allow_clean_update:
                            tainted.discard(name)
                            clean.add(name)
                    elif self._value_is_tainted(
                        value,
                        tainted,
                        tainted_containers,
                        collection_values,
                        constant_methods,
                    ):
                        tainted.add(name)
                        clean.discard(name)
                    elif allow_clean_update and self._value_is_clean(
                        value,
                        clean,
                        collection_values,
                        constant_methods,
                    ):
                        tainted.discard(name)
                        clean.add(name)
                    elif allow_clean_update:
                        tainted.discard(name)
                        clean.discard(name)

                line_is_tainted = (
                    source_hits
                    or _contains_identifier(line, tainted)
                    or _contains_identifier(line, tainted_containers)
                )
                line_has_clean_value = (
                    _contains_clean_sink_value(line, clean)
                    or self._sink_arguments_are_clean(line, clean)
                )
                if any(pattern.search(line) for pattern in self.sinks):
                    sink_seen = True
                    if line_is_tainted and not sanitizer_hits:
                        vulnerable_ids.append(item.evidence_id)
                    elif sanitizer_seen or line_has_clean_value:
                        safe_ids.append(item.evidence_id)

            next_branch_decision: bool | None = None
            last_if_decision: bool | None = None
            switch_target: str | None = None
            switch_active = False
            switch_matched = False
            switch_done = False
            for stripped in _logical_code_lines(item.text):
                code_line = stripped
                if switch_target is not None:
                    if stripped == "}":
                        switch_target = None
                        switch_active = False
                        switch_matched = False
                        switch_done = False
                        continue
                    case_match = CASE_RE.match(stripped)
                    if case_match:
                        if switch_done:
                            switch_active = False
                        elif switch_active:
                            switch_matched = True
                        else:
                            case_value = _literal_string(case_match.group("value"))
                            switch_active = case_value == switch_target
                            switch_matched = switch_matched or switch_active
                        continue
                    if DEFAULT_RE.match(stripped):
                        switch_active = not switch_done and (
                            switch_active or not switch_matched
                        )
                        switch_matched = True
                        continue
                    if stripped == "break;":
                        if switch_active:
                            switch_done = True
                            switch_active = False
                        continue
                    if switch_done:
                        continue
                    if switch_active:
                        process_line(code_line)
                    continue
                switch_match = SWITCH_RE.match(stripped)
                if switch_match:
                    value = switch_match.group("value").strip()
                    switch_target = char_values.get(value) or _literal_string(value)
                    if switch_target is not None:
                        switch_active = False
                        switch_matched = False
                        switch_done = False
                        continue
                if_match = IF_RE.match(stripped)
                if if_match:
                    decision = _safe_eval_condition(
                        if_match.group("condition"),
                        numeric_values,
                    )
                    trailing = if_match.group("trailing").strip()
                    last_if_decision = decision
                    if trailing and trailing != "{":
                        if decision is True:
                            process_line(trailing)
                        elif decision is None:
                            process_line(trailing, allow_clean_update=False)
                    else:
                        next_branch_decision = decision
                    continue
                else_match = ELSE_RE.match(stripped)
                if else_match:
                    trailing = else_match.group("trailing").strip()
                    decision = None if last_if_decision is None else not last_if_decision
                    last_if_decision = None
                    if trailing and trailing != "{":
                        if decision is True:
                            process_line(trailing)
                        elif decision is None:
                            process_line(trailing, allow_clean_update=False)
                    else:
                        next_branch_decision = decision
                    continue
                if next_branch_decision is False:
                    next_branch_decision = None
                    continue
                if next_branch_decision is True:
                    next_branch_decision = None
                process_line(code_line)

            if source_seen or sink_seen or sanitizer_seen:
                partial_ids.append(item.evidence_id)
            if self._legacy_source_before_sink(item):
                fallback_vulnerable_ids.append(item.evidence_id)

        if vulnerable_ids:
            return ExpertVote(
                expert="taint",
                label="VULNERABLE",
                confidence=0.84,
                evidence_ids=tuple(dict.fromkeys(vulnerable_ids)),
                rationale="A source precedes a sink in the same function without an intervening sanitizer.",
                trace=(
                    ReasoningStep(action="order_source_to_sink", observation=f"{len(set(vulnerable_ids))} unguarded function path(s)"),
                ),
            )
        if safe_ids:
            return ExpertVote(
                expert="taint",
                label="SAFE",
                confidence=0.82,
                evidence_ids=tuple(dict.fromkeys(safe_ids)),
                rationale=(
                    "A sink is present, but the local taint flow is cut by sanitization "
                    "or by assignment from non-source data."
                ),
                trace=(
                    ReasoningStep(
                        action="track_local_taint_to_sink",
                        observation="sink reached without a tracked tainted value",
                    ),
                ),
            )
        if fallback_vulnerable_ids:
            return ExpertVote(
                expert="taint",
                label="VULNERABLE",
                confidence=0.78,
                evidence_ids=tuple(dict.fromkeys(fallback_vulnerable_ids)),
                rationale=(
                    "A source precedes a sink in the same function; local value tracking "
                    "did not produce a stronger refutation."
                ),
                trace=(
                    ReasoningStep(
                        action="fallback_source_before_sink",
                        observation=(
                            f"{len(set(fallback_vulnerable_ids))} same-function "
                            "source-before-sink candidate(s)"
                        ),
                    ),
                ),
            )
        return ExpertVote(
            expert="taint",
            label="ABSTAIN",
            confidence=0.35,
            evidence_ids=tuple(dict.fromkeys(partial_ids)),
            rationale="No ordered same-function source-to-sink path can be established.",
        )


class FlowRefutationExpert:
    """Independently prove that retrieved sink inputs are non-source values.

    This expert deliberately emits SAFE or ABSTAIN only. A failed refutation is
    not positive vulnerability evidence, while a SAFE vote requires a complete
    backward proof for every modelled sink value in the retrieved item.
    """

    name = "flow"
    sinks = ScanExpert.sinks
    sources = TaintExpert.sources
    sanitizers = TaintExpert.sanitizers
    value_transforms = frozenset(
        {
            "append",
            "charAt",
            "decode",
            "decodeBuffer",
            "encode",
            "encodeBuffer",
            "getBytes",
            "replace",
            "split",
            "substring",
            "toLowerCase",
            "toString",
            "toUpperCase",
            "trim",
        }
    )
    static_clean_calls = frozenset({"getProperty"})
    package_roots = frozenset({"com", "java", "javax", "org", "sun"})
    sink_value_names = SINK_VALUE_NAMES | {"expression"}

    @staticmethod
    def _method_name(item: Evidence) -> str | None:
        if "::" not in item.path:
            return None
        symbol = item.path.split("::", 1)[1].rsplit("@", 1)[0]
        return symbol.rsplit(".", 1)[-1]

    def _constant_return_methods(self, evidence: Sequence[Evidence]) -> set[str]:
        return _constant_return_method_names(evidence, self.sources)

    @staticmethod
    def _numeric_values(lines: list[str], before_index: int) -> dict[str, float]:
        values: dict[str, float] = {}
        for line in lines[:before_index]:
            assignment = ASSIGNMENT_RE.match(line)
            if not assignment:
                continue
            value = _safe_eval_numeric(assignment.group("value"), values)
            if value is None:
                values.pop(assignment.group("name"), None)
            else:
                values[assignment.group("name")] = value
        return values

    def _fallback_identifiers(self, value: str) -> set[str]:
        without_literals = STRING_LITERAL_RE.sub("", value)
        identifiers: set[str] = set()
        for match in IDENTIFIER_RE.finditer(without_literals):
            name = match.group(0)
            if (
                name in NON_VALUE_IDENTIFIERS
                or name in self.package_roots
                or name[:1].isupper()
            ):
                continue
            previous = without_literals[match.start() - 1 : match.start()]
            following = without_literals[match.end() :].lstrip()
            if previous == "." or following.startswith("("):
                continue
            identifiers.add(name)
        return identifiers

    def _collection_get_is_clean(
        self,
        match: re.Match[str],
        lines: list[str],
        before_index: int,
        constant_methods: set[str],
        seen: set[tuple[str, int]],
    ) -> bool:
        collection = match.group("name")
        key = match.group("key")
        for index in range(before_index - 1, -1, -1):
            for put in COLLECTION_PUT_RE.finditer(lines[index]):
                if put.group("name") != collection:
                    continue
                split = _split_first_argument(put.group("arguments"))
                if split is None or split[0].strip() != key.strip():
                    continue
                return self._expression_is_clean(
                    split[1],
                    lines,
                    index,
                    constant_methods,
                    seen,
                )
        return False

    def _name_is_clean(
        self,
        name: str,
        lines: list[str],
        before_index: int,
        constant_methods: set[str],
        seen: set[tuple[str, int]],
    ) -> bool:
        key = (name, before_index)
        if key in seen:
            return False
        definitions = [
            (index, assignment)
            for index, line in enumerate(lines[:before_index])
            if (assignment := ASSIGNMENT_RE.match(line)) is not None
            and assignment.group("name") == name
        ]
        if not definitions:
            return name in self._numeric_values(lines, before_index)
        next_seen = {*seen, key}
        # Requiring every possible definition to be clean is conservative for
        # unresolved branch joins and avoids choosing a convenient last branch.
        return all(
            self._expression_is_clean(
                assignment.group("value"),
                lines,
                index,
                constant_methods,
                next_seen,
            )
            for index, assignment in definitions
        )

    def _expression_is_clean(
        self,
        value: str,
        lines: list[str],
        before_index: int,
        constant_methods: set[str],
        seen: set[tuple[str, int]],
    ) -> bool:
        value = LEADING_CAST_RE.sub("", value.strip().rstrip(";"))
        if not value:
            return True
        if any(pattern.search(value) for pattern in self.sources):
            return False
        if any(pattern.search(value) for pattern in self.sanitizers):
            return True
        if _literal_string(value) is not None:
            return True

        numeric_values = self._numeric_values(lines, before_index)
        if _safe_eval_numeric(value, numeric_values) is not None:
            return True
        ternary = TERNARY_RE.match(value)
        if ternary:
            decision = _safe_eval_condition(ternary.group("condition"), numeric_values)
            if decision is not None:
                selected = ternary.group("when_true" if decision else "when_false")
                return self._expression_is_clean(
                    selected,
                    lines,
                    before_index,
                    constant_methods,
                    seen,
                )
            return all(
                self._expression_is_clean(
                    branch,
                    lines,
                    before_index,
                    constant_methods,
                    seen,
                )
                for branch in (ternary.group("when_true"), ternary.group("when_false"))
            )

        collection_gets = list(COLLECTION_GET_RE.finditer(value))
        if collection_gets:
            if not all(
                self._collection_get_is_clean(
                    match,
                    lines,
                    before_index,
                    constant_methods,
                    seen,
                )
                for match in collection_gets
            ):
                return False
            value = COLLECTION_GET_RE.sub("", value)

        call_value = re.sub(r"^new\s+", "", value).strip()
        call = CALL_RE.fullmatch(call_value)
        if call:
            method = call.group("method")
            arguments = _split_arguments(call.group("arguments"))
            if method in constant_methods or method in self.static_clean_calls:
                return True
            arguments_clean = all(
                self._expression_is_clean(
                    argument,
                    lines,
                    before_index,
                    constant_methods,
                    seen,
                )
                for argument in arguments
            )
            if method in self.value_transforms:
                receiver = call.group("receiver")
                return arguments_clean and (
                    receiver is None
                    or self._name_is_clean(
                        receiver,
                        lines,
                        before_index,
                        constant_methods,
                        seen,
                    )
                )
            # Unknown helpers may read ambient input, so clean arguments alone
            # are insufficient for a refutation unless a retrieved summary exists.
            return False

        identifiers = self._fallback_identifiers(value)
        return all(
            self._name_is_clean(
                name,
                lines,
                before_index,
                constant_methods,
                seen,
            )
            for name in identifiers
        )

    def evaluate(self, candidate: Candidate, evidence: Sequence[Evidence]) -> ExpertVote:
        constant_methods = self._constant_return_methods(evidence)
        safe_ids: list[str] = []
        unresolved_ids: list[str] = []
        for item in evidence:
            lines = _logical_code_lines(item.text)
            item_sinks: list[bool] = []
            for index, line in enumerate(lines):
                for arguments in _sink_arguments(line, self.sinks):
                    if not arguments:
                        continue
                    identifiers = self._fallback_identifiers(arguments)
                    focused = {
                        name
                        for name in identifiers
                        if name.casefold() in self.sink_value_names
                    }
                    if focused:
                        clean = all(
                            self._name_is_clean(
                                name,
                                lines,
                                index,
                                constant_methods,
                                set(),
                            )
                            for name in focused
                        )
                    else:
                        clean = self._expression_is_clean(
                            arguments,
                            lines,
                            index,
                            constant_methods,
                            set(),
                        )
                    item_sinks.append(clean)
            if item_sinks and all(item_sinks):
                safe_ids.append(item.evidence_id)
            elif item_sinks:
                unresolved_ids.append(item.evidence_id)

        if safe_ids and not unresolved_ids:
            return ExpertVote(
                expert="flow",
                label="SAFE",
                confidence=0.86,
                evidence_ids=tuple(dict.fromkeys(safe_ids)),
                rationale=(
                    "Backward sink slicing proved every modelled sink input in the "
                    "retrieved path independent of request-derived values."
                ),
                trace=(
                    ReasoningStep(
                        action="prove_sink_inputs_clean",
                        observation=f"proved {len(set(safe_ids))} sink-bearing path(s)",
                    ),
                ),
            )
        return ExpertVote(
            expert="flow",
            label="ABSTAIN",
            confidence=0.35,
            evidence_ids=tuple(dict.fromkeys(unresolved_ids)),
            rationale="Backward slicing could not prove every retrieved sink input safe.",
        )


class AuthorizationExpert:
    name = "authz"
    sensitive = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"\.delete\s*\(",
            r"(?<![\w.])transfer\s*\(",
            r"(?<![\w.])(?:update|set|grant)_role\s*\(",
        )
    )
    guards = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"require_permission\s*\(",
            r"(?<![\w.])authorize\s*\(",
            r"is_admin\s*\(",
            r"check_role\s*\(",
            r"has_permission\s*\(",
        )
    )

    def applies(self, evidence: Sequence[Evidence]) -> bool:
        return bool(_matching_evidence(evidence, (*self.sensitive, *self.guards)))

    def evaluate(self, candidate: Candidate, evidence: Sequence[Evidence]) -> ExpertVote:
        guarded_ids: list[str] = []
        unguarded_ids: list[str] = []
        partial_ids: list[str] = []
        for item in evidence:
            operations = _positions(item.text, self.sensitive)
            guards = _positions(item.text, self.guards)
            if operations or guards:
                partial_ids.append(item.evidence_id)
            for operation in operations:
                if any(guard < operation for guard in guards):
                    guarded_ids.append(item.evidence_id)
                else:
                    unguarded_ids.append(item.evidence_id)

        if unguarded_ids:
            return ExpertVote(
                expert="authz",
                label="VULNERABLE",
                confidence=0.82,
                evidence_ids=tuple(dict.fromkeys(unguarded_ids)),
                rationale="A sensitive operation has no preceding authorization guard in the same function.",
                trace=(ReasoningStep(action="order_guard_before_operation", observation="unguarded operation found"),),
            )
        if guarded_ids:
            return ExpertVote(
                expert="authz",
                label="SAFE",
                confidence=0.84,
                evidence_ids=tuple(dict.fromkeys(guarded_ids)),
                rationale="An authorization guard precedes the sensitive operation in the same function.",
                trace=(ReasoningStep(action="order_guard_before_operation", observation="ordered guard found"),),
            )
        return ExpertVote(
            expert="authz",
            label="ABSTAIN",
            confidence=0.35,
            evidence_ids=tuple(dict.fromkeys(partial_ids)),
            rationale="No same-function authorization claim can be established.",
        )


EXPERTS: dict[str, Expert] = {
    "scan": ScanExpert(),
    "taint": TaintExpert(),
    "authz": AuthorizationExpert(),
    "flow": FlowRefutationExpert(),
}
