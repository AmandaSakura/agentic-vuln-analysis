"""Forward textual taint analysis over retrieved evidence."""
from __future__ import annotations

from collections.abc import Sequence
import re

from cv_agent.code_adapters.java_lexical import ASSIGNMENT_RE, COLLECTION_GET_RE, COLLECTION_PUT_RE, SINK_VALUE_NAMES, split_first_argument as _split_first_argument, value_identifiers as _value_identifiers
from cv_agent.domain.types import Candidate, Evidence, ExpertVote, ReasoningStep
from cv_agent.baselines.experts.common import _positions
from cv_agent.baselines.experts.scan import ScanExpert
from cv_agent.baselines.experts.syntax import CASE_RE, CHAR_AT_RE, COLLECTION_ADD_RE, DEFAULT_RE, ELSE_RE, IF_RE, LEADING_CAST_RE, SWITCH_RE, TERNARY_RE, _constant_return_method_names, _contains_clean_sink_value, _contains_identifier, _literal_string, _logical_code_lines, _outer_call_parts, _safe_eval_condition, _safe_eval_numeric, _sink_arguments, _value_with_known_clean_collection_gets_removed


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
        call = _outer_call_parts(LEADING_CAST_RE.sub("", value.strip()))
        if call and call[0] in constant_methods:
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
        call = _outer_call_parts(LEADING_CAST_RE.sub("", value.strip()))
        if call and call[0] in constant_methods:
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

                for add in COLLECTION_ADD_RE.finditer(line):
                    container = add.group("name")
                    value_argument = add.group("value")
                    if self._value_is_tainted(
                        value_argument,
                        tainted,
                        tainted_containers,
                        collection_values,
                        constant_methods,
                    ):
                        tainted_containers.add(container)
                        clean.discard(container)
                    elif self._value_is_clean(
                        value_argument,
                        clean,
                        collection_values,
                        constant_methods,
                    ):
                        if container not in tainted_containers:
                            clean.add(container)
                    else:
                        clean.discard(container)

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
