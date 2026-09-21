"""Backward sink slicing and clean-input refutation."""
from __future__ import annotations

from collections.abc import Sequence
import re

from ..java_lexical import (
    ASSIGNMENT_RE,
    COLLECTION_GET_RE,
    COLLECTION_PUT_RE,
    IDENTIFIER_RE,
    NON_VALUE_IDENTIFIERS,
    SINK_VALUE_NAMES,
    STRING_LITERAL_RE,
    split_first_argument as _split_first_argument,
)
from ..types import Candidate, Evidence, ExpertVote, ReasoningStep
from .scan import ScanExpert
from .syntax import (
    CASE_RE,
    CHAR_AT_RE,
    COLLECTION_ADD_RE,
    DEFAULT_RE,
    ELSE_RE,
    IF_RE,
    LEADING_CAST_RE,
    RETURN_RE,
    SWITCH_RE,
    TERNARY_RE,
    _constant_return_method_names,
    _literal_string,
    _logical_code_lines,
    _outer_call_parts,
    _safe_eval_condition,
    _safe_eval_numeric,
    _sink_arguments,
    _split_arguments,
)
from .taint import TaintExpert


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
    static_clean_calls = frozenset({"getClass", "getClassLoader", "getProperty"})
    package_roots = frozenset({"com", "java", "javax", "org", "sun"})
    sink_value_names = SINK_VALUE_NAMES | {"expression"}

    def _constant_return_methods(self, evidence: Sequence[Evidence]) -> set[str]:
        return _constant_return_method_names(evidence, self.sources)

    def _argument_preserving_methods(self, evidence: Sequence[Evidence]) -> set[str]:
        method_results: dict[str, list[bool]] = {}
        for item in evidence:
            if "::" not in item.path:
                continue
            returns = [match.group("value") for match in RETURN_RE.finditer(item.text)]
            if not returns:
                continue
            symbol = item.path.split("::", 1)[1].rsplit("@", 1)[0]
            method_name = symbol.rsplit(".", 1)[-1]
            signature = item.text.split("{", 1)[0]
            parameter_match = re.search(r"\((?P<parameters>.*)\)", signature, re.DOTALL)
            parameters: set[str] = set()
            if parameter_match:
                for parameter in _split_arguments(parameter_match.group("parameters")):
                    names = IDENTIFIER_RE.findall(parameter)
                    if names:
                        parameters.add(names[-1])

            clean = set(parameters)
            has_ambient_source = any(
                pattern.search(item.text) for pattern in self.sources
            )
            for line in _logical_code_lines(item.text):
                assignment = ASSIGNMENT_RE.match(line)
                if not assignment:
                    continue
                value = assignment.group("value")
                identifiers = self._fallback_identifiers(value)
                if (
                    not any(pattern.search(value) for pattern in self.sources)
                    and identifiers.issubset(clean)
                ):
                    clean.add(assignment.group("name"))
                else:
                    clean.discard(assignment.group("name"))

            preserves_arguments = not has_ambient_source and all(
                _literal_string(value) is not None
                or self._fallback_identifiers(value).issubset(clean)
                for value in returns
            )
            method_results.setdefault(method_name, []).append(preserves_arguments)
        return {
            name
            for name, results in method_results.items()
            if results and all(results)
        }

    @staticmethod
    def _record_literal_state(
        line: str,
        numeric_values: dict[str, float],
        string_values: dict[str, str],
        char_values: dict[str, str],
    ) -> None:
        assignment = ASSIGNMENT_RE.match(line)
        if not assignment:
            return
        name = assignment.group("name")
        value = assignment.group("value")
        numeric = _safe_eval_numeric(value, numeric_values)
        if numeric is None:
            numeric_values.pop(name, None)
        else:
            numeric_values[name] = numeric
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

    def _active_lines(
        self,
        lines: list[str],
        before_index: int,
    ) -> list[tuple[int, str]]:
        """Select lines from provably reachable simple Java branches."""

        active: list[tuple[int, str]] = []
        numeric_values: dict[str, float] = {}
        string_values: dict[str, str] = {}
        char_values: dict[str, str] = {}
        next_branch_decision: bool | None = None
        last_if_decision: bool | None = None
        switch_target: str | None = None
        switch_active = False
        switch_matched = False
        switch_done = False

        def include(index: int, line: str) -> None:
            active.append((index, line))
            self._record_literal_state(
                line,
                numeric_values,
                string_values,
                char_values,
            )

        for index, stripped in enumerate(lines[:before_index]):
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
                    include(index, stripped)
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
                    if decision is not False:
                        include(index, trailing)
                else:
                    next_branch_decision = decision
                continue

            else_match = ELSE_RE.match(stripped)
            if else_match:
                trailing = else_match.group("trailing").strip()
                decision = None if last_if_decision is None else not last_if_decision
                last_if_decision = None
                if trailing and trailing != "{":
                    if decision is not False:
                        include(index, trailing)
                else:
                    next_branch_decision = decision
                continue

            if next_branch_decision is False:
                next_branch_decision = None
                continue
            next_branch_decision = None
            include(index, stripped)
        return active

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
        argument_methods: set[str],
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
                    argument_methods,
                    seen,
                )
        return False

    def _name_is_clean(
        self,
        name: str,
        lines: list[str],
        before_index: int,
        constant_methods: set[str],
        argument_methods: set[str],
        seen: set[tuple[str, int]],
    ) -> bool:
        key = (name, before_index)
        if key in seen:
            return False
        active_lines = self._active_lines(lines, before_index)
        definitions = [
            (index, assignment)
            for index, line in active_lines
            if (assignment := ASSIGNMENT_RE.match(line)) is not None
            and assignment.group("name") == name
        ]
        if not definitions:
            return name in self._numeric_values(lines, before_index)
        if len(definitions) > 1:
            first_index = definitions[0][0]
            last_index = definitions[-1][0]
            has_control_join = any(
                IF_RE.match(lines[index])
                or ELSE_RE.match(lines[index])
                or SWITCH_RE.match(lines[index])
                or CASE_RE.match(lines[index])
                or DEFAULT_RE.match(lines[index])
                for index in range(first_index, last_index + 1)
            )
            if not has_control_join:
                definitions = [definitions[-1]]
        next_seen = {*seen, key}
        # Requiring every remaining feasible definition to be clean is
        # conservative for unresolved branch joins.
        definitions_clean = all(
            self._expression_is_clean(
                assignment.group("value"),
                lines,
                index,
                constant_methods,
                argument_methods,
                next_seen,
            )
            for index, assignment in definitions
        )
        if not definitions_clean:
            return False
        first_definition = min(index for index, _ in definitions)
        for index, line in active_lines:
            if index <= first_definition:
                continue
            for add in COLLECTION_ADD_RE.finditer(line):
                if add.group("name") == name and not self._expression_is_clean(
                    add.group("value"),
                    lines,
                    index,
                    constant_methods,
                    argument_methods,
                    next_seen,
                ):
                    return False
        return True

    def _expression_is_clean(
        self,
        value: str,
        lines: list[str],
        before_index: int,
        constant_methods: set[str],
        argument_methods: set[str],
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
                    argument_methods,
                    seen,
                )
            return all(
                self._expression_is_clean(
                    branch,
                    lines,
                    before_index,
                    constant_methods,
                    argument_methods,
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
                    argument_methods,
                    seen,
                )
                for match in collection_gets
            ):
                return False
            value = COLLECTION_GET_RE.sub("", value)

        call = _outer_call_parts(value)
        if call:
            method, raw_arguments, receiver = call
            arguments = _split_arguments(raw_arguments)
            if method in constant_methods or method in self.static_clean_calls:
                return True
            arguments_clean = all(
                self._expression_is_clean(
                    argument,
                    lines,
                    before_index,
                    constant_methods,
                    argument_methods,
                    seen,
                )
                for argument in arguments
            )
            if method in self.value_transforms:
                return arguments_clean and (
                    receiver is None
                    or (
                        self._name_is_clean(
                            receiver,
                            lines,
                            before_index,
                            constant_methods,
                            argument_methods,
                            seen,
                        )
                        if IDENTIFIER_RE.fullmatch(receiver)
                        else self._expression_is_clean(
                            receiver,
                            lines,
                            before_index,
                            constant_methods,
                            argument_methods,
                            seen,
                        )
                    )
                )
            if method in argument_methods:
                return arguments_clean
            if value.lstrip().startswith("new ") and method[:1].isupper():
                return arguments_clean
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
                argument_methods,
                seen,
            )
            for name in identifiers
        )

    def evaluate(self, candidate: Candidate, evidence: Sequence[Evidence]) -> ExpertVote:
        constant_methods = self._constant_return_methods(evidence)
        argument_methods = self._argument_preserving_methods(evidence)
        safe_ids: list[str] = []
        unresolved_ids: list[str] = []
        for item in evidence:
            lines = _logical_code_lines(item.text)
            item_sinks: list[bool] = []
            for index, line in enumerate(lines):
                sink_arguments = _sink_arguments(line, self.sinks)
                for sink_index, arguments in enumerate(sink_arguments):
                    if not arguments:
                        continue
                    if (
                        sink_index > 0
                        and ".compile(" in line
                        and ".evaluate(" in line
                    ):
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
                                argument_methods,
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
                            argument_methods,
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
