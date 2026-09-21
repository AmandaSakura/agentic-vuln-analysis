"""Registered vulnerable/fixed source comparison as unresolved evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from ..agent_tools import ToolExecutionScope
from ..agent_types import ToolObservation, ValidationStatus
from ..retrieval import RepositoryIndex
from ..types import CodeDocument, FrozenModel
from .models import PathInput
from .patterns import GUARD_PATTERN, SINK_RULES, _matching_lines
from .scope import _admitted_document, _json_content


def compare_versions(
    index: RepositoryIndex,
    fixed_index: RepositoryIndex | None,
    paired: Mapping[str, str],
    arguments: FrozenModel,
    scope: ToolExecutionScope,
) -> ToolObservation:
    value = cast(PathInput, arguments)
    vulnerable, error = _admitted_document(
        index,
        value.path,
        scope,
        "compare_vulnerable_and_fixed",
    )
    if error is not None:
        return error
    fixed_path = paired.get(value.path)
    fixed = fixed_index.document(fixed_path) if fixed_index and fixed_path else None
    if fixed is None:
        return ToolObservation(
            tool="compare_vulnerable_and_fixed",
            status="ok",
            content=_json_content(
                {
                    "status": ValidationStatus.UNRESOLVED,
                    "summary": "no verified paired fixed document is registered",
                }
            ),
        )
    vulnerable_item = cast(CodeDocument, vulnerable)
    vulnerable_sinks = _matching_lines(vulnerable_item, SINK_RULES)
    fixed_sinks = _matching_lines(fixed, SINK_RULES)
    vulnerable_guards = sorted(
        {match.group(0) for match in GUARD_PATTERN.finditer(vulnerable_item.text)}
    )
    fixed_guards = sorted(
        {match.group(0) for match in GUARD_PATTERN.finditer(fixed.text)}
    )
    fixed_guard_lines = [
        line_number
        for line_number, line in enumerate(fixed.text.splitlines(), start=1)
        if GUARD_PATTERN.search(line)
    ]
    guard_precedes_fixed_sinks = bool(
        fixed_sinks
        and all(
            any(guard_line < sink["line"] for guard_line in fixed_guard_lines)
            for sink in fixed_sinks
        )
    )
    sink_removed = len(fixed_sinks) < len(vulnerable_sinks)
    governing_guard_added = (
        len(fixed_guards) > len(vulnerable_guards)
        and guard_precedes_fixed_sinks
    )
    supports_fix = sink_removed or governing_guard_added
    status = ValidationStatus.UNRESOLVED
    return ToolObservation(
        tool="compare_vulnerable_and_fixed",
        status="ok",
        validation_status=status,
        content=_json_content(
            {
                "fixed_guard_count": len(fixed_guards),
                "fixed_guard_precedes_sinks": guard_precedes_fixed_sinks,
                "fixed_path": fixed_path,
                "fixed_sink_count": len(fixed_sinks),
                "status": status,
                "source_difference_supports_fix_hypothesis": supports_fix,
                "vulnerable_guard_count": len(vulnerable_guards),
                "vulnerable_path": value.path,
                "vulnerable_sink_count": len(vulnerable_sinks),
            }
        ),
        evidence_ids=(f"vulnerable:{value.path}", f"fixed:{fixed_path}"),
    )
