"""Declared text-only adapters for formats without an AST adapter."""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from cv_agent.harness import FULL_SYSTEM_HARNESS
from cv_agent.domain.types import CodeDocument
from cv_agent.code_adapters.models import ParsedSource, SourceDocumentSpan


FALLBACK_SUFFIXES = frozenset(FULL_SYSTEM_HARNESS.fallback_suffixes)


def _fallback_language(suffix: str) -> str:
    return {
        ".yml": "yaml",
        ".yaml": "yaml",
        ".sh": "shell",
    }.get(suffix, suffix.removeprefix(".") or "unknown")


def parse_fallback_source(
    repository_id: str,
    relative_path: str,
    text: str,
) -> ParsedSource:
    suffix = PurePosixPath(relative_path).suffix.casefold()
    language = _fallback_language(suffix)
    lines = text.splitlines()
    end_line = max(1, len(lines))
    definitions = set(
        re.findall(
            r"(?m)^\s*(?:class|def|function|func)\s+([A-Za-z_]\w*)|"
            r"^\s*([A-Za-z_][\w.-]*)\s*:",
            text,
        )
    )
    flattened_definitions = {
        value for pair in definitions for value in pair if value
    }
    calls = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", text))
    document = CodeDocument(
        repository_id=repository_id,
        path=f"{relative_path}::file@1-{end_line}",
        text=text,
        language=language,
        adapter_tier="fallback",
        defines=tuple(sorted(flattened_definitions)),
        calls=tuple(sorted(calls)),
    )
    return ParsedSource(
        spans=(
            SourceDocumentSpan(
                relative_path=relative_path,
                start_line=1,
                end_line=end_line,
                document=document,
                language=language,
                adapter_tier="fallback",
            ),
        ),
        has_error=False,
    )
