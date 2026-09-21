"""Source spans and repository documents shared by language adapters."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from cv_agent.domain.types import CodeDocument


@dataclass(frozen=True)
class SourceDocumentSpan:
    relative_path: str
    start_line: int
    end_line: int
    document: CodeDocument
    language: str
    adapter_tier: Literal["ast", "fallback"]


@dataclass(frozen=True)
class ParsedSource:
    spans: tuple[SourceDocumentSpan, ...]
    has_error: bool


@dataclass(frozen=True)
class CodeRepositoryDocuments:
    documents: tuple[CodeDocument, ...]
    spans: tuple[SourceDocumentSpan, ...]
    parse_error_paths: tuple[str, ...]
    source_file_count: int
    language_file_counts: dict[str, int]
    adapter_tier_file_counts: dict[str, int]

    def locate(self, relative_path: str, line: int) -> SourceDocumentSpan | None:
        normalized = PurePosixPath(relative_path.removeprefix("./")).as_posix()
        matches = [
            span
            for span in self.spans
            if span.relative_path == normalized
            and span.start_line <= line <= span.end_line
        ]
        if not matches:
            return None
        return min(
            matches,
            key=lambda span: (span.end_line - span.start_line, span.start_line),
        )
